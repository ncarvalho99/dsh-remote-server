"""Relay-only DSH Remote protocol server.

The server authenticates devices and forwards opaque encrypted control/relay frames.
It deliberately never accepts, stores, logs, or parses remote business payloads.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from argon2 import PasswordHasher
from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

PROTOCOL_VERSION = 1
MAX_CONTROL_FRAME_BYTES = 64 * 1024
MAX_RELAY_FRAME_BYTES = 1024 * 1024
ACCESS_TTL_SECONDS = 15 * 60
REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60
# A rotated refresh token stays usable for this long after rotation, so a client that
# lost (or failed to persist) the rotation response can retry instead of being orphaned.
REFRESH_GRACE_SECONDS = int(os.environ.get("DSH_REMOTE_REFRESH_GRACE_SECONDS", "600"))
HEARTBEAT_INTERVAL_MS = 25_000
HEARTBEAT_TIMEOUT_SECONDS = 75
SERVER_CAPABILITIES = [
    "transport.lan",
    "transport.p2p",
    "transport.turn",
    "transport.relay",
    "harness.api.v1",
    "harness.api.transfer.v1",
    "harness.remote.v1",
    "harness.remote.transfer.v1",
    "fileviewer.read.v1",
    "codex.appserver.v1",
    "codex.appserver.transfer.v1",
    # Relay data sockets and resume leases (ds-harness-remote 0.6.x).
    "transport.relay.attach",
    "transport.relay.resume.v1",
    # Advertised by ds-harness-remote Hosts; negotiation only gates transports, so these are informational
    # (clients discover Host features end-to-end through harness.transport.describe).
    "harness.remote.v3",
    "harness.terminal.v1",
    "agent.acp.v1",
    "agent.acp.transfer.v1",
    "agent.acp.terminal.v1",
    "agent.acp.antigravity.models.v1",
    "plugin.route.v1",
    "agent.acp.claude.v1",
    "agent.acp.hermes.v1",
    "agent.acp.opencode.archive.v1",
    "harness.remote.stream.transfer.v1",
]
SERVER_VERSION = "0.3.0"
# WebSocket close codes the ds-harness-remote client maps to specific recovery paths.
CLOSE_AUTH_INVALID = 4002  # refresh credentials and retry hello once
CLOSE_CONNECTION_REPLACED = 4003  # another instance took this identity; client stops reconnecting
CLOSE_DEVICE_REVOKED = 4004  # client clears its authorization; next account login rotates the identity
CLOSE_UNSUPPORTED_VERSION = 4011
CLOSE_RECOVERY_REJECTED = 4012  # hello recoveryTickets not live; client drops tunnels and retries without them
RELAY_ATTACH_CAPABILITY = "transport.relay.attach"
RELAY_RESUME_CAPABILITY = "transport.relay.resume.v1"
LEASE_MS = 300_000  # must equal the client's WEBRTC_LEASE_MS literal
DATA_ATTACH_TIMEOUT_SECONDS = 10
PENDING_TUNNEL_SECONDS = 60  # a Host that never answers connect.incoming
TUNNEL_SWEEP_SECONDS = 10
# Public base URL used for relayEndpoint; derived from forwarded headers when unset.
PUBLIC_URL = os.environ.get("DSH_REMOTE_PUBLIC_URL", "").strip().rstrip("/")
DB_PATH = Path(os.environ.get("DSH_REMOTE_DB", "/var/lib/dsh-remote/server.sqlite3"))
PEPPER = os.environ.get("DSH_REMOTE_TOKEN_PEPPER")
if not PEPPER:
    raise RuntimeError("DSH_REMOTE_TOKEN_PEPPER must be set")

log = logging.getLogger("uvicorn.error")
hasher = PasswordHasher()
connections: dict[str, "Session"] = {}
connections_lock = asyncio.Lock()


def now_ms() -> int:
    return int(time.time() * 1000)


def token_hash(token: str) -> str:
    return hmac.new(PEPPER.encode(), token.encode(), hashlib.sha256).hexdigest()


def random_token() -> str:
    return secrets.token_urlsafe(48)


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
              email TEXT PRIMARY KEY,
              password_hash TEXT NOT NULL,
              is_admin INTEGER NOT NULL DEFAULT 0,
              created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS devices (
              device_id TEXT PRIMARY KEY,
              owner_email TEXT NOT NULL REFERENCES users(email),
              name TEXT NOT NULL,
              role TEXT NOT NULL CHECK(role IN ('host','client')),
              platform TEXT NOT NULL,
              identity_key TEXT NOT NULL,
              client_version TEXT NOT NULL,
              harness_version TEXT,
              revoked_at INTEGER,
              created_at INTEGER NOT NULL,
              last_seen_at INTEGER NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS devices_identity_guard
              ON devices(device_id, identity_key, role, owner_email);
            CREATE TABLE IF NOT EXISTS refresh_tokens (
              token_hash TEXT PRIMARY KEY,
              device_id TEXT NOT NULL REFERENCES devices(device_id),
              expires_at INTEGER NOT NULL,
              revoked_at INTEGER,
              created_at INTEGER NOT NULL
            );
            """
        )


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=1024)


class DeviceDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid")
    deviceId: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=128)
    role: str
    platform: str = Field(min_length=1, max_length=64)
    identityKey: str = Field(min_length=1, max_length=256)
    clientVersion: str = Field(min_length=1, max_length=64)
    harnessVersion: str | None = Field(default=None, max_length=64)


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    v: int
    device: DeviceDescriptor


class RefreshRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    deviceId: str = Field(min_length=1, max_length=128)
    refreshToken: str = Field(min_length=16, max_length=8192)


def issue_tokens(conn: sqlite3.Connection, device_id: str) -> dict[str, Any]:
    now = now_ms()
    access = random_token()
    refresh = random_token()
    conn.execute(
        "INSERT INTO refresh_tokens(token_hash,device_id,expires_at,created_at) VALUES(?,?,?,?)",
        (token_hash(refresh), device_id, now + REFRESH_TTL_SECONDS * 1000, now),
    )
    return {
        "accessToken": access,
        "accessTokenExpiresAt": now + ACCESS_TTL_SECONDS * 1000,
        "refreshToken": refresh,
        "refreshTokenExpiresAt": now + REFRESH_TTL_SECONDS * 1000,
    }


def access_token(device_id: str, owner: str, role: str) -> str:
    expiry = now_ms() + ACCESS_TTL_SECONDS * 1000
    nonce = random_token()
    payload_obj = {"d": device_id, "o": owner, "r": role, "e": expiry, "n": nonce}
    body = base64.urlsafe_b64encode(json.dumps(payload_obj).encode()).decode().rstrip("=")
    sig = token_hash(body)
    return f"{body}.{sig}"


def parse_access_token(value: str) -> tuple[str, str, str]:
    try:
        body, sig = value.rsplit(".", 1)
        if not hmac.compare_digest(token_hash(body), sig):
            raise ValueError("Signature mismatch")
        raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)).decode()
        data = json.loads(raw)
        if int(data["e"]) < now_ms():
            raise ValueError("Token expired")
        return str(data["d"]), str(data["o"]), str(data["r"])
    except Exception as exc:
        raise HTTPException(401, detail=error("INVALID_TOKEN", "Invalid or expired token.")) from exc


def error(code: str, message: str, retryable: bool = False, connection_id: str | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {"code": code, "message": message, "retryable": retryable}
    if connection_id:
        payload["connectionId"] = connection_id
    return {"error": payload}


def auth_from_request(request: Request) -> tuple[str, str, str]:
    header = request.headers.get("authorization", "")
    if not header.startswith("Bearer "):
        raise HTTPException(401, detail=error("INVALID_TOKEN", "Bearer token required."))
    return parse_access_token(header[7:])


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    sweeper = asyncio.create_task(sweep_tunnels())
    try:
        yield
    finally:
        sweeper.cancel()


app = FastAPI(title="DSH Remote Relay", version=SERVER_VERSION, lifespan=lifespan)


def device_revoked() -> HTTPException:
    return HTTPException(403, detail=error("DEVICE_REVOKED", "This device was revoked; authorize again with a new identity."))


@app.exception_handler(HTTPException)
async def http_error(_: Request, exc: HTTPException):
    detail = exc.detail if isinstance(exc.detail, dict) else error("INVALID_MESSAGE", str(exc.detail))
    return JSONResponse(status_code=exc.status_code, content=detail)


@app.get("/")
def root() -> dict[str, Any]:
    return {
        "service": "dsh-remote-server",
        "status": "online",
        "protocol": PROTOCOL_VERSION,
        "transport": "relay",
        "health": "/health",
        "ready": "/ready",
        "ws": "/ws/v1/connect",
        "relay": "/ws/v1/relay",
    }


@app.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "protocol": PROTOCOL_VERSION, "transport": "relay"}


@app.get("/ready")
def ready() -> dict[str, Any]:
    with db() as conn:
        conn.execute("SELECT 1").fetchone()
    return {"status": "ready"}


@app.post("/api/v1/auth/login")
def login(body: LoginRequest) -> dict[str, Any]:
    with db() as conn:
        row = conn.execute("SELECT * FROM users WHERE email=?", (body.email.strip().lower(),)).fetchone()
    if not row:
        raise HTTPException(401, detail=error("INVALID_TOKEN", "Invalid credentials."))
    try:
        hasher.verify(row["password_hash"], body.password)
    except Exception as exc:
        raise HTTPException(401, detail=error("INVALID_TOKEN", "Invalid credentials.")) from exc
    return {"token": access_token("account", row["email"], "account"), "expiresAt": now_ms() + ACCESS_TTL_SECONDS * 1000,
            "account": row["email"], "profile": {}, "isAdmin": bool(row["is_admin"])}


@app.get("/api/v1/auth/oauth/providers")
def oauth_providers() -> dict[str, Any]:
    # Account (email/password) login only; an empty list stops 0.5.x clients probing legacy OAuth routes.
    return {"items": []}


@app.post("/api/v1/devices/register")
def register(body: RegisterRequest, request: Request) -> dict[str, Any]:
    _, owner, role = auth_from_request(request)
    if body.v != PROTOCOL_VERSION or role != "account":
        raise HTTPException(400, detail=error("UNSUPPORTED_VERSION", "Account authorization and protocol version 1 required."))
    if body.device.role not in ("host", "client"):
        raise HTTPException(400, detail=error("INVALID_MESSAGE", "Invalid device role."))
    return upsert_device(body, owner)


def upsert_device(body: RegisterRequest, owner: str) -> dict[str, Any]:
    now = now_ms()
    with db() as conn:
        existing = conn.execute("SELECT * FROM devices WHERE device_id=?", (body.device.deviceId,)).fetchone()
        if existing and (existing["owner_email"] != owner or existing["role"] != body.device.role or existing["identity_key"] != body.device.identityKey):
            raise HTTPException(409, detail=error("INVALID_MESSAGE", "Device identity cannot be reassigned."))
        if existing and existing["revoked_at"]:
            # Revocation is permanent; ds-harness-remote 0.5.x rotates its identity on this code.
            raise device_revoked()
        conn.execute(
            """INSERT INTO devices(device_id,owner_email,name,role,platform,identity_key,client_version,harness_version,created_at,last_seen_at)
               VALUES(?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(device_id) DO UPDATE SET name=excluded.name, platform=excluded.platform, client_version=excluded.client_version,
                 harness_version=excluded.harness_version, last_seen_at=excluded.last_seen_at""",
            (body.device.deviceId, owner, body.device.name, body.device.role, body.device.platform, body.device.identityKey,
             body.device.clientVersion, body.device.harnessVersion, now, now),
        )
        tokens = issue_tokens(conn, body.device.deviceId)
        conn.commit()
    # Access tokens are signed and stateless; refresh remains hashed in SQLite.
    tokens["accessToken"] = access_token(body.device.deviceId, owner, body.device.role)
    return tokens


@app.post("/api/v1/devices/register-owned-role")
def register_owned_role(body: RegisterRequest, request: Request) -> dict[str, Any]:
    """Register opposite-role device under same account owner (client registers host or vice versa)."""
    caller_device_id, owner, caller_role = auth_from_request(request)
    if body.v != PROTOCOL_VERSION or caller_role not in ("host", "client"):
        raise HTTPException(400, detail=error("UNSUPPORTED_VERSION", "Device authorization and protocol version 1 required."))
    if body.device.role not in ("host", "client") or body.device.role == caller_role:
        raise HTTPException(400, detail=error("INVALID_MESSAGE", "Must register opposite device role."))
    with db() as conn:
        caller = conn.execute("SELECT revoked_at FROM devices WHERE device_id=?", (caller_device_id,)).fetchone()
    if not caller or caller["revoked_at"]:
        raise device_revoked()
    return upsert_device(body, owner)


@app.delete("/api/v1/devices/self")
def revoke_self(request: Request) -> dict[str, Any]:
    """Revoke the calling device."""
    device_id, owner, role = auth_from_request(request)
    now = now_ms()
    with db() as conn:
        conn.execute("UPDATE devices SET revoked_at=? WHERE device_id=?", (now, device_id))
        conn.execute("UPDATE refresh_tokens SET revoked_at=? WHERE device_id=?", (now, device_id))
        conn.commit()
    return {"revoked": True}


@app.post("/api/v1/auth/refresh")
def refresh(body: RefreshRequest) -> dict[str, Any]:
    with db() as conn:
        row = conn.execute("SELECT * FROM refresh_tokens WHERE token_hash=?", (token_hash(body.refreshToken),)).fetchone()
        now = now_ms()
        if not row or row["device_id"] != body.deviceId or row["expires_at"] < now:
            raise HTTPException(401, detail=error("INVALID_TOKEN", "Invalid refresh token."))
        # A genuine (hash-matched) refresh token of a revoked device reports the revocation itself,
        # so the client clears its authorization instead of retrying forever.
        device = conn.execute("SELECT * FROM devices WHERE device_id=?", (body.deviceId,)).fetchone()
        if not device or device["revoked_at"]:
            raise device_revoked()
        # Rotated tokens are accepted within the grace window.
        if row["revoked_at"] and now - row["revoked_at"] > REFRESH_GRACE_SECONDS * 1000:
            raise HTTPException(401, detail=error("INVALID_TOKEN", "Invalid refresh token."))
        if not row["revoked_at"]:
            # Keep the original rotation time on replays so the grace window never slides.
            conn.execute("UPDATE refresh_tokens SET revoked_at=? WHERE token_hash=?", (now, row["token_hash"]))
        tokens = issue_tokens(conn, body.deviceId)
        conn.commit()
    tokens["accessToken"] = access_token(body.deviceId, device["owner_email"], device["role"])
    return tokens


@app.get("/api/v1/turn/credentials")
def turn_credentials(connection_id: str | None = None, request: Request = None) -> dict[str, Any]:
    auth_from_request(request)
    return {"iceServers": []}


@app.get("/api/v1/devices")
def list_hosts(request: Request) -> dict[str, Any]:
    device_id, owner, role = auth_from_request(request)
    if role not in ("host", "client"):
        raise HTTPException(403, detail=error("INVALID_TOKEN", "Device authorization required."))
    with db() as conn:
        rows = conn.execute("SELECT * FROM devices WHERE owner_email=? AND role='host' AND revoked_at IS NULL", (owner,)).fetchall()
    return {"items": [device_public(row) for row in rows if row["device_id"] != device_id]}


@app.get("/api/v1/devices/{peer_device_id}")
def get_device(peer_device_id: str, request: Request) -> dict[str, Any]:
    _, owner, role = auth_from_request(request)
    with db() as conn:
        row = conn.execute("SELECT * FROM devices WHERE device_id=? AND owner_email=? AND revoked_at IS NULL", (peer_device_id, owner)).fetchone()
    if not row or row["role"] == role:
        raise HTTPException(404, detail=error("CONNECTION_NOT_FOUND", "Authorized peer not found."))
    value = device_public(row)
    value["identityKey"] = row["identity_key"]
    return value


@app.get("/api/v1/devices/{peer_device_id}/presence")
def get_device_presence(peer_device_id: str, request: Request) -> dict[str, Any]:
    _, owner, _ = auth_from_request(request)
    with db() as conn:
        row = conn.execute("SELECT * FROM devices WHERE device_id=? AND owner_email=? AND revoked_at IS NULL", (peer_device_id, owner)).fetchone()
    if not row:
        raise HTTPException(404, detail=error("CONNECTION_NOT_FOUND", "Device not found."))
    session = connections.get(peer_device_id)
    return {"online": bool(session), "lastSeenAt": row["last_seen_at"]}


def device_public(row: sqlite3.Row) -> dict[str, Any]:
    session = connections.get(row["device_id"])
    return {"deviceId": row["device_id"], "name": row["name"], "platform": row["platform"],
            "membershipId": f"account:{row['owner_email']}", "online": bool(session), "lastSeenAt": row["last_seen_at"],
            "clientVersion": row["client_version"], "harnessVersion": row["harness_version"], "role": row["role"]}


class Session:
    def __init__(self, websocket: WebSocket, device_id: str, owner: str, role: str, negotiated: set[str]):
        self.websocket, self.device_id, self.owner, self.role = websocket, device_id, owner, role
        self.negotiated = negotiated
        self.last_pong = time.monotonic()

    async def send(self, type_: str, payload: dict[str, Any]) -> None:
        await self.websocket.send_json(envelope(type_, payload))


class Lease:
    """Relay resume lease for one tunnel member (transport.relay.resume.v1).

    The member renews it with connection.lease.request every ~25 s; each ack rotates the ticket.
    The previous ticket stays acceptable once, so a lost ack does not orphan the tunnel.
    """

    def __init__(self) -> None:
        self.ticket = random_token()
        self.previous: str | None = None
        self.expires = time.monotonic() + LEASE_MS / 1000

    def valid(self) -> bool:
        return time.monotonic() < self.expires

    def matches(self, ticket: str) -> bool:
        return self.valid() and any(t is not None and hmac.compare_digest(t, ticket) for t in (self.ticket, self.previous))

    def rotate(self) -> str:
        self.previous, self.ticket = self.ticket, random_token()
        self.expires = time.monotonic() + LEASE_MS / 1000
        return self.ticket


class Tunnel:
    """One client<->host connection. Lives outside control sockets so it can survive a control reconnect."""

    def __init__(self, cid: str, owner: str, host_id: str, client_id: str):
        self.cid, self.owner, self.host_id, self.client_id = cid, owner, host_id, client_id
        self.accepted = False
        self.created = time.monotonic()
        self.epoch = 0
        self.attach_tickets: dict[str, str] = {}  # device_id -> single-use relay.attach ticket
        self.data: dict[str, WebSocket] = {}  # device_id -> attached relay data socket
        self.leases: dict[str, Lease] = {}

    @property
    def members(self) -> tuple[str, str]:
        return self.host_id, self.client_id

    def peer_of(self, device_id: str) -> str | None:
        if device_id == self.host_id:
            return self.client_id
        if device_id == self.client_id:
            return self.host_id
        return None

    def detachable(self, device_id: str) -> bool:
        lease = self.leases.get(device_id)
        return lease is not None and lease.valid() and device_id in self.data


tunnels: dict[str, Tunnel] = {}


def envelope(type_: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {"v": 1, "id": str(uuid.uuid4()), "type": type_, "timestamp": now_ms(), "payload": payload}


def short(value: str | None) -> str:
    return (value or "-")[:8]


def control_session(device_id: str, owner: str) -> Session | None:
    session = connections.get(device_id)
    return session if session and session.owner == owner else None


def relay_endpoint(websocket: WebSocket) -> str | None:
    if PUBLIC_URL:
        base = PUBLIC_URL
    else:
        host = websocket.headers.get("x-forwarded-host") or websocket.headers.get("host")
        if not host:
            return None
        proto = websocket.headers.get("x-forwarded-proto", websocket.url.scheme)
        base = f"{'https' if proto in ('https', 'wss') else 'http'}://{host}"
    return base.replace("https://", "wss://", 1).replace("http://", "ws://", 1) + "/ws/v1/relay"


async def heartbeat(session: Session) -> None:
    while True:
        await asyncio.sleep(HEARTBEAT_INTERVAL_MS / 1000)
        if time.monotonic() - session.last_pong > HEARTBEAT_TIMEOUT_SECONDS:
            await session.websocket.close(code=1011, reason="heartbeat timeout")
            return
        nonce = secrets.token_urlsafe(12)
        await session.send("ping", {"nonce": nonce})


def valid_frame(frame: Any) -> tuple[str, dict[str, Any]]:
    if not isinstance(frame, dict) or set(frame) != {"v", "id", "type", "timestamp", "payload"}:
        raise ValueError("Malformed control frame")
    if frame["v"] != 1 or not isinstance(frame["id"], str) or not isinstance(frame["type"], str) or not isinstance(frame["payload"], dict):
        raise ValueError("Malformed control frame")
    return frame["type"], frame["payload"]


def tunnel_for(session: Session, cid: Any, target: Any = None) -> tuple[Tunnel, str] | None:
    """Resolve the tunnel and peer id for a frame sent by session; None when the sender is not a member."""
    tunnel = tunnels.get(cid) if isinstance(cid, str) else None
    if not tunnel or tunnel.owner != session.owner:
        return None
    peer_id = tunnel.peer_of(session.device_id)
    if not peer_id or (target is not None and target != peer_id):
        return None
    return tunnel, peer_id


async def forward_relay(tunnel: Tunnel, peer_id: str, payload: dict[str, Any]) -> bool:
    """Deliver a relay frame on the peer's data socket when attached (it then ignores control relay)."""
    data_ws = tunnel.data.get(peer_id)
    try:
        if data_ws is not None:
            await data_ws.send_json(envelope("relay", payload))
            return True
        peer = control_session(peer_id, tunnel.owner)
        if peer:
            await peer.send("relay", payload)
            return True
    except Exception:
        pass
    return False


async def teardown(tunnel: Tunnel, reason: str, cause: str | None = None, notify: bool = True) -> None:
    """Drop a tunnel; peers learn through relay.detach on a data socket or a retryable control error."""
    if tunnels.get(tunnel.cid) is not tunnel:
        return
    del tunnels[tunnel.cid]
    log.info("tunnel %s closed: %s", short(tunnel.cid), reason)
    attached = dict(tunnel.data)
    tunnel.data.clear()
    for device_id, data_ws in attached.items():
        try:
            if device_id != cause:
                await data_ws.send_json(envelope("relay.detach", {"connectionId": tunnel.cid}))
            await data_ws.close(code=1000, reason="relay detached")
        except Exception:
            pass
    if not notify:
        return
    for device_id in tunnel.members:
        if device_id == cause or device_id in attached:
            continue
        session = control_session(device_id, tunnel.owner)
        if session:
            try:
                await session.send("error", {"code": "CONNECTION_FAILED", "message": "Remote connection closed.",
                                             "retryable": True, "connectionId": tunnel.cid})
            except Exception:
                pass


async def sweep_tunnels() -> None:
    """Expire unanswered connection requests and tunnels whose detached member lost its lease."""
    while True:
        await asyncio.sleep(TUNNEL_SWEEP_SECONDS)
        for tunnel in list(tunnels.values()):
            if not tunnel.accepted and time.monotonic() - tunnel.created > PENDING_TUNNEL_SECONDS:
                await teardown(tunnel, "host did not answer")
                continue
            for device_id in tunnel.members:
                if control_session(device_id, tunnel.owner) is None and not tunnel.detachable(device_id):
                    await teardown(tunnel, f"{short(device_id)} control lost", cause=device_id)
                    break


def recovered_tunnels(device_id: str, tickets: Any) -> set[str] | None:
    """Map hello recoveryTickets to tunnel ids; None when any ticket is not a live lease of this device."""
    if not isinstance(tickets, list):
        return set()
    recovered: set[str] = set()
    for ticket in tickets[:64]:
        match = next((t for t in tunnels.values() if isinstance(ticket, str) and device_id in t.leases
                      and t.leases[device_id].matches(ticket)), None)
        if match is None:
            return None
        recovered.add(match.cid)
    return recovered


async def handle_control(session: Session, type_: str, payload: dict[str, Any], size: int, websocket: WebSocket) -> None:
    device_id, owner, role = session.device_id, session.owner, session.role
    if type_ == "connect.request" and role == "client":
        host_id = payload.get("hostDeviceId")
        preferred = payload.get("preferredTransports", [])
        host = connections.get(host_id) if isinstance(host_id, str) else None
        if not host or host.owner != owner or host.role != "host":
            await session.send("error", {"code": "HOST_OFFLINE", "message": "Host is offline."})
            return
        if "relay" not in preferred:
            await session.send("error", {"code": "RELAY_UNAVAILABLE", "message": "Relay transport required."})
            return
        tunnel = Tunnel(str(uuid.uuid4()), owner, host_id, device_id)
        tunnels[tunnel.cid] = tunnel
        endpoint = relay_endpoint(websocket)
        incoming: dict[str, Any] = {"connectionId": tunnel.cid, "clientDeviceId": device_id, "authorization": "account",
                                    "preferredTransports": ["relay"]}
        with db() as conn:
            client = conn.execute("SELECT identity_key FROM devices WHERE device_id=?", (device_id,)).fetchone()
        incoming["clientIdentityKey"] = client["identity_key"]
        incoming.update(member_assignment(tunnel, host, endpoint))
        log.info("tunnel %s requested: client %s -> host %s (attach host=%s client=%s)", short(tunnel.cid), short(device_id),
                 short(host_id), RELAY_ATTACH_CAPABILITY in host.negotiated, RELAY_ATTACH_CAPABILITY in session.negotiated)
        await host.send("connect.incoming", incoming)
        return
    cid = payload.get("connectionId")
    if type_ == "connection.lease.request":
        resolved = tunnel_for(session, cid)
        lease = resolved[0].leases.get(device_id) if resolved else None
        ticket, request_id = payload.get("ticket"), payload.get("requestId")
        if not lease or not isinstance(ticket, str) or not isinstance(request_id, str) or not lease.matches(ticket):
            await session.send("error", {"code": "CONNECTION_NOT_FOUND", "message": "Connection lease unavailable.",
                                         "retryable": False, "connectionId": cid if isinstance(cid, str) else "unknown"})
            return
        await session.send("connection.lease.ack", {"connectionId": cid, "requestId": request_id, "ticket": lease.rotate(),
                                                    "leaseMs": LEASE_MS})
        return
    if type_ == "connection.lease.close":
        resolved = tunnel_for(session, cid)
        if resolved:
            resolved[0].leases.pop(device_id, None)
        return
    if type_ in {"connect.accepted", "connect.rejected"} and role == "host":
        resolved = tunnel_for(session, cid)
        if not resolved:
            log.info("%s for unknown tunnel %s ignored", type_, short(cid))
            return
        tunnel, client_id = resolved
        client = control_session(client_id, owner)
        if type_ == "connect.rejected":
            rejected = {"connectionId": tunnel.cid, "code": "CONNECTION_REJECTED", "message": "Host rejected the connection."}
            rejected.update({k: payload[k] for k in ("code", "message") if isinstance(payload.get(k), str) and payload[k]})
            log.info("tunnel %s rejected by host (%s)", short(tunnel.cid), rejected["code"])
            if client:
                await client.send("connect.rejected", rejected)
            await teardown(tunnel, "rejected by host", notify=False)
            return
        tunnel.accepted = True
        log.info("tunnel %s accepted", short(tunnel.cid))
        if client:
            accepted = {"connectionId": tunnel.cid}
            accepted.update(member_assignment(tunnel, client, relay_endpoint(websocket)))
            await client.send("connect.accepted", accepted)
        return
    if type_ == "error":
        resolved = tunnel_for(session, cid)
        if not resolved:
            log.info("control error from %s %s ignored (code=%s)", role, short(device_id), payload.get("code"))
            return
        tunnel, peer_id = resolved
        log.info("tunnel %s error from %s: %s", short(tunnel.cid), role, payload.get("code"))
        peer = control_session(peer_id, owner)
        if peer and isinstance(payload.get("code"), str) and isinstance(payload.get("message"), str):
            await peer.send("error", {"code": payload["code"], "message": payload["message"],
                                      "retryable": bool(payload.get("retryable", False)), "connectionId": tunnel.cid})
        await teardown(tunnel, f"error from {role}", cause=device_id, notify=False)
        return
    if type_ in {"transport.selected", "secure.handshake", "relay", "signal.offer", "signal.answer", "signal.ice"} and isinstance(cid, str):
        if type_ == "relay" and size > MAX_RELAY_FRAME_BYTES:
            await session.send("error", {"code": "FRAME_TOO_LARGE", "message": "Relay frame is too large.", "connectionId": cid})
            return
        resolved = tunnel_for(session, cid, payload.get("targetDeviceId"))
        if resolved:
            tunnel, peer_id = resolved
            if type_ == "transport.selected":
                log.info("tunnel %s transport %s selected by %s", short(cid), payload.get("transport"), role)
            if type_ == "relay":
                delivered = await forward_relay(tunnel, peer_id, payload)
            else:
                peer = control_session(peer_id, owner)
                delivered = peer is not None
                if peer:
                    await peer.send(type_, payload)
            if delivered:
                return
        await session.send("error", {"code": "CONNECTION_NOT_FOUND", "message": "Connection unavailable.", "connectionId": cid})
        return
    log.warning("unsupported control frame %r from %s %s", type_[:64], role, short(device_id))
    await session.send("error", {"code": "CAPABILITY_NOT_SUPPORTED", "message": "Unsupported control frame."})


def member_assignment(tunnel: Tunnel, member: Session, endpoint: str | None) -> dict[str, Any]:
    """Data-socket assignment and resume ticket for one tunnel member, per its negotiated capabilities."""
    assignment: dict[str, Any] = {}
    if RELAY_ATTACH_CAPABILITY in member.negotiated and endpoint:
        ticket = random_token()
        tunnel.attach_tickets[member.device_id] = ticket
        assignment.update({"relayEndpoint": endpoint, "relayTicket": ticket, "relayEpoch": tunnel.epoch})
    if RELAY_RESUME_CAPABILITY in member.negotiated:
        lease = tunnel.leases.setdefault(member.device_id, Lease())
        assignment["relayRecoveryTicket"] = lease.ticket
    return assignment


@app.websocket("/ws/v1/connect")
async def ws_connect(websocket: WebSocket):
    await websocket.accept()
    try:
        raw = await asyncio.wait_for(websocket.receive_text(), timeout=5)
        if len(raw.encode()) > MAX_CONTROL_FRAME_BYTES:
            await websocket.close(code=1009)
            return
        type_, payload = valid_frame(json.loads(raw))
        if type_ != "hello":
            raise ValueError("hello required")
        try:
            device_id, owner, role = parse_access_token(str(payload.get("accessToken", "")))
        except HTTPException:
            await websocket.close(code=CLOSE_AUTH_INVALID, reason="access token invalid or expired")
            return
        if payload.get("deviceId") != device_id or payload.get("role", role) != role:
            raise ValueError("Invalid hello authorization")
        if 1 not in payload.get("protocols", []):
            await websocket.close(code=CLOSE_UNSUPPORTED_VERSION, reason="protocol 1 required")
            return
        capabilities = set(payload.get("capabilities", []))
        with db() as conn:
            device = conn.execute("SELECT * FROM devices WHERE device_id=?", (device_id,)).fetchone()
            if not device or device["revoked_at"]:
                await websocket.close(code=CLOSE_DEVICE_REVOKED, reason="device revoked")
                return
            if device["owner_email"] != owner or device["role"] != role:
                raise ValueError("Device does not match its access token")
            # Hosts report their current versions on every hello; keep the device list truthful
            # (clients fall back to clientVersion when a Host cannot describe its features).
            versions = {key: payload.get(key) for key in ("clientVersion", "harnessVersion")}
            client_version = versions["clientVersion"] if isinstance(versions["clientVersion"], str) and 0 < len(versions["clientVersion"]) <= 64 else device["client_version"]
            harness_version = versions["harnessVersion"] if isinstance(versions["harnessVersion"], str) and 0 < len(versions["harnessVersion"]) <= 64 else device["harness_version"]
            conn.execute("UPDATE devices SET last_seen_at=?, client_version=?, harness_version=? WHERE device_id=?",
                         (now_ms(), client_version, harness_version, device_id))
            conn.commit()
        recovered = recovered_tunnels(device_id, payload.get("recoveryTickets"))
        if recovered is None:
            log.info("%s %s presented stale recovery tickets", role, short(device_id))
            await websocket.close(code=CLOSE_RECOVERY_REJECTED, reason="recovery authorization rejected")
            return
        negotiated = capabilities.intersection(SERVER_CAPABILITIES)
        session = Session(websocket, device_id, owner, role, negotiated)
        async with connections_lock:
            old = connections.get(device_id)
            connections[device_id] = session
        if old:
            try:
                await old.send("error", {"code": "CONNECTION_REPLACED", "message": "New device session connected."})
            except Exception:
                pass
            try:
                await old.websocket.close(code=CLOSE_CONNECTION_REPLACED, reason="connection replaced")
            except Exception:
                pass
        await session.send("hello.ack", {"protocol": 1, "serverVersion": SERVER_VERSION, "connectionSessionId": str(uuid.uuid4()),
                                          "heartbeatIntervalMs": HEARTBEAT_INTERVAL_MS, "maxControlFrameBytes": MAX_CONTROL_FRAME_BYTES,
                                          "maxRelayFrameBytes": MAX_RELAY_FRAME_BYTES, "capabilities": sorted(negotiated), "webrtcEnabled": False})
        log.info("%s %s online (v%s, attach=%s, resume=%s, recovered=%d)", role, short(device_id), client_version,
                 RELAY_ATTACH_CAPABILITY in negotiated, RELAY_RESUME_CAPABILITY in negotiated, len(recovered))
        # A fresh control session without a ticket for a tunnel means this instance no longer holds it.
        for tunnel in [t for t in tunnels.values() if device_id in t.members and t.cid not in recovered]:
            await teardown(tunnel, f"{short(device_id)} reconnected without it", cause=device_id)
        task = asyncio.create_task(heartbeat(session))
        try:
            while True:
                raw = await websocket.receive_text()
                size = len(raw.encode())
                if size > MAX_RELAY_FRAME_BYTES:
                    await session.send("error", {"code": "FRAME_TOO_LARGE", "message": "Frame is too large."})
                    continue
                type_, payload = valid_frame(json.loads(raw))
                if type_ == "pong":
                    session.last_pong = time.monotonic()
                    continue
                if type_ == "ping":
                    await session.send("pong", {"nonce": payload.get("nonce", "")})
                    continue
                await handle_control(session, type_, payload, size, websocket)
        finally:
            task.cancel()
            current = False
            async with connections_lock:
                if connections.get(device_id) is session:
                    connections.pop(device_id, None)
                    current = True
            if current:
                # Tunnels with a live lease and an attached data socket stay up until the lease runs out.
                for tunnel in [t for t in tunnels.values() if device_id in t.members]:
                    if not tunnel.detachable(device_id):
                        await teardown(tunnel, f"{short(device_id)} control closed", cause=device_id)
    except (ValueError, json.JSONDecodeError):
        await websocket.close(code=1008, reason="invalid control frame")
    except WebSocketDisconnect:
        pass


@app.websocket("/ws/v1/relay")
async def ws_relay(websocket: WebSocket):
    """Per-connection relay data socket (transport.relay.attach): relay.attach -> relay.ready, then relay frames."""
    await websocket.accept()
    tunnel: Tunnel | None = None
    device_id: str | None = None
    try:
        raw = await asyncio.wait_for(websocket.receive_text(), timeout=DATA_ATTACH_TIMEOUT_SECONDS)
        if len(raw.encode()) > MAX_CONTROL_FRAME_BYTES:
            await websocket.close(code=1009)
            return
        type_, payload = valid_frame(json.loads(raw))
        cid, claimed, peer_claim, ticket = (payload.get(k) for k in ("connectionId", "deviceId", "peerDeviceId", "ticket"))
        candidate = tunnels.get(cid) if isinstance(cid, str) else None
        expected = candidate.attach_tickets.get(claimed) if candidate and isinstance(claimed, str) else None
        if (type_ != "relay.attach" or not expected or not isinstance(ticket, str) or not hmac.compare_digest(expected, ticket)
                or candidate.peer_of(claimed) != peer_claim or claimed in candidate.data):
            log.info("relay attach rejected for tunnel %s", short(cid if isinstance(cid, str) else None))
            await websocket.close(code=1008, reason="relay attach rejected")
            return
        tunnel, device_id = candidate, claimed
        del tunnel.attach_tickets[device_id]
        tunnel.data[device_id] = websocket
        await websocket.send_json(envelope("relay.ready", {"connectionId": tunnel.cid, "epoch": tunnel.epoch}))
        log.info("tunnel %s data socket attached by %s", short(tunnel.cid), short(device_id))
        peer_id = tunnel.peer_of(device_id)
        last_seen = time.monotonic()
        while True:
            try:
                raw = await asyncio.wait_for(websocket.receive_text(), timeout=HEARTBEAT_INTERVAL_MS / 1000)
            except asyncio.TimeoutError:
                if time.monotonic() - last_seen > HEARTBEAT_TIMEOUT_SECONDS:
                    await websocket.close(code=1011, reason="heartbeat timeout")
                    return
                await websocket.send_json(envelope("ping", {"nonce": secrets.token_urlsafe(12)}))
                continue
            last_seen = time.monotonic()
            if len(raw.encode()) > MAX_RELAY_FRAME_BYTES:
                await websocket.close(code=1009, reason="relay frame too large")
                return
            type_, payload = valid_frame(json.loads(raw))
            if type_ == "pong":
                continue
            if type_ == "ping":
                await websocket.send_json(envelope("pong", {"nonce": str(payload.get("nonce", ""))}))
                continue
            if type_ != "relay" or payload.get("connectionId") != tunnel.cid or payload.get("targetDeviceId") != peer_id:
                raise ValueError("Unexpected relay data frame")
            if not await forward_relay(tunnel, peer_id, payload):
                return
    except (ValueError, json.JSONDecodeError):
        await websocket.close(code=1008, reason="invalid relay data frame")
    except (WebSocketDisconnect, asyncio.TimeoutError):
        pass
    finally:
        if tunnel is not None and device_id is not None and tunnel.data.get(device_id) is websocket:
            del tunnel.data[device_id]
            await teardown(tunnel, f"{short(device_id)} data socket closed", cause=device_id)
