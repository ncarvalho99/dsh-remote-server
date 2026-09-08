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
]
DB_PATH = Path(os.environ.get("DSH_REMOTE_DB", "/var/lib/dsh-remote/server.sqlite3"))
PEPPER = os.environ.get("DSH_REMOTE_TOKEN_PEPPER")
if not PEPPER:
    raise RuntimeError("DSH_REMOTE_TOKEN_PEPPER must be set")

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
    yield


app = FastAPI(title="DSH Remote Relay", version="0.1.0", lifespan=lifespan)


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


@app.post("/api/v1/devices/register")
def register(body: RegisterRequest, request: Request) -> dict[str, Any]:
    _, owner, role = auth_from_request(request)
    if body.v != PROTOCOL_VERSION or role != "account":
        raise HTTPException(400, detail=error("UNSUPPORTED_VERSION", "Account authorization and protocol version 1 required."))
    if body.device.role not in ("host", "client"):
        raise HTTPException(400, detail=error("INVALID_MESSAGE", "Invalid device role."))
    now = now_ms()
    with db() as conn:
        existing = conn.execute("SELECT * FROM devices WHERE device_id=?", (body.device.deviceId,)).fetchone()
        if existing and (existing["owner_email"] != owner or existing["role"] != body.device.role or existing["identity_key"] != body.device.identityKey):
            raise HTTPException(409, detail=error("INVALID_MESSAGE", "Device identity cannot be reassigned."))
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
    
    now = now_ms()
    with db() as conn:
        existing = conn.execute("SELECT * FROM devices WHERE device_id=?", (body.device.deviceId,)).fetchone()
        if existing and (existing["owner_email"] != owner or existing["role"] != body.device.role or existing["identity_key"] != body.device.identityKey):
            raise HTTPException(409, detail=error("INVALID_MESSAGE", "Device identity cannot be reassigned."))
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
    tokens["accessToken"] = access_token(body.device.deviceId, owner, body.device.role)
    return tokens


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
        if not row or row["device_id"] != body.deviceId or row["revoked_at"] or row["expires_at"] < now_ms():
            raise HTTPException(401, detail=error("INVALID_TOKEN", "Invalid refresh token."))
        device = conn.execute("SELECT * FROM devices WHERE device_id=? AND revoked_at IS NULL", (body.deviceId,)).fetchone()
        if not device:
            raise HTTPException(401, detail=error("INVALID_TOKEN", "Device is unavailable."))
        conn.execute("UPDATE refresh_tokens SET revoked_at=? WHERE token_hash=?", (now_ms(), row["token_hash"]))
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
    def __init__(self, websocket: WebSocket, device_id: str, owner: str, role: str, capabilities: set[str]):
        self.websocket, self.device_id, self.owner, self.role = websocket, device_id, owner, role
        self.capabilities = capabilities
        self.last_pong = time.monotonic()
        self.pending_connections: dict[str, str] = {}  # connection_id -> peer device_id

    async def send(self, type_: str, payload: dict[str, Any]) -> None:
        await self.websocket.send_json({"v": 1, "id": str(uuid.uuid4()), "type": type_, "timestamp": now_ms(), "payload": payload})


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


async def peer_for(session: Session, connection_id: str, target: str | None = None) -> Session | None:
    peer_id = session.pending_connections.get(connection_id)
    if not peer_id or (target and target != peer_id):
        return None
    peer = connections.get(peer_id)
    if not peer or peer.owner != session.owner or peer.role == session.role:
        return None
    return peer


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
        device_id, owner, role = parse_access_token(str(payload.get("accessToken", "")))
        if payload.get("deviceId") != device_id or payload.get("role") != role or 1 not in payload.get("protocols", []):
            raise ValueError("Invalid hello authorization")
        capabilities = set(payload.get("capabilities", []))
        with db() as conn:
            device = conn.execute("SELECT * FROM devices WHERE device_id=? AND owner_email=? AND role=? AND revoked_at IS NULL", (device_id, owner, role)).fetchone()
            if not device:
                raise ValueError("Unknown or revoked device")
            conn.execute("UPDATE devices SET last_seen_at=? WHERE device_id=?", (now_ms(), device_id))
            conn.commit()
        session = Session(websocket, device_id, owner, role, capabilities)
        async with connections_lock:
            old = connections.get(device_id)
            connections[device_id] = session
        if old:
            await old.send("error", {"code": "CONNECTION_REPLACED", "message": "New device session connected."})
            await old.websocket.close(code=1012)
        negotiated = sorted(capabilities.intersection(SERVER_CAPABILITIES))
        await session.send("hello.ack", {"protocol": 1, "serverVersion": "0.1.0", "connectionSessionId": str(uuid.uuid4()),
                                          "heartbeatIntervalMs": HEARTBEAT_INTERVAL_MS, "maxControlFrameBytes": MAX_CONTROL_FRAME_BYTES,
                                          "maxRelayFrameBytes": MAX_RELAY_FRAME_BYTES, "capabilities": negotiated, "webrtcEnabled": False})
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
                if type_ == "connect.request" and role == "client":
                    host_id = payload.get("hostDeviceId")
                    preferred = payload.get("preferredTransports", [])
                    host = connections.get(host_id)
                    if not host or host.owner != owner or host.role != "host":
                        await session.send("error", {"code": "HOST_OFFLINE", "message": "Host is offline."})
                        continue
                    if "relay" not in preferred:
                        await session.send("error", {"code": "RELAY_UNAVAILABLE", "message": "Relay transport required."})
                        continue
                    cid = str(uuid.uuid4())
                    session.pending_connections[cid] = host_id
                    host.pending_connections[cid] = device_id
                    with db() as conn:
                        client = conn.execute("SELECT identity_key FROM devices WHERE device_id=?", (device_id,)).fetchone()
                    await host.send("connect.incoming", {"connectionId": cid, "clientDeviceId": device_id, "clientIdentityKey": client["identity_key"],
                                                           "authorization": "account", "preferredTransports": ["relay"]})
                    continue
                cid = payload.get("connectionId")
                if type_ == "connect.accepted" and role == "host" and isinstance(cid, str):
                    peer = await peer_for(session, cid)
                    if peer:
                        await peer.send("connect.accepted", {"connectionId": cid})
                    continue
                if type_ == "transport.selected" and isinstance(cid, str):
                    peer = await peer_for(session, cid)
                    if peer:
                        await peer.send("transport.selected", payload)
                    continue
                if type_ in {"secure.handshake", "relay", "signal.offer", "signal.answer", "signal.ice"} and isinstance(cid, str):
                    if type_ == "relay" and size > MAX_RELAY_FRAME_BYTES:
                        await session.send("error", {"code": "FRAME_TOO_LARGE", "message": "Relay frame is too large.", "connectionId": cid})
                        continue
                    peer = await peer_for(session, cid, payload.get("targetDeviceId"))
                    if peer:
                        await peer.send(type_, payload)
                    else:
                        await session.send("error", {"code": "CONNECTION_NOT_FOUND", "message": "Connection unavailable.", "connectionId": cid})
                    continue
                await session.send("error", {"code": "CAPABILITY_NOT_SUPPORTED", "message": "Unsupported control frame."})
        finally:
            task.cancel()
            async with connections_lock:
                if connections.get(device_id) is session:
                    connections.pop(device_id, None)
    except (ValueError, json.JSONDecodeError):
        await websocket.close(code=1008, reason="invalid control frame")
    except WebSocketDisconnect:
        pass
