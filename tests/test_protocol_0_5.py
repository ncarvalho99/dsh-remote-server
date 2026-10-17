"""End-to-end protocol checks against a disposable relay (temporary DB, loopback port).

Covers the behaviours ds-harness-remote 0.5.x relies on: hello/hello.ack shape, version refresh on hello,
close codes 4002/4003/4004/4011, DEVICE_REVOKED on refresh/register, connect/relay forwarding, and
OAuth provider discovery. Run from the repository root:

    python tests/test_protocol_0_5.py
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import httpx
import websockets

ROOT = Path(__file__).resolve().parents[1]
EMAIL, PASSWORD = "relay-test@example.invalid", "relay-test-password"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def frame(type_: str, payload: dict) -> str:
    return json.dumps({"v": 1, "id": str(uuid.uuid4()), "type": type_, "timestamp": int(time.time() * 1000), "payload": payload})


def device(role: str, name: str, version: str = "0.4.23") -> dict:
    return {"deviceId": str(uuid.uuid4()), "name": name, "role": role, "platform": "win32",
            "identityKey": uuid.uuid4().hex, "clientVersion": version, "harnessVersion": "0.2.0-rc.2" if role == "host" else None}


async def hello(base_ws: str, dev: dict, token: str, **extra) -> websockets.ClientConnection:
    ws = await websockets.connect(f"{base_ws}/ws/v1/connect")
    payload = {"deviceId": dev["deviceId"], "accessToken": token, "protocols": [1], "capabilities": ["transport.relay", "plugin.route.v1"]}
    payload.update(extra)
    await ws.send(frame("hello", payload))
    return ws


async def recv_type(ws, wanted: str, timeout: float = 5) -> dict:
    deadline = time.monotonic() + timeout
    while True:
        msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=max(0.1, deadline - time.monotonic())))
        if msg["type"] == wanted:
            return msg
        if msg["type"] != "ping":
            raise AssertionError(f"expected {wanted}, got {msg['type']}: {msg['payload']}")


async def close_code(ws, timeout: float = 5) -> int:
    try:
        while True:
            await asyncio.wait_for(ws.recv(), timeout=timeout)
    except websockets.ConnectionClosed as closed:
        return closed.rcvd.code if closed.rcvd else 1006


async def run(base: str) -> None:
    base_ws = base.replace("http", "ws", 1)
    async with httpx.AsyncClient(base_url=base, timeout=10) as http:
        assert (await http.get("/api/v1/auth/oauth/providers")).json() == {"items": []}
        account = (await http.post("/api/v1/auth/login", json={"email": EMAIL, "password": PASSWORD})).json()["token"]
        auth = {"Authorization": f"Bearer {account}"}

        host, client = device("host", "TEST-HOST"), device("client", "TEST-CLIENT")
        host_tokens = (await http.post("/api/v1/devices/register", headers=auth, json={"v": 1, "device": host})).json()
        client_tokens = (await http.post("/api/v1/devices/register", headers=auth, json={"v": 1, "device": client})).json()

        # 0.5.x hello: no role, current versions; ack must satisfy requireHelloAck and refresh stored versions.
        h1 = await hello(base_ws, host, host_tokens["accessToken"], clientVersion="0.5.10", harnessVersion="0.2.1-rc.2")
        ack = (await recv_type(h1, "hello.ack"))["payload"]
        assert ack["protocol"] == 1 and isinstance(ack["serverVersion"], str) and isinstance(ack["connectionSessionId"], str)
        assert all(isinstance(ack[k], int) for k in ("heartbeatIntervalMs", "maxControlFrameBytes", "maxRelayFrameBytes"))
        assert "transport.relay" in ack["capabilities"] and "plugin.route.v1" in ack["capabilities"]
        listed = (await http.get("/api/v1/devices", headers={"Authorization": f"Bearer {client_tokens['accessToken']}"})).json()["items"]
        mine = next(d for d in listed if d["deviceId"] == host["deviceId"])
        assert (mine["clientVersion"], mine["harnessVersion"], mine["online"]) == ("0.5.10", "0.2.1-rc.2", True), mine
        print("PASS hello.ack shape, capability negotiation, version refresh on hello")

        # connect + relay forwarding between client and host.
        c1 = await hello(base_ws, client, client_tokens["accessToken"])
        await recv_type(c1, "hello.ack")
        await c1.send(frame("connect.request", {"hostDeviceId": host["deviceId"], "preferredTransports": ["relay"]}))
        incoming = (await recv_type(h1, "connect.incoming"))["payload"]
        assert incoming["clientDeviceId"] == client["deviceId"] and incoming["authorization"] == "account"
        assert isinstance(incoming["clientIdentityKey"], str) and isinstance(incoming["preferredTransports"], list)
        cid = incoming["connectionId"]
        await h1.send(frame("connect.accepted", {"connectionId": cid}))
        await recv_type(c1, "connect.accepted")
        await c1.send(frame("secure.handshake", {"connectionId": cid, "targetDeviceId": host["deviceId"], "step": 1, "data": "AA"}))
        assert (await recv_type(h1, "secure.handshake"))["payload"]["data"] == "AA"
        await h1.send(frame("relay", {"connectionId": cid, "targetDeviceId": client["deviceId"], "data": "BB"}))
        assert (await recv_type(c1, "relay"))["payload"]["data"] == "BB"
        print("PASS connect.request/incoming/accepted, secure.handshake and relay forwarding")

        # A second session for the same identity replaces the first with 4003.
        h2 = await hello(base_ws, host, host_tokens["accessToken"])
        await recv_type(h2, "hello.ack")
        assert await close_code(h1) == 4003
        print("PASS replaced session closes with 4003")

        bad = await hello(base_ws, host, "not-a-token")
        assert await close_code(bad) == 4002
        old_proto = await websockets.connect(f"{base_ws}/ws/v1/connect")
        await old_proto.send(frame("hello", {"deviceId": host["deviceId"], "accessToken": host_tokens["accessToken"], "protocols": [2]}))
        assert await close_code(old_proto) == 4011
        malformed = await websockets.connect(f"{base_ws}/ws/v1/connect")
        await malformed.send(json.dumps({"v": 1, "type": "hello", "payload": {}}))
        assert await close_code(malformed) == 1008
        print("PASS 4002 invalid token, 4011 unsupported protocol, 1008 malformed envelope")

        # Revocation: hello -> 4004, refresh -> DEVICE_REVOKED, re-register same id -> DEVICE_REVOKED, new id -> ok.
        assert (await http.delete("/api/v1/devices/self", headers={"Authorization": f"Bearer {host_tokens['accessToken']}"})).json() == {"revoked": True}
        revoked = await hello(base_ws, host, host_tokens["accessToken"])
        assert await close_code(revoked) == 4004
        refreshed = await http.post("/api/v1/auth/refresh", json={"deviceId": host["deviceId"], "refreshToken": host_tokens["refreshToken"]})
        assert refreshed.status_code == 403 and refreshed.json()["error"]["code"] == "DEVICE_REVOKED", refreshed.text
        again = await http.post("/api/v1/devices/register", headers=auth, json={"v": 1, "device": host})
        assert again.status_code == 403 and again.json()["error"]["code"] == "DEVICE_REVOKED", again.text
        rotated = dict(host, deviceId=str(uuid.uuid4()), identityKey=uuid.uuid4().hex)
        assert (await http.post("/api/v1/devices/register", headers=auth, json={"v": 1, "device": rotated})).status_code == 200
        print("PASS revoked device: 4004 on hello, DEVICE_REVOKED on refresh and register, rotated identity registers")

        # Ordinary refresh rotation still works for a live device.
        ok = await http.post("/api/v1/auth/refresh", json={"deviceId": client["deviceId"], "refreshToken": client_tokens["refreshToken"]})
        assert ok.status_code == 200 and "accessToken" in ok.json()
        print("PASS live device refresh")
        for ws in (h2, c1):
            await ws.close()


def main() -> int:
    # Windows can hold the SQLite -shm handle briefly after the server exits.
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        env = dict(os.environ, DSH_REMOTE_DB=str(Path(tmp) / "relay.sqlite3"), DSH_REMOTE_TOKEN_PEPPER="test-pepper-" + uuid.uuid4().hex)
        subprocess.run([sys.executable, "init_user.py", EMAIL, PASSWORD], cwd=ROOT, env=env, check=True, capture_output=True)
        port = free_port()
        server = subprocess.Popen([sys.executable, "-m", "uvicorn", "app:app", "--host", "127.0.0.1", "--port", str(port)],
                                  cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            base = f"http://127.0.0.1:{port}"
            for _ in range(100):
                try:
                    if httpx.get(f"{base}/health", timeout=1).status_code == 200:
                        break
                except httpx.HTTPError:
                    time.sleep(0.1)
            asyncio.run(run(base))
        finally:
            server.terminate()
            server.wait(10)
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
