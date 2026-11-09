"""End-to-end checks for the ds-harness-remote 0.6.x relay contract against a disposable relay.

Covers: relay data sockets (transport.relay.attach: relay.attach -> relay.ready, relay forwarding,
relay.detach), resume leases (transport.relay.resume.v1: connection.lease.request/ack rotation and
hello recoveryTickets, 4012 on stale tickets), connect.rejected/error forwarding to the client, and
mixed 0.5 client / 0.6 host routing. Run from the repository root:

    python tests/test_protocol_0_6.py
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import httpx
import websockets

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_protocol_0_5 import EMAIL, PASSWORD, ROOT, close_code, device, frame, free_port, recv_type  # noqa: E402

V06 = ["transport.relay", "transport.relay.attach", "transport.relay.resume.v1", "transport.webrtc.resume.v1", "harness.api.v1"]


async def hello(base_ws: str, dev: dict, token: str, capabilities: list[str], **extra):
    ws = await websockets.connect(f"{base_ws}/ws/v1/connect")
    payload = {"deviceId": dev["deviceId"], "accessToken": token, "protocols": [1], "capabilities": capabilities}
    payload.update(extra)
    await ws.send(frame("hello", payload))
    return ws


async def attach(endpoint: str, cid: str, dev: dict, peer: dict, ticket: str):
    ws = await websockets.connect(endpoint)
    await ws.send(frame("relay.attach", {"connectionId": cid, "deviceId": dev["deviceId"], "peerDeviceId": peer["deviceId"], "ticket": ticket}))
    return ws


def relay(cid: str, target: dict, data: str) -> str:
    return frame("relay", {"connectionId": cid, "targetDeviceId": target["deviceId"], "counter": 0, "ciphertext": data})


async def connect(base_ws, host_ws, client_ws, host, client):
    await client_ws.send(frame("connect.request", {"hostDeviceId": host["deviceId"], "preferredTransports": ["lan", "p2p", "turn", "relay"]}))
    incoming = (await recv_type(host_ws, "connect.incoming"))["payload"]
    await host_ws.send(frame("connect.accepted", {"connectionId": incoming["connectionId"]}))
    accepted = (await recv_type(client_ws, "connect.accepted"))["payload"]
    return incoming, accepted


async def run(base: str) -> None:
    base_ws = base.replace("http", "ws", 1)
    async with httpx.AsyncClient(base_url=base, timeout=10) as http:
        account = (await http.post("/api/v1/auth/login", json={"email": EMAIL, "password": PASSWORD})).json()["token"]
        auth = {"Authorization": f"Bearer {account}"}
        host, client, old_client = device("host", "H06", "0.6.3"), device("client", "C06", "0.6.3"), device("client", "C05", "0.5.17")
        tok = {}
        for dev in (host, client, old_client):
            tok[dev["deviceId"]] = (await http.post("/api/v1/devices/register", headers=auth, json={"v": 1, "device": dev})).json()

        h = await hello(base_ws, host, tok[host["deviceId"]]["accessToken"], V06, clientVersion="0.6.3")
        ack = (await recv_type(h, "hello.ack"))["payload"]
        assert {"transport.relay.attach", "transport.relay.resume.v1"} <= set(ack["capabilities"]), ack
        assert "transport.webrtc.resume.v1" not in ack["capabilities"] and ack["webrtcEnabled"] is False
        c = await hello(base_ws, client, tok[client["deviceId"]]["accessToken"], V06)
        await recv_type(c, "hello.ack")
        print("PASS hello.ack negotiates relay attach and relay resume, not WebRTC resume")

        # Host rejection reaches the client instead of leaving it waiting.
        await c.send(frame("connect.request", {"hostDeviceId": host["deviceId"], "preferredTransports": ["relay"]}))
        incoming = (await recv_type(h, "connect.incoming"))["payload"]
        await h.send(frame("connect.rejected", {"connectionId": incoming["connectionId"]}))
        rejected = (await recv_type(c, "connect.rejected"))["payload"]
        assert rejected["connectionId"] == incoming["connectionId"] and rejected["code"] == "CONNECTION_REJECTED", rejected
        await h.send(frame("connect.accepted", {"connectionId": incoming["connectionId"]}))  # tunnel is gone: ignored
        print("PASS connect.rejected forwarded to the client")

        incoming, accepted = await connect(base_ws, h, c, host, client)
        cid = incoming["connectionId"]
        for side in (incoming, accepted):
            assert side["relayEndpoint"].endswith("/ws/v1/relay") and side["relayEpoch"] == 0, side
            assert isinstance(side["relayTicket"], str) and isinstance(side["relayRecoveryTicket"], str)
        assert incoming["relayTicket"] != accepted["relayTicket"]
        print("PASS connect.incoming/accepted carry per-member relay assignment and recovery ticket")

        bad = await attach(accepted["relayEndpoint"], cid, client, host, "wrong-ticket")
        assert await close_code(bad) == 1008
        cd = await attach(accepted["relayEndpoint"], cid, client, host, accepted["relayTicket"])
        ready = (await recv_type(cd, "relay.ready"))["payload"]
        assert ready == {"connectionId": cid, "epoch": 0}, ready
        reuse = await attach(accepted["relayEndpoint"], cid, client, host, accepted["relayTicket"])
        assert await close_code(reuse) == 1008
        await c.send(frame("transport.selected", {"connectionId": cid, "targetDeviceId": host["deviceId"], "transport": "relay"}))
        assert (await recv_type(h, "transport.selected"))["payload"]["transport"] == "relay"
        hd = await attach(incoming["relayEndpoint"], cid, host, client, incoming["relayTicket"])
        await recv_type(hd, "relay.ready")
        print("PASS relay.attach: bad and reused tickets rejected (1008), relay.ready with epoch")

        await c.send(frame("secure.handshake", {"connectionId": cid, "targetDeviceId": host["deviceId"], "step": 1, "data": "AA"}))
        assert (await recv_type(h, "secure.handshake"))["payload"]["data"] == "AA"
        await cd.send(relay(cid, host, "C2H"))
        assert (await recv_type(hd, "relay"))["payload"]["ciphertext"] == "C2H"
        await h.send(relay(cid, client, "H2C-control"))  # control relay reaches the attached data socket
        assert (await recv_type(cd, "relay"))["payload"]["ciphertext"] == "H2C-control"
        await cd.send(frame("ping", {"nonce": "n1"}))
        assert (await recv_type(cd, "pong"))["payload"]["nonce"] == "n1"
        print("PASS data-socket relay forwarding both ways, control relay routed to data socket, data ping/pong")

        # Leases: request -> ack with rotated ticket; the previous ticket is accepted once more; garbage is refused.
        first = incoming["relayRecoveryTicket"]
        await h.send(frame("connection.lease.request", {"connectionId": cid, "requestId": "1", "ticket": first}))
        lease = (await recv_type(h, "connection.lease.ack"))["payload"]
        assert lease["requestId"] == "1" and lease["leaseMs"] == 300000 and lease["ticket"] != first, lease
        await h.send(frame("connection.lease.request", {"connectionId": cid, "requestId": "2", "ticket": lease["ticket"]}))
        lease = (await recv_type(h, "connection.lease.ack"))["payload"]
        await c.send(frame("connection.lease.request", {"connectionId": cid, "requestId": "x", "ticket": "garbage"}))
        refused = (await recv_type(c, "error"))["payload"]
        assert refused["code"] == "CONNECTION_NOT_FOUND" and refused["connectionId"] == cid, refused
        print("PASS connection.lease.request/ack rotation and refusal of unknown tickets")

        # Host control drops while leased + attached: tunnel survives, recovery hello resumes it.
        await h.close()
        await asyncio.sleep(0.3)
        await cd.send(relay(cid, host, "during-outage"))
        assert (await recv_type(hd, "relay"))["payload"]["ciphertext"] == "during-outage"
        stale = await hello(base_ws, host, tok[host["deviceId"]]["accessToken"], V06, recoveryTickets=["not-a-lease"])
        assert await close_code(stale) == 4012
        h = await hello(base_ws, host, tok[host["deviceId"]]["accessToken"], V06, recoveryTickets=[lease["ticket"]])
        await recv_type(h, "hello.ack")
        await h.send(frame("connection.lease.request", {"connectionId": cid, "requestId": "3", "ticket": lease["ticket"]}))
        lease = (await recv_type(h, "connection.lease.ack"))["payload"]
        await hd.send(relay(cid, client, "after-recovery"))
        assert (await recv_type(cd, "relay"))["payload"]["ciphertext"] == "after-recovery"
        print("PASS tunnel survives host control loss; 4012 on stale recovery ticket; recovery hello resumes the tunnel")

        # A host hello without the ticket means it dropped the tunnel: client data socket gets relay.detach.
        h2 = await hello(base_ws, host, tok[host["deviceId"]]["accessToken"], V06)
        await recv_type(h2, "hello.ack")
        assert (await recv_type(cd, "relay.detach"))["payload"] == {"connectionId": cid}
        assert await close_code(h) == 4003
        h = h2
        print("PASS reconnect without recovery ticket tears the tunnel down with relay.detach")

        # Closing one data socket detaches the peer.
        incoming, accepted = await connect(base_ws, h, c, host, client)
        cid = incoming["connectionId"]
        cd = await attach(accepted["relayEndpoint"], cid, client, host, accepted["relayTicket"])
        await recv_type(cd, "relay.ready")
        hd = await attach(incoming["relayEndpoint"], cid, host, client, incoming["relayTicket"])
        await recv_type(hd, "relay.ready")
        await cd.close()
        assert (await recv_type(hd, "relay.detach"))["payload"] == {"connectionId": cid}
        print("PASS closing a data socket sends relay.detach to the peer")

        # Host-side error with connectionId is forwarded to the client and ends the tunnel.
        incoming, accepted = await connect(base_ws, h, c, host, client)
        await h.send(frame("error", {"code": "CONNECTION_FAILED", "message": "Relay data connection failed.", "retryable": True,
                                     "connectionId": incoming["connectionId"]}))
        forwarded = (await recv_type(c, "error"))["payload"]
        assert forwarded["code"] == "CONNECTION_FAILED" and forwarded["connectionId"] == incoming["connectionId"], forwarded
        print("PASS host error with connectionId forwarded to the client")

        # 0.5 client (control relay only) against a 0.6 host using a data socket.
        o = await hello(base_ws, old_client, tok[old_client["deviceId"]]["accessToken"], ["transport.relay", "harness.api.v1"])
        await recv_type(o, "hello.ack")
        incoming, accepted = await connect(base_ws, h, o, host, old_client)
        cid = incoming["connectionId"]
        assert "relayEndpoint" not in accepted and "relayRecoveryTicket" not in accepted, accepted
        hd = await attach(incoming["relayEndpoint"], cid, host, old_client, incoming["relayTicket"])
        await recv_type(hd, "relay.ready")
        await hd.send(relay(cid, old_client, "to-old"))
        assert (await recv_type(o, "relay"))["payload"]["ciphertext"] == "to-old"
        await o.send(relay(cid, host, "from-old"))
        assert (await recv_type(hd, "relay"))["payload"]["ciphertext"] == "from-old"
        await o.close()
        assert (await recv_type(hd, "relay.detach"))["payload"] == {"connectionId": cid}
        print("PASS 0.5 control-relay client interoperates with a 0.6 data-socket host; its disconnect detaches the host")

        await h.send(frame("bogus.frame", {}))
        assert (await recv_type(h, "error"))["payload"]["code"] == "CAPABILITY_NOT_SUPPORTED"
        print("PASS unsupported control frames still answered with CAPABILITY_NOT_SUPPORTED")
        for ws in (h, c):
            await ws.close()


def main() -> int:
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        env = dict(os.environ, DSH_REMOTE_DB=str(Path(tmp) / "relay.sqlite3"), DSH_REMOTE_TOKEN_PEPPER="test-pepper-" + uuid.uuid4().hex)
        env.pop("DSH_REMOTE_PUBLIC_URL", None)
        subprocess.run([sys.executable, "init_user.py", EMAIL, PASSWORD], cwd=ROOT, env=env, check=True, capture_output=True)
        port = free_port()
        log_path = Path(tmp) / "server.log"
        with open(log_path, "w") as log:
            server = subprocess.Popen([sys.executable, "-m", "uvicorn", "app:app", "--host", "127.0.0.1", "--port", str(port)],
                                      cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
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
        text = log_path.read_text(errors="replace")
        assert "Traceback" not in text, text
        assert "unsupported control frame 'bogus.frame'" in text, text
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
