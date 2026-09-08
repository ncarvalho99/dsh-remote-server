# DSH Remote Server (Self-Hosted Runtime)

An independent, protocol-compatible self-hosted coordination and relay server runtime for [DeepSeek Harness Remote](https://github.com/liguobao/ds-harness-remote) (`ds-harness-remote`).

It provides the complete control, auth, and encrypted relay infrastructure needed to operate your own private DSH Remote server behind your own domain (e.g., via Cloudflare Tunnel, Nginx, or Caddy).

---

## 🔒 Privacy & Architecture

- **End-to-End Encryption (E2EE):** The server coordinates device pairing and forwards opaque Noise IK encrypted WebSocket control and relay frames.
- **Zero Decryption:** The server never receives, decrypts, parses, or stores prompts, tool executions, file contents, code outputs, or session plaintext.
- **Stateless Access Tokens & Hashed Refresh Tokens:** Access tokens are cryptographically signed using a local server pepper; refresh tokens are stored as HMAC-SHA256 hashes in SQLite.

---

## 🚀 Features

- **FastAPI + Uvicorn + SQLite (WAL mode):** Ultra-lightweight resource footprint (<40MB RAM).
- **REST Device & Auth Protocol v1:**
  - `POST /api/v1/auth/login` — User authentication with Argon2id password hashing
  - `POST /api/v1/auth/refresh` — Cryptographic refresh token rotation
  - `POST /api/v1/devices/register` — Account-scoped device registration
  - `POST /api/v1/devices/register-owned-role` — Seamless opposite-role device pairing
  - `GET /api/v1/devices` & `GET /api/v1/devices/{id}/presence` — Real-time peer discovery and presence
  - `DELETE /api/v1/devices/self` — Device revocation
- **Opaque WebSocket Relay Gateway (`/ws/v1/connect`):**
  - Protocol v1 `hello` / `hello.ack` capability negotiation
  - Connection lifecycle (`connect.request`, `connect.incoming`, `connect.accepted`)
  - WebRTC signaling (`signal.offer`, `signal.answer`, `signal.ice`) and transport negotiation
  - Bidirectional encrypted relay transport with bounded frame checks and 25s ping/pong heartbeats
- **CLI Utilities:**
  - `init_user.py` — Add or update user accounts directly in SQLite
  - `generate_code.py` — Generate single-use, 10-minute host pairing codes

---

## 📦 Requirements

- Linux / Debian / Ubuntu (Bare metal, VM, or Proxmox LXC)
- Python 3.11+
- SQLite 3

---

## 🛠️ Installation & Setup

### 1. Clone & Set Up Virtual Environment

```bash
git clone https://github.com/ncarvalho99/dsh-remote-server.git /opt/dsh-remote-server
cd /opt/dsh-remote-server

python3 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt
```

### 2. Configure Environment

Create an environment file at `/etc/default/dsh-remote-server`:

```bash
# Generate a secure 64-char random hex pepper
PEPPER=$(python3 -c "import secrets; print(secrets.token_hex(32))")

sudo bash -c "cat <<EOF > /etc/default/dsh-remote-server
DSH_REMOTE_DB=/var/lib/dsh-remote/server.sqlite3
DSH_REMOTE_TOKEN_PEPPER=$PEPPER
EOF"

sudo chmod 600 /etc/default/dsh-remote-server
sudo mkdir -p /var/lib/dsh-remote
```

### 3. Initialize an Admin Account

```bash
set -a
source /etc/default/dsh-remote-server
set +a

./venv/bin/python3 init_user.py your-email@domain.com "your-password" --admin
```

### 4. Set Up Systemd Service

Create `/etc/systemd/system/dsh-remote-server.service`:

```ini
[Unit]
Description=DSH Remote Relay Server
After=network.target

[Service]
Type=simple
User=dshremote
Group=dshremote
WorkingDirectory=/opt/dsh-remote-server
EnvironmentFile=/etc/default/dsh-remote-server
ExecStart=/opt/dsh-remote-server/venv/bin/uvicorn app:app --host 0.0.0.0 --port 8080 --proxy-headers
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536
CapabilityBoundingSet=
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/dsh-remote

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo useradd -r -s /usr/sbin/nologin -d /opt/dsh-remote-server dshremote
sudo chown -R dshremote:dshremote /opt/dsh-remote-server /var/lib/dsh-remote
sudo systemctl daemon-reload
sudo systemctl enable --now dsh-remote-server
```

---

## 🌐 Ingress & Cloudflare Tunnel Configuration

Run the server behind Cloudflare Tunnel, Caddy, or Nginx with WebSocket support enabled.

### Cloudflare Tunnel:
1. In the **Zero Trust Dashboard** → **Networks** → **Tunnels**, select your active connector.
2. Under **Public Hostnames**, add a public hostname:
   - **Service Type:** `HTTP`
   - **URL:** `127.0.0.1:8080` (or your internal container IP: `10.x.x.x:8080` / `172.x.x.x:8080`)
   - Ensure **WebSockets** is enabled.

---

## 📱 Client / Plugin Configuration

### DSH Web / Desktop Plugin
In your DSH profile's `cordis.patch.yml`, set `serverUrl` to your domain:

```yaml
config:
  enabled: true
  role: host
  serverUrl: https://dsh-remote.yourdomain.com
```

### Android App
In the DSH Remote Android app login screen, enter your custom server URL in the server field:
```
https://dsh-remote.yourdomain.com
```
Then sign in with your email and password.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
