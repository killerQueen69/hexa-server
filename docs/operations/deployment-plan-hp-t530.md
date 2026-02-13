# Production Deployment Plan (HP t530)

## 1. Target Hardware

- Host: HP t530
- CPU: AMD GX-215JJ class
- RAM: 4 GB
- Storage: 16 GB SSD
- Deployment mode: single-node production

## 2. Chosen OS and Why

- OS: **Debian 13 (Trixie) minimal install**
- Why:
  - lower idle RAM and disk footprint than heavier server images
  - stable package set and long-term maintenance profile
  - good fit for 4 GB RAM / 16 GB SSD constraints

## 3. Exposure Decision (Cloudflare Tunnel vs Alternative)

### Decision

- **Use a split model:**
  - device/API traffic: direct TLS termination on HP t530 with Caddy
  - admin traffic: Cloudflare Tunnel + Cloudflare Access on a separate admin hostname
- Keep Cloudflare DNS record for device/API hostname as DNS-only (not proxied).
- Chosen hostnames:
  - `api.vistfiy.store` for ESP8266 device/API/OTA/WS traffic
  - `admin.vistfiy.store` for admin dashboard/API through Cloudflare Tunnel

### Why this is chosen for ESP8266 limits

- ESP8266 TLS memory is tight; predictable certificate chain is critical.
- Device plane stays on one stable host/cert path to avoid extra TLS complexity on constrained firmware.
- Admin plane can use Cloudflare Access controls without impacting device compatibility.

## 4. Network and DNS Layout

- `api.vistfiy.store` -> public WAN IP (DNS-only / not proxied; device/API endpoint)
- `admin.vistfiy.store` -> Cloudflare Tunnel (proxied; admin-only endpoint)
- Open and forward TCP `443` from router to HP t530
- Block public `3000`; Node app must be private behind Caddy only
- Allow outbound MQTT to customer HA broker:
  - usually TCP `8883` for `mqtts://`
  - optionally `1883` only for local non-TLS development

## 5. Required Software

Install on Debian:

- `caddy` (TLS reverse proxy + automatic certificates)
- `postgresql` (Debian package)
- `nodejs` 22 LTS
- `npm`
- `ufw` (firewall)
- `fail2ban` (optional but recommended)
- `jq`, `curl`, `git`, `ca-certificates`
- `cloudflared` (required for admin tunnel plane)

## 6. Runtime Architecture

- Caddy listens on `:443`
- Caddy reverse-proxies to `127.0.0.1:3000`
- Server runs as `systemd` service (non-root)
- PostgreSQL local socket/TCP with SSL enabled as configured
- Backups stored in `server/data/backups` (encrypted)

### 6.1 Remote Home Assistant Integration Model

- Server does not run an MQTT broker by default.
- Server acts as outbound MQTT client to whichever broker Home Assistant uses.
- For customer-managed remote HA:
  - configure server to connect to customer broker over `mqtts://...`
  - keep broker ACL limited to Hexa topic namespace
  - no inbound MQTT exposure is needed on HP t530

## 7. Security Baseline

- `NODE_ENV=production`
- `ENFORCE_HTTPS=true`
- `TRUST_PROXY=true`
- `DB_SSL=true` (or Unix socket/local trusted network if your DB is local-only)
- `DB_SSL_REJECT_UNAUTHORIZED=true` (keep true when TLS is enabled)
- Strong secrets for JWT/provision/backup keys
- No direct internet exposure for port `3000`
- UFW allow only `22/tcp` and `443/tcp`
- For remote HA MQTT:
  - `HA_MQTT_URL=mqtts://<broker>:8883`
  - `HA_MQTT_REJECT_UNAUTHORIZED=true`
  - set `HA_MQTT_CA_FILE` when broker uses private CA
  - optionally set client certificate/key if broker requires mTLS

## 8. ESP8266-Specific Production Constraints

- Use one stable HTTPS host for API/OTA to reduce trust-anchor complexity.
- Use compact JSON payloads and avoid oversized response bodies.
- Keep WS messages small; avoid large telemetry blobs.
- Use OTA chunks and timeout settings conservative for low-memory clients.
- Pin/validate certificate chain using minimal trust anchors in firmware.
- Keep one secure client connection per device session (avoid parallel secure sockets from one ESP8266).
- Keep max concurrent device commands bounded to avoid reconnect storms.

## 9. Step-by-Step Deployment

1. Install Debian 13 minimal; apply system updates.
2. Install dependencies from section 5.
3. Create service user (e.g., `hexa`) and deployment directories.
4. Clone repo to `/opt/hexa/resltime`.
5. Configure `server/.env` with production values and strong secrets.
   - If customer HA is remote, set HA MQTT values (`HA_MQTT_*`) before first start.
6. Run:
   - `npm ci`
   - `npm run migrate`
   - `npm run test:ci`
   - `npm run validate:signoff`
7. Configure Caddy reverse proxy for `api.vistfiy.store -> 127.0.0.1:3000`.
8. Configure Cloudflare Tunnel for `admin.vistfiy.store -> local admin route`.
9. Enable and start:
   - `postgresql`
   - `caddy`
   - `hexa-server.service`
10. Run:
   - `npm run backup:run`
   - `npm run restore:drill`
11. Validate external HTTPS, WS, OTA, and dashboard operations.
12. Validate HA MQTT bridge:
   - discovery messages are created in HA
   - relay state updates publish to MQTT
   - HA command topic toggles relays successfully
13. Make updater script executable:
   - `chmod +x /opt/hexa/resltime/server/scripts/ops-update-server.sh`

## 10. Initial systemd Unit (server)

Create `/etc/systemd/system/hexa-server.service`:

```ini
[Unit]
Description=Hexa Relay Platform Server
After=network.target postgresql.service

[Service]
Type=simple
User=hexa
WorkingDirectory=/opt/hexa/resltime/server
Environment=NODE_ENV=production
ExecStart=/usr/bin/node /opt/hexa/resltime/server/dist/index.js
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

## 11. Initial Caddyfile

`/etc/caddy/Caddyfile`:

```caddyfile
api.vistfiy.store {
  encode gzip

  @ws {
    header Connection *Upgrade*
    header Upgrade websocket
  }

  reverse_proxy @ws 127.0.0.1:3000
  reverse_proxy 127.0.0.1:3000
}
```

Route `admin.vistfiy.store` through `cloudflared` to local server and protect with Cloudflare Access policy.

## 12. Capacity Notes for 4 GB / 16 GB

- Keep PostgreSQL shared buffers conservative (`256MB` range).
- Keep Node single process initially.
- Keep log retention short and rotate aggressively.
- Keep backup retention small (`7` default is appropriate for 16 GB).

## 13. Go-Live Verification Checklist

- `GET /health` returns `ok` via HTTPS
- `GET /metrics` reachable only via HTTPS
- Device `wss://.../ws/device` handshake succeeds from ESP8266 firmware
- Relay command path success + timeout metrics visible
- OTA check/manifest/report flow passes with real firmware
- Backup + restore drill pass in production
- Remote HA MQTT discovery/state/command loop verified

## 14. Rollback Plan

- Keep previous `dist/` build artifact and previous `.env`.
- If deployment fails:
  - stop service
  - restore previous artifact/env
  - start service
  - validate `/health`, `/metrics`, and command path
- Follow full runbook: `docs/operations/rollback-runbook.md`

## 15. Domain-Specific Cloudflare Steps

- For production domain wiring and tunnel commands, follow:
  - `docs/operations/cloudflare-vistfiy-setup.md`

## 16. Routine Server Updates (Easier Path)

Use the update helper script:

```bash
sudo /opt/hexa/resltime/server/scripts/ops-update-server.sh
```

For a faster run (skip unit tests):

```bash
sudo /opt/hexa/resltime/server/scripts/ops-update-server.sh --fast
```

Detailed procedure is documented in:
- `docs/operations/server-update-runbook.md`

For fully automatic updates after push to `main`, configure:
- `.github/workflows/deploy-server.yml`
- required repository secrets (`PROD_SSH_*`)
