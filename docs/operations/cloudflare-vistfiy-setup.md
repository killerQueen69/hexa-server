# Cloudflare Setup for `vistfiy.store`

This document applies your chosen production hostnames:

- `api.vistfiy.store` (device/API plane, direct TLS on Caddy)
- `admin.vistfiy.store` (admin plane, Cloudflare Tunnel + Access)

## 1. DNS Records in Cloudflare

Create these DNS records:

- `A` record:
  - Name: `api`
  - Content: your home/public WAN IP
  - Proxy status: **DNS only** (gray cloud)
- `admin` record is created automatically by:
  - `cloudflared tunnel route dns vistfiy-admin admin.vistfiy.store`
  - Proxy status: **Proxied** (orange cloud)

Notes:

- Keep `api.vistfiy.store` DNS-only so ESP8266 talks directly to your Caddy cert chain.
- Keep `admin.vistfiy.store` proxied so Cloudflare Access policies can protect admin traffic.
- Use `admin.vistfiy.store` only for admin dashboard/operator access, not for firmware or device API/WS traffic.

## 2. Caddy (Device/API Plane)

Use this `/etc/caddy/Caddyfile` block:

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

Reload:

```bash
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

## 3. Cloudflare Tunnel (Admin Plane)

Install `cloudflared`, then:

```bash
cloudflared tunnel login
cloudflared tunnel create vistfiy-admin
cloudflared tunnel route dns vistfiy-admin admin.vistfiy.store
TUNNEL_ID=$(cloudflared tunnel list | awk '/vistfiy-admin/ {print $1; exit}')
sudo mkdir -p /etc/cloudflared
sudo cp ~/.cloudflared/$TUNNEL_ID.json /etc/cloudflared/
```

Create `/etc/cloudflared/config.yml`:

```yaml
tunnel: TUNNEL_ID
credentials-file: /etc/cloudflared/TUNNEL_ID.json
ingress:
  - hostname: admin.vistfiy.store
    service: http://127.0.0.1:3000
  - service: http_status:404
```

Before enabling service:

```bash
sudo sed -i "s/TUNNEL_ID/$TUNNEL_ID/g" /etc/cloudflared/config.yml
```

Enable:

```bash
sudo systemctl enable --now cloudflared
```

## 4. Cloudflare Access Policy (Required for Admin)

In Cloudflare Zero Trust:

1. Create one self-hosted application for `admin.vistfiy.store`.
2. Require identity login (email/OTP, Google, or your IdP).
3. Allow only your admin identities/groups.
4. Set session duration (for example 12h).

## 5. Server `.env` Baseline

```env
NODE_ENV=production
TRUST_PROXY=true
ENFORCE_HTTPS=true
DB_SSL=true
DB_SSL_REJECT_UNAUTHORIZED=true
```

## 6. ESP8266 Endpoint Rules

- Firmware should use only `api.vistfiy.store` for:
  - REST (`/api/v1/*`)
  - OTA (`/api/v1/ota/*`)
  - WS (`wss://api.vistfiy.store/ws/device`)
- Do not point devices to `admin.vistfiy.store`.

## 7. Firmware Build Profile

A production build environment is available at:

- `firmware/platformio.ini` -> `[env:hexa_mini_v1_prod]`

It is pinned to:

- `FW_DEFAULT_SERVER_HOST="api.vistfiy.store"`
- `FW_DEFAULT_SERVER_PORT=443`
- `FW_DEFAULT_USE_TLS=1`

Build/upload example:

```bash
cd firmware
pio run -e hexa_mini_v1_prod
pio run -e hexa_mini_v1_prod -t upload
```

Current compile check for `hexa_mini_v1_prod`:

- RAM: `41.4%` (`33924 / 81920` bytes)
- Flash: `50.6%` (`528323 / 1044464` bytes)

## 8. Home Assistant MQTT with Remote Customer Broker

Cloudflare setup in this document covers HTTPS/WSS hostnames only. Home Assistant integration uses MQTT directly and is configured in `server/.env`:

- `HA_MQTT_ENABLED=true`
- `HA_MQTT_URL=mqtts://<customer-broker-host>:8883`
- `HA_MQTT_USERNAME`, `HA_MQTT_PASSWORD` (if required)
- `HA_MQTT_REJECT_UNAUTHORIZED=true` (default)
- optional trust/cert settings:
  - `HA_MQTT_CA_FILE`
  - `HA_MQTT_CERT_FILE`
  - `HA_MQTT_KEY_FILE`
  - `HA_MQTT_KEY_PASSPHRASE`
  - `HA_MQTT_SNI_SERVERNAME`

No Cloudflare Tunnel is required for MQTT unless you intentionally run MQTT over WebSockets through another edge design.
