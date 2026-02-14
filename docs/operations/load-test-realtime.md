# Realtime Load Test Runbook

This runbook validates concurrent realtime load against production endpoints:

- `https://api.vistfiy.store` (all API + WS + device traffic)
- `https://admin.vistfiy.store` (admin dashboard only via Cloudflare Tunnel + Access)

## 1) DB Pool Settings (Required)

Set explicit DB pool values in `server/.env`:

```env
DB_POOL_MAX=30
DB_POOL_IDLE_TIMEOUT_MS=30000
DB_POOL_CONNECTION_TIMEOUT_MS=5000
```

Notes:

- `DB_POOL_MAX=30` is a practical starting point for HP t530 single-node.
- Keep PostgreSQL `max_connections` comfortably above this value.
- Tune with `/metrics` after a real load run.

## 2) Test Prerequisites

- Server is live and reachable on `api.vistfiy.store`.
- `api.vistfiy.store` stays **DNS-only** in Cloudflare (not proxied).
- `DEVICE_PROVISION_KEY` (or `LOAD_PROVISION_KEY`) is set.
- For admin-domain checks behind Cloudflare Access, create a service token and export:
  - `LOAD_ADMIN_CF_ACCESS_CLIENT_ID`
  - `LOAD_ADMIN_CF_ACCESS_CLIENT_SECRET`

## 3) Default Run (150 Devices + 150 Clients)

From `server/`:

```bash
npm run load:realtime
```

Default behavior:

- provisions/reuses 150 load-test devices
- opens 150 device sockets
- opens 150 client sockets
- sends realtime command rounds and checks ACK success
- checks admin dashboard reachability at `/dashboard` by default

## 4) Domain Guardrails

- Do not route API or WS load to `admin.vistfiy.store`.
- Keep `LOAD_API_BASE_URL` and `LOAD_CLIENT_BASE_URL` on `https://api.vistfiy.store`.
- The script enforces this and exits if `LOAD_CLIENT_BASE_URL` differs from API base URL.

## 5) Useful Overrides

```bash
LOAD_DEVICE_COUNT=200 \
LOAD_CLIENT_COUNT=200 \
LOAD_COMMAND_ROUNDS=3 \
LOAD_BATCH_SIZE=25 \
LOAD_RUN_TAG=t530-load \
LOAD_USER_EMAIL=loadtest-t530@vistfiy.store \
LOAD_USER_PASSWORD='StrongPasswordHere' \
npm run load:realtime
```

## 6) Pass/Fail

Treat as pass when:

- connected devices == target devices
- connected clients == target clients
- command failures == `0`
- `/metrics` does not show timeout spikes during run

The script exits non-zero on failed thresholds.
