# How The Platform Works

This document explains the implemented runtime behavior of the current server and dashboard.

## 1. High-Level Runtime Model

The platform has one central server that coordinates:

- Auth and user identity (`JWT` access tokens + refresh rotation).
- Device lifecycle (provisioning, claim/release, ownership, config sync).
- Device capability extensibility (relay, IR, sensor, and hybrid classes).
- Realtime command routing (`WS` for devices and browser clients).
- Persistent state (`relay_states`, schedules, automations, audit, OTA artifacts).
- Per-user persisted dashboard/app preferences.
- Smart-home integrations (Alexa endpoint, HomeKit bridge runtime, Home Assistant MQTT bridge).
- Production operations (metrics, backups, restore drills, OTA signing key rotation, admin dashboard).
- Production transport guardrails (HTTPS/WSS enforcement when enabled).

Core design rule:

- All relay state changes go through the central relay service path, then fan out to DB/WS/smart-home/audit.

## 2. Request and Authentication Flow

### 2.1 Browser/API Clients

1. Client authenticates via `POST /api/v1/auth/login` or `register`.
2. Server returns:
   - `access_token` (JWT, short-lived)
   - `refresh_token` (rotating, stored hashed)
3. Protected REST routes use `Authorization: Bearer <access_token>`.
4. Role checks (`admin`/`user`) are enforced where required.

### 2.2 Devices

1. Device provisions with `POST /api/v1/provision/register` using `DEVICE_PROVISION_KEY`.
2. Server returns `device_uid` + `device_token`.
3. Device opens `WS /ws/device?uid=<uid>&token=<token>`.
4. Server validates token hash, registers session, and starts heartbeat tracking.

## 3. Relay Command Path (Single Source Of Truth)

When any source triggers a relay command (API, WS client, schedule, automation, HomeKit, Alexa, HA):

1. Validate ownership/device status.
2. Send WS command to device (`set_relay` or `set_all_relays`) with `command_id`.
3. Wait for device `ack` or timeout.
4. Persist relay states in `relay_states`.
5. Update in-memory device state cache.
6. Broadcast updates to relevant web client sessions.
7. Fan out to smart-home bridges (HomeKit characteristic + MQTT state/availability).
8. Write audit entry.
9. Emit metrics (`success`/`timeout`/`error`, latency histogram).

## 4. Device State Report and Event Flow

### 4.1 Device `state_report`

When a device sends `state_report` on WS:

- Server updates `last_seen_at` and IP.
- Server reconciles relay changes vs existing DB state.
- Server updates `relay_states` and cache.
- Server pushes `device_state` to owner clients.
- Server syncs smart-home bridges.
- If relays changed, server writes a system audit entry.

### 4.2 Input Events

When a device sends `input_event`:

- Automation engine evaluates matching enabled rules.
- If rule matches and passes cooldown/dedupe, relay action is executed through relay service.
- `automation_fired` is pushed to user clients.

## 5. Extensibility for Future Device Families

The server is now ready for upcoming non-relay and mixed hardware lines:

- Device type model:
  - `device_class`: `relay_controller`, `ir_hub`, `sensor_hub`, `hybrid`
  - `capabilities` summary on each device
  - normalized `device_capabilities` table
- IR learning/transmit support:
  - `device_ir_codes` table
  - REST CRUD under `/api/v1/devices/:id/ir-codes`
- Sensor support (motion, mmWave, and future sensors):
  - `device_sensor_state` for latest values
  - `device_sensor_events` for event timeline/history
  - user/admin ingest routes and device callback route `POST /api/v1/devices/sensor-report`

This avoids future schema rewrites for new device classes.

## 6. Schedules and Automations

### 6.1 Scheduler

- Internal worker ticks every 10 seconds.
- Loads due schedules (`next_execution <= now()`).
- Executes relay actions via relay service.
- Updates execution counters/timestamps and computes next run.
- Records failures to audit and metrics.

### 6.2 Automation Engine

- Event-driven rules on:
  - `input_event`
  - `button_hold`
  - `device_online`
  - `device_offline`
- Enforces cooldown and dedupe window.
- Actions:
  - `set_relay`
  - `set_all_relays`

## 7. OTA Update Strategy (Implemented Server Side)

### 7.1 Release Management

- OTA releases are stored in `ota_releases`.
- Server supports channels: `dev`, `beta`, `stable`.
- `security_version` is enforced for anti-rollback.
- Admin can upload firmware `.bin` directly; server computes artifact hash/size,
  stores artifact under OTA storage path, generates artifact URL, and creates signed release metadata.

### 7.2 Manifest Signing

- Manifest payload is canonicalized and signed using `ecdsa-p256-sha256`.
- Release stores:
  - `signature`
  - `verification_key_id` (active key used)
  - `next_verification_key_id` (for firmware key rotation window)
  - `manifest_payload` (signed canonical payload)

### 7.3 Key Rotation

- Signing keys live in `ota_signing_keys`.
- Supported statuses: `active`, `next`, `retired`.
- Rotation endpoint promotes `next -> active` and retires prior active.

### 7.4 Fail-Closed Validation

Before serving a manifest, server verifies:

- allowed host policy
- signature algorithm
- key IDs exist
- release fields match canonical manifest payload
- signature verifies against `verification_key_id`
- candidate respects minimum device `ota_security_version`

If any check fails, release is not served.

## 8. Backup and Disaster Recovery

### 8.1 Encrypted Backup

- Backup service exports critical tables into one JSON envelope.
- Encrypts with `AES-256-GCM`.
- Key source:
  - `BACKUP_ENCRYPTION_KEY` (production expected)
  - non-production fallback from JWT secret hash
- Retention enforced by `BACKUP_RETENTION_COUNT`.
- Runs recorded in `ops_backup_runs`.

### 8.2 Restore Drill

- Decrypts latest (or specified) backup.
- Validates backup structure and required table dumps.
- Compares backup table row counts to current DB row counts.
- Measures elapsed time and enforces configured RTO.
- Records drill result in `ops_backup_runs`.

## 9. Observability and Alerts

- `/health` for liveness/basic DB check.
- `/metrics` for Prometheus format metrics:
  - command totals and latency
  - scheduler tick/execution outcomes
  - API error totals
  - fleet/user gauge summaries
- Admin route `POST /api/v1/admin/ops/alerts/simulate` evaluates alert thresholds over current metrics snapshot and backup failures.

## 10. Per-User Preferences

Per-user UI and app state is persisted server-side in `user_preferences`, exposed via `/api/v1/preferences`:

- `dashboard_layout`
- `dashboard_settings`
- `device_view_state`
- `notification_settings`

This covers saved dashboard layout, operator settings, and last-viewed device state context.

## 11. Admin Dashboard (`/dashboard`)

The dashboard is a live operations console and uses real APIs (no mock placeholders) to manage:

- auth + session refresh
- automatic access-token refresh on API `401` using refresh token
- persisted dashboard session + base URL/user context across page reloads
- collapsible cards with persisted collapsed state
- fleet overview KPIs
- user role/activation updates
- device relay operations and token rotation
- device claim-by-code from dashboard user session
- device delete action (admin)
- richer device view (relay names, input config, power restore mode, last action, last input event)
- online/stale heuristic using `last_seen_at` freshness
- OTA signing keys and release signing lifecycle
- backup/restore drill execution and history
- alert simulation and raw metrics view
- audit stream filtering

## 12. Home Assistant MQTT Bridge (Remote-Friendly)

When `HA_MQTT_ENABLED=true`, the server acts as an MQTT client and connects outbound to a broker (local or remote customer-managed HA broker).

- MQTT transport:
  - local dev can use `mqtt://...`
  - production should use `mqtts://...`
- Topic contract:
  - discovery publish: `homeassistant/switch/hexa_<device_uid>_<relay_index>/config`
  - state publish: `hexa/<device_uid>/relay/<relay_index>/state`
  - availability publish: `hexa/<device_uid>/availability`
  - command subscribe: `hexa/+/relay/+/set`
- Remote TLS controls:
  - `HA_MQTT_REJECT_UNAUTHORIZED=true` by default
  - optional `HA_MQTT_CA_FILE`, `HA_MQTT_CERT_FILE`, `HA_MQTT_KEY_FILE`, `HA_MQTT_KEY_PASSPHRASE`
  - optional `HA_MQTT_SNI_SERVERNAME`
  - keepalive/connect timeout tunables for WAN links

No inbound MQTT listener is opened on this server for HA integration; only outbound broker connections are used.

## 13. Request Idempotency and Error Contract

### 13.1 Idempotency

- Applies to mutating methods (`POST`, `PATCH`, `PUT`, `DELETE`) when `idempotency-key` header is sent.
- Replay returns original response + `idempotency-replayed: true`.
- Conflicting payload for same key returns `409 idempotency_conflict`.

### 13.2 Production Transport Security

- In production, when `ENFORCE_HTTPS=true`, plain HTTP and non-secure WS upgrades are rejected.
- Plain HTTP requests are rejected with `426 https_required` (except localhost maintenance access).
- Proxy TLS termination is supported via `TRUST_PROXY=true` and forwarded proto checks.
- Intended deployment pattern: TLS termination at reverse proxy (e.g., Caddy) with forwarded proto headers.

### 13.3 Error Shape

All API errors use:

```json
{
  "code": "validation_error",
  "message": "Human readable error",
  "details": null,
  "request_id": "req-abc123"
}
```
