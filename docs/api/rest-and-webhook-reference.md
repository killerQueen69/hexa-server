# REST APIs and Webhook-Style HTTP Endpoints

This is the live HTTP contract for the current server implementation.

## 1. Conventions

### Base

- API base: `/api/v1`
- Health/metrics:
  - `GET /health`
  - `GET /metrics`
- Production transport:
  - when `ENFORCE_HTTPS=true`, server rejects non-HTTPS API requests and non-secure WS upgrades.

### Auth Header

- Protected routes require:
  - `Authorization: Bearer <access_token>`

### Idempotency

- For mutating routes (`POST`, `PATCH`, `PUT`, `DELETE`), optional:
  - `idempotency-key: <key>`
- Replay response includes:
  - `idempotency-replayed: true`

### Error Contract

```json
{
  "code": "validation_error",
  "message": "Invalid request body.",
  "details": null,
  "request_id": "req-123"
}
```

## 2. Public System Endpoints

### `GET /health`

- Purpose: liveness and DB connectivity check.
- Response fields:
  - `status`
  - `uptime_seconds`
  - `db_engine`
  - `now`

### `GET /metrics`

- Purpose: Prometheus metrics output (text format).

### `GET /dashboard`

- Purpose: Serve operations dashboard UI.
- Source file: `server/public/dashboard.html` (served by backend route).

### `GET /test-ui`

- Purpose: legacy testing UI.

## 3. Auth APIs

Prefix: `/api/v1/auth`

### `POST /register`

- Body:
  - `email`
  - `password`
  - `name`
  - optional `claim_code`
- Returns:
  - `user`
  - `access_token`
  - `refresh_token`
  - optional `claimed_device_uid`

### `POST /login`

- Body: `email`, `password`
- Returns: `user`, `access_token`, `refresh_token`

### `POST /refresh`

- Body: `refresh_token`
- Returns: `access_token`, `refresh_token` (rotated)

### `POST /logout`

- Body: `refresh_token`
- Returns: `{ "ok": true }`

## 4. Device Provisioning API

Prefix: `/api/v1/provision`

### `POST /register`

- Device bootstrap endpoint.
- Body:
  - `provision_key`
  - `chip_id`
  - optional `mac`
  - optional `claim_code` (8 hex chars). If not provided, server derives a stable claim code from MAC/hardware/device identity.
  - optional `model`
  - optional `firmware_version`
  - optional `relay_count`
  - optional `button_count`
- Returns:
  - `device_id`
  - `device_uid`
  - `device_token`
  - `claim_code`
  - `claimed`

## 5. Device APIs (User Context)

Prefix: `/api/v1/devices`

### `GET /`

- List devices owned by authenticated user.

### `GET /:id`

- Get one owned device.

### `POST /claim`

- Body: `claim_code`
- Claims an unowned provisioned device for authenticated user.

### `POST /:id/release`

- Release owned device back to unclaimed pool.
- Returns stable `claim_code` (existing code is reused; release does not rotate it).

### `POST /` (admin role)

- Create device record manually.
- Supports future-ready fields:
  - `device_class`: `relay_controller|ir_hub|sensor_hub|hybrid`
  - `capabilities`: capability summary array (`key`, `kind`, `enabled`)

### `PATCH /:id`

- Update owned device fields (`name`, `is_active`, `firmware_version`, `device_class`, `capabilities`, `input_config`, `power_restore_mode`, `config`).
- If `config.connectivity`/`config.connection` contains transport settings, server pushes a runtime `config_update` with connectivity payload to the online device.

### `PATCH /:id/io-config`

- Body: full `input_config` array.
- Enforces matrix validation (push/rocker/link/target/mode rules).
- Pushes runtime `config_update` to online device.

### `PATCH /:id/power-restore-mode`

- Body: `power_restore_mode` in `last_state|all_off|all_on`
- Pushes runtime `config_update` to online device.

### `POST /:id/relays/:index`

- Body: `action` in `on|off|toggle`
- Optional body field: `timeout_ms` (1000-30000) to override command ACK timeout per request.
- Effective server-side command wait is capped to `4000ms` (internal guardrail).
- Executes single relay command.

### `POST /:id/relays/all`

- Body: `action` in `on|off`
- Optional body field: `timeout_ms` (1000-30000) to override command ACK timeout per request.
- Effective server-side command wait is capped to `4000ms` (internal guardrail).
- Executes all-relays command.

Relay command error notes:

- `409 device_offline`: no active WS device session.
- `409 device_disconnected`: WS session dropped before ACK.
- `409 device_unreachable`: ACK timed out and state verification window did not confirm the command.
- ACK timeout fallback uses state verification window (capped to `800ms`) before returning `device_unreachable`.

### `POST /:id/token/rotate`

- Rotate device token for owned device.

### `DELETE /:id` (admin role)

- Delete device.

## 6. Device Feature APIs (Extensibility)

Prefix: `/api/v1/devices`

### Capabilities

- `GET /:id/capabilities`
- `PUT /:id/capabilities/:capabilityKey`
- `DELETE /:id/capabilities/:capabilityKey`

### IR Code Library

- `GET /:id/ir-codes`
- `POST /:id/ir-codes`
- `PATCH /:id/ir-codes/:codeId`
- `DELETE /:id/ir-codes/:codeId`

### Sensor State and Events

- `GET /:id/sensor-state`
- `POST /:id/sensor-state`
- `GET /:id/sensor-events`
- `POST /:id/sensor-events`

### Device Sensor Callback (Webhook-Style)

- `POST /sensor-report`
- Body:
  - `device_uid`
  - `device_token`
  - `events[]` with `sensor_key`, `sensor_type`, `event_kind`, `value`, optional `observed_at`
- Behavior:
  - Authenticates firmware/device token
  - Writes `device_sensor_events`
  - Upserts `device_sensor_state`
  - Writes audit log

## 7. User Preferences APIs

Prefix: `/api/v1/preferences`

- `GET /`
  - Returns persisted per-user dashboard/app preferences.
- `PATCH /`
  - Supports:
    - `dashboard_layout`
    - `dashboard_settings`
    - `device_view_state`
    - `notification_settings`
    - `merge` boolean (default `true`).

## 8. Schedule APIs

Prefix: `/api/v1/schedules`

### `GET /`

- Query optional: `device_id`
- List schedules owned by user.

### `POST /`

- Create schedule.
- Supports:
  - `target_scope`: `single|all`
  - `schedule_type`: `once|cron`
  - `action`: `on|off|toggle` (toggle not allowed for all scope)
  - `timezone`

### `PATCH /:id`

- Update schedule fields and recompute next execution.

### `POST /:id/enable`

- Enable schedule and compute next run.

### `POST /:id/disable`

- Disable schedule.

### `DELETE /:id`

- Delete schedule.

## 9. Automation APIs

Prefix: `/api/v1/automations`

### `GET /`

- Query optional: `device_id`
- List automations owned by user.

### `POST /`

- Create automation.
- Trigger types:
  - `input_event`
  - `button_hold`
  - `device_online`
  - `device_offline`
- Action types:
  - `set_relay`
  - `set_all_relays`

### `PATCH /:id`

- Update automation.

### `POST /:id/enable`

- Enable automation.

### `POST /:id/disable`

- Disable automation.

### `DELETE /:id`

- Delete automation.

## 10. OTA APIs

Prefix: `/api/v1/ota`

### Device Update Checks

#### `GET /check`

- Query:
  - `device_uid` (required)
  - `current` semver (required)
  - optional `channel`
  - optional `token` (device token)
- Returns either:
  - `update_available: false`
  - or signed `manifest` with:
    - `signature`
    - `verification_key_id`
    - `next_verification_key_id`

#### `GET /manifest/:device_uid`

- Query:
  - optional `channel`
  - optional `current`
  - optional `token`
- Returns selected signed manifest, including:
  - `signature`
  - `verification_key_id`
  - `next_verification_key_id`

### OTA Device Callback (Webhook-Style)

#### `POST /report`

- Purpose: device callback for OTA state transitions.
- Body:
  - `device_uid`
  - `device_token`
  - `event_type` in `check|download|verify|install|rollback|success|failure|boot_ok`
  - `status` in `ok|error|in_progress|rejected`
  - optional `from_version`, `to_version`, `security_version`, `reason`, `details`
- Behavior:
  - records row in `ota_reports`
  - updates device OTA status/version fields
  - rejects rollback if reported `security_version` is below current minimum
  - pushes `ota_status` realtime event to owner clients

### OTA Release Management (Admin)

#### `GET /releases`

- Optional query: `model`, `channel`
- Lists release registry.

#### `POST /releases`

- Creates signed release manifest entry.
- Enforces anti-rollback floor per model/channel active releases.
- Supports auto-signing from active signing key.

#### `POST /releases/upload`

- `multipart/form-data` admin endpoint for firmware upload.
- Uploads `.bin`, computes `sha256` + `size_bytes`, stores artifact under server OTA artifact directory,
  builds public artifact URL, then creates signed release entry.
- Accepts optional form fields:
  - `model`, `version`, `channel` (otherwise inferred from filename pattern `model-version-channel.bin`)
  - `security_version`, `expires_at`, `is_active`, `metadata`, `auto_sign`
  - manual signing fields (`signature`, `verification_key_id`, `next_verification_key_id`) when `auto_sign=false`

#### `GET /artifacts/*`

- Public binary artifact serving endpoint used by OTA manifests.
- Path resolves inside configured OTA artifact root only (path traversal blocked).

#### `PATCH /releases/:id`

- Updates release fields, re-signs when signed fields change.

#### `GET /releases/:id/verify`

- Verifies manifest integrity and signature validity.

### OTA Signing Key Management (Admin)

#### `GET /signing-keys`

- Lists key registry.

#### `POST /signing-keys`

- Creates key row:
  - `key_id`
  - `public_key_pem`
  - `private_key_secret_ref`
  - `status` (`active|next|retired`)

#### `PATCH /signing-keys/:id`

- Updates key material/status.

#### `POST /signing-keys/rotate`

- Promotes `next -> active`, retires previous active.

## 11. Alexa Smart Home Endpoint (Webhook-Style)

Prefix: `/api/v1/alexa`

### `POST /smart-home`

- Purpose: Alexa directive callback endpoint.
- Handles:
  - `Alexa.Authorization.AcceptGrant`
  - `Alexa.Discovery.Discover`
  - `Alexa.PowerController.TurnOn`
  - `Alexa.PowerController.TurnOff`
  - `Alexa.ReportState`
- Token validation: expects JWT-like bearer token mapped to platform user.

Example directive envelope:

```json
{
  "directive": {
    "header": {
      "namespace": "Alexa.Discovery",
      "name": "Discover",
      "payloadVersion": "3",
      "messageId": "abc-123"
    },
    "payload": {
      "scope": {
        "type": "BearerToken",
        "token": "Bearer <jwt>"
      }
    }
  }
}
```

## 12. Audit APIs

### User/Owner Scope

Prefix: `/api/v1/audit`

#### `GET /`

- Query:
  - optional `device_id`
  - optional `source`
  - optional `action`
  - optional `limit`, `offset`
- Non-admin users only see records for their owned devices.

### Admin Scope

Prefix: `/api/v1/admin`

#### `GET /audit`

- Global audit log query with filters.

#### `DELETE /audit`

- Clears audit rows.
- Optional query filters: `device_id`, `source`, `action`.
- Returns number of deleted rows.

## 13. Admin Operations APIs

Prefix: `/api/v1/admin` (admin role required)

### Fleet/Platform

- `GET /overview`
- `GET /versioning`

### User Admin

- `GET /users`
- `PATCH /users/:id`

### Device Admin

- `GET /devices`
- `PATCH /devices/:id`
- `POST /devices/:id/token/rotate`
- `POST /devices/:id/release`
- `POST /devices/:id/relays/:index`
- `POST /devices/:id/relays/all`

Relay/admin command behavior:

- `device_disconnected` now returns HTTP `409` when the device disconnects before ACK.
- `device_unreachable` returns HTTP `409` after ACK timeout + state-verify window miss.
- `device_offline` returns HTTP `409` when device session is not online.

### Backup and Restore

- `GET /ops/backup/policy`
- `GET /ops/backup/runs`
- `POST /ops/backup/run`
- `POST /ops/restore-drill/run`

### Alert Simulation

- `POST /ops/alerts/simulate`

## 14. Webhook Summary

Incoming webhook-style HTTP callbacks implemented:

1. `POST /api/v1/ota/report` (device OTA status callback)
2. `POST /api/v1/alexa/smart-home` (Alexa directive callback)
3. `POST /api/v1/devices/sensor-report` (device sensor event callback)

Outbound HTTP webhooks:

- None currently implemented. Outbound realtime updates use WebSocket events and smart-home bridges.

## 15. Home Assistant MQTT Bridge (Non-HTTP)

The HA integration is MQTT-based (not REST/webhook). The server connects outbound to a broker and publishes discovery/state while consuming command topics.

Notes:

- This section is for server-side HA bridge (`HA_MQTT_*` env vars).
- Firmware local MQTT transport mode is a separate device-side path switched via `config_update.connectivity.mode`.

### MQTT Topic Contract

- Discovery publish:
  - `<HA_MQTT_DISCOVERY_PREFIX>/switch/hexa_<device_uid>_<relay_index>/config`
- Relay state publish:
  - `<HA_MQTT_BASE_TOPIC>/<device_uid>/relay/<relay_index>/state`
- Device availability publish:
  - `<HA_MQTT_BASE_TOPIC>/<device_uid>/availability`
- Command subscribe:
  - `<HA_MQTT_BASE_TOPIC>/+/relay/+/set`

Command payloads accepted:

- `ON`, `OFF`, `TOGGLE`
- `1`, `0`
- `TRUE`, `FALSE`

### Remote Customer-Hosted HA Broker

Supported by configuring the server as an outbound MQTT client:

- `HA_MQTT_ENABLED=true`
- `HA_MQTT_URL=mqtts://<customer-broker-host>:8883`
- `HA_MQTT_USERNAME`, `HA_MQTT_PASSWORD` (if required)
- `HA_MQTT_REJECT_UNAUTHORIZED=true` (default)
- Optional TLS files:
  - `HA_MQTT_CA_FILE`
  - `HA_MQTT_CERT_FILE`
  - `HA_MQTT_KEY_FILE`
  - `HA_MQTT_KEY_PASSPHRASE`
  - `HA_MQTT_SNI_SERVERNAME`
- WAN tuning:
  - `HA_MQTT_KEEPALIVE_SECONDS`
  - `HA_MQTT_CONNECT_TIMEOUT_MS`
  - `RELAY_COMMAND_TIMEOUT_MS`
  - `RELAY_COMMAND_STATE_VERIFY_WINDOW_MS`
  - `RELAY_COMMAND_STATE_VERIFY_POLL_MS`

Notes:

- No inbound MQTT port is required on this server for HA integration.
- Home Assistant auto-discovery still works when the broker is remote, as long as HA is connected to that same broker.

## 16. Usage Examples

### Login

```bash
curl -X POST http://localhost:3000/api/v1/auth/login \
  -H "content-type: application/json" \
  -d '{"email":"admin@example.com","password":"AdminPass!234"}'
```

### Relay Command (single)

```bash
curl -X POST http://localhost:3000/api/v1/devices/<device_id>/relays/0 \
  -H "authorization: Bearer <access_token>" \
  -H "content-type: application/json" \
  -H "idempotency-key: cmd-001" \
  -d '{"action":"toggle"}'
```

### Run Backup (admin)

```bash
curl -X POST http://localhost:3000/api/v1/admin/ops/backup/run \
  -H "authorization: Bearer <access_token>" \
  -H "content-type: application/json" \
  -d '{}'
```

### OTA Report Callback (device webhook-style)

```bash
curl -X POST http://localhost:3000/api/v1/ota/report \
  -H "content-type: application/json" \
  -d '{
    "device_uid":"hexa-mini-001",
    "device_token":"dt_...",
    "event_type":"success",
    "status":"ok",
    "from_version":"1.0.0",
    "to_version":"1.1.0",
    "security_version":3
  }'
```

### Save User Dashboard Preferences

```bash
curl -X PATCH http://localhost:3000/api/v1/preferences \
  -H "authorization: Bearer <access_token>" \
  -H "content-type: application/json" \
  -d '{
    "dashboard_layout":{"pinned_sections":["overview","devices","ota"]},
    "dashboard_settings":{"auto_refresh_seconds":30},
    "device_view_state":{"hexa-mini-001":{"last_selected_tab":"relays"}},
    "merge": true
  }'
```
