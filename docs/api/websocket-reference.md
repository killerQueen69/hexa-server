# WebSocket Protocol Reference

This is the implemented WS contract in `server/src/modules/realtime/gateway.ts`.

## 1. Endpoints

## Device Channel

- URL: `/ws/device?uid=<device_uid>&token=<device_token>`
- Auth: URL query credentials (token compared to hashed device token in DB)
- Purpose: device state reports, ACKs, input events, OTA status

## Client Channel

- URL: `/ws/client`
- Auth: client must send `auth` message with access token after connect
- Purpose: realtime updates and command dispatch from browser/app

## 2. Connection and Session Rules

- Max payload: `16 KB` per message.
- Invalid/oversized JSON is ignored.
- Device heartbeat ping interval: `2.5s`.
- Miss limit before terminating device socket: `1` missed pong cycle.
- Offline broadcast is delayed by a `5s` grace window to avoid transient disconnect flapping.
- Any inbound device frame resets heartbeat miss tracking (not only explicit pong frames).
- Device session is single-active per `device_uid` (new session replaces old one).

## 3. Device Channel Messages

## 3.1 Device -> Server

### `state_report`

Example:

```json
{
  "type": "state_report",
  "relays": [true, false, true],
  "telemetry": {
    "heap": 32000,
    "rssi": -58,
    "uptime": 12345
  },
  "ts": "2026-02-13T12:00:00.000Z"
}
```

Behavior:

- updates `last_seen_at` and relay states
- writes audit when relay values changed
- pushes `device_state` to owner clients
- syncs smart-home bridges

### `ack`

Example:

```json
{
  "type": "ack",
  "command_id": "uuid",
  "ok": true,
  "error": null,
  "ts": "2026-02-13T12:00:00.100Z"
}
```

Behavior:

- resolves pending command waiter in relay service path

### `input_event`

Example:

```json
{
  "type": "input_event",
  "input_index": 0,
  "input_type": "push_button",
  "event": "hold",
  "duration_ms": 10050,
  "ts": "2026-02-13T12:00:01.000Z"
}
```

Behavior:

- automation engine evaluates matching rules
- forwarded to owner clients

### `ota_status`

Example:

```json
{
  "type": "ota_status",
  "command_id": "uuid",
  "status": "ok",
  "event_type": "verify",
  "reason": null,
  "from_version": "0.2.0",
  "to_version": "0.2.1",
  "security_version": 1,
  "details": {
    "channel": "stable"
  },
  "ts": "2026-02-13T12:00:02.000Z"
}
```

Behavior:

- forwarded to owner clients

## 3.2 Server -> Device

### `set_relay`

```json
{
  "type": "set_relay",
  "command_id": "uuid",
  "relay_index": 1,
  "action": "toggle",
  "ts": "2026-02-13T12:01:00.000Z"
}
```

### `set_all_relays`

```json
{
  "type": "set_all_relays",
  "command_id": "uuid",
  "action": "off",
  "ts": "2026-02-13T12:01:00.000Z"
}
```

### `config_update`

Sent when input config, power restore mode, or connectivity settings are changed via API.

```json
{
  "type": "config_update",
  "io_config": [],
  "power_restore_mode": "last_state",
  "connectivity": {
    "mode": "local_mqtt",
    "mqtt": {
      "enabled": true,
      "host": "192.168.0.100",
      "port": 1883,
      "username": "user",
      "password": "pass",
      "discovery_prefix": "homeassistant",
      "base_topic": "d"
    },
    "wifi": {
      "op": "set",
      "ssid": "MyWiFi",
      "password": "MyPass1234",
      "reboot": true
    }
  },
  "ts": "2026-02-13T12:02:00.000Z"
}
```

If `connectivity.mode` changes transport mode (`cloud_ws` <-> `local_mqtt`), firmware is expected to apply config and reboot to switch stacks cleanly.
If `connectivity.wifi.op` is `set` or `clear`, firmware applies the Wi-Fi credential update and can reboot when `reboot` is true.

### `ota_control`

```json
{
  "type": "ota_control",
  "command_id": "uuid",
  "operation": "install",
  "channel": "stable",
  "transfer_id": "uuid",
  "manifest": {
    "version": "0.2.1",
    "security_version": 1,
    "channel": "stable",
    "url": "https://api.vistfiy.store/api/v1/ota/artifacts/hexa/stable/0.2.1/fw.bin",
    "size_bytes": 587432,
    "sha256": "0123...abcd",
    "signature_alg": "ecdsa-p256-sha256",
    "expires_at": "2026-03-31T23:59:59.000Z",
    "signature": "base64url-signature",
    "verification_key_id": "ota-key-2026-01",
    "next_verification_key_id": "ota-key-2026-04"
  },
  "ts": "2026-02-13T12:03:00.000Z"
}
```

Notes:

- OTA is WS-manifest driven. Device does not fetch OTA manifest over HTTP.
- `operation=check` also carries manifest when update is available.
- `transfer_id` is required for `operation=install`.

### `ota_chunk`

```json
{
  "type": "ota_chunk",
  "command_id": "uuid",
  "transfer_id": "uuid",
  "chunk_index": 0,
  "offset": 0,
  "data_b64": "base64url-firmware-bytes",
  "is_last": false,
  "ts": "2026-02-13T12:03:01.000Z"
}
```

Notes:

- Chunks are sent sequentially over WS text frames.
- Device ACKs each chunk via normal `ack` using `command_id`.
- `is_last=true` marks final chunk; device verifies full SHA-256 and finalizes OTA.

### `ota_abort`

```json
{
  "type": "ota_abort",
  "command_id": "uuid",
  "transfer_id": "uuid",
  "reason": "ws_transfer_failed",
  "ts": "2026-02-13T12:03:10.000Z"
}
```

## 4. Client Channel Messages

## 4.1 Client -> Server

### `auth`

```json
{
  "type": "auth",
  "access_token": "jwt"
}
```

Server responds with:

- `auth_ok` on success
- `auth_error` on failure

### `cmd`

Single relay command:

```json
{
  "type": "cmd",
  "request_id": "req-001",
  "device_id": "device-uuid",
  "scope": "single",
  "relay_index": 0,
  "action": "on"
}
```

All-relays command:

```json
{
  "type": "cmd",
  "request_id": "req-002",
  "device_id": "device-uuid",
  "scope": "all",
  "action": "off"
}
```

Wi-Fi provisioning command (`set`):

```json
{
  "type": "cmd",
  "request_id": "req-003",
  "device_id": "device-uuid",
  "scope": "wifi",
  "wifi": {
    "op": "set",
    "ssid": "MyWiFi",
    "password": "MyPass1234",
    "reboot": true
  }
}
```

Wi-Fi credential removal command (`clear`):

```json
{
  "type": "cmd",
  "request_id": "req-004",
  "device_id": "device-uuid",
  "scope": "wifi",
  "wifi": {
    "op": "clear",
    "reboot": true
  }
}
```

Device reboot command:

```json
{
  "type": "cmd",
  "request_id": "req-005",
  "device_id": "device-uuid",
  "scope": "device",
  "operation": "reboot"
}
```

Device factory reset command:

```json
{
  "type": "cmd",
  "request_id": "req-006",
  "device_id": "device-uuid",
  "scope": "device",
  "operation": "factory_reset"
}
```

OTA check/install command:

```json
{
  "type": "cmd",
  "request_id": "req-007",
  "device_id": "device-uuid",
  "scope": "ota",
  "operation": "check",
  "channel": "stable"
}
```

Server returns `cmd_ack` with either:

- `ok: true` and command result
- or `ok: false` with `code`/`message`
- Command authorization: device owner can send commands; admin sessions are also allowed.
- OTA command validation:
  - `operation` must be `check` or `install`
  - optional `channel` must be `dev|beta|stable`

## 4.2 Server -> Client

### Session/auth events

- `auth_ok`
- `auth_error`

### Device presence events

- `device_online`
- `device_offline`

### State and command events

- `device_state`
- `cmd_ack`
- `automation_fired`
- `ota_status`
- forwarded device `input_event` payloads

Example `cmd_ack` success:

```json
{
  "type": "cmd_ack",
  "ok": true,
  "request_id": "req-001",
  "result": {
    "device_id": "device-uuid",
    "device_uid": "hexa-mini-001",
    "relay_index": 0,
    "action": "on",
    "is_on": true,
    "latency_ms": 120
  }
}
```

Example `cmd_ack` failure:

```json
{
  "type": "cmd_ack",
  "ok": false,
  "code": "device_offline",
  "message": "Device is offline.",
  "request_id": "req-001"
}
```

## 5. WS Usage Notes

- Always authenticate immediately on `/ws/client` connect.
- Include stable `request_id` in `cmd` for client correlation.
- Device firmware should always ACK command IDs exactly once.
- Device should send periodic `state_report` to keep presence fresh.
- On transport mode change pushed via `config_update`, firmware should persist settings and reboot.
- Handle reconnects and replay initial state via REST on reconnect.
