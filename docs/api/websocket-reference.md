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
- Device heartbeat ping interval: `20s`.
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
  "status": "ok",
  "event_type": "verify",
  "reason": null,
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

Sent when input config or power restore mode is changed via API.

```json
{
  "type": "config_update",
  "io_config": [],
  "power_restore_mode": "last_state",
  "ts": "2026-02-13T12:02:00.000Z"
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

Server returns `cmd_ack` with either:

- `ok: true` and command result
- or `ok: false` with `code`/`message`

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
- Handle reconnects and replay initial state via REST on reconnect.
