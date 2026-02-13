# PRD: IoT Relay Control Platform

| Field | Value |
| --- | --- |
| Version | 1.2 |
| Status | Draft |
| Target Launch | MVP in 6 weeks |
| Initial Scale | 150 users, 150 devices |
| Growth Target | 1000 devices within 12 months |

## 1. Product Summary

Build a cloud relay-control platform where ESP8266 devices keep outbound secure WebSocket (WSS) connections to a central server. Users control relays from a web app, automate actions with schedules and rule-based automations, and optionally integrate with Apple HomeKit, Amazon Alexa, and Home Assistant.

### Core Principles

- ESP8266 devices never accept inbound internet traffic.
- Server is the single command router and source of truth.
- All relay changes go through one central relay service.
- Real-time state sync across web app, schedules, automations, and smart home integrations.

### 1.1 First Device SKU: Hexa Mini Switch

- Device model: `hexa-mini-switch-v1`
- Hardware I/O:
- 3 relays
- 3 local inputs (buttons/switches)
- fixed service button on `GPIO0` for factory reset and provisioning trigger
- built-in status LED on `GPIO2` for status and error signaling
- Per-input configurable behavior from UI:
- Input type: `push_button` or `rocker_switch`
- Link mode: linked to a target relay, or unlinked
- Target relay index (0-2) when linked
- Rocker behavior modes:
- `edge_toggle`: each change of rocker position toggles the linked relay
- `follow_position`: relay continuously follows rocker ON/OFF position
- Long-press input events supported (default 10 seconds), for rule triggers

## 2. High-Level Architecture

```text
Users / Smart Home Clients

Browser (WSS + REST) --\
Alexa (REST) ----------+-----> SERVER (Node.js + Fastify + WS)
HomeKit (HAP) ---------+       - SQLite
Home Assistant (MQTT) -+       - In-memory cache
API clients -----------/       - Scheduler + Automation Engine

ESP8266 devices (WSS outbound only)
- Hexa Mini Switch v1
```

### Why This Works on ESP8266

- ESP acts as TLS client (lower memory than hosting TLS server).
- Works behind NAT/firewalls without port forwarding.
- No DDNS/static IP needed on device side.
- Server handles public TLS certificates and routing.

## 3. Technology Stack

| Layer | Choice | Rationale |
| --- | --- | --- |
| Runtime | Node.js 20 | Mature async + WS ecosystem |
| Server Framework | Fastify | Performance + plugin model |
| Database | SQLite (`better-sqlite3`) | Zero-config and sufficient for MVP scale |
| Cache | In-memory `Map` + LRU | Avoid Redis complexity at MVP |
| WebSocket | `ws` | Lightweight and proven |
| Auth | JWT + bcrypt | Standard web auth pattern |
| Scheduler/Rules | `node-cron` + custom rule engine | Time + event automations |
| Web App | React + Vite + Tailwind | Fast iteration and bundle performance |
| Deployment | Docker on single VPS | Simple and low-cost |
| TLS | Caddy | Automatic HTTPS certificates |

### SQLite and Redis Decision

- SQLite is sufficient for 150 users/150 devices MVP.
- In-memory cache is enough for online state + rate limits in a single instance.
- Upgrade path: PostgreSQL + Redis when moving to multi-instance architecture.

## 4. Functional Scope

### 4.1 User and Device Management

- User registration, login, refresh/logout.
- Admin device provisioning and token rotation.
- User-to-device permissions (`view`, `control`, `admin`).
- Device hardware profile and per-input configuration management.
- Device provisioning support for first boot and recovery using WiFi Manager.

### 4.2 Relay Control

- Relay on/off/toggle commands from UI/API/schedule/automations/integrations.
- Device ACK with latency tracking.
- Offline and timeout handling with audit logging.
- Bulk operation support (`all_relays_on`, `all_relays_off`).

### 4.3 Scheduling and Automation

- One-time and recurring schedules.
- Cron + timezone support.
- IFTTT-style automations: trigger + optional condition + action.
- Supported triggers at MVP:
- `time_schedule`
- `button_hold` (example: hold input for 10s)
- `button_press`
- `device_online` / `device_offline`
- Supported actions at MVP:
- set one relay on/off/toggle
- set all relays on/off

### 4.4 Smart Home Integrations

- HomeKit via HAP bridge.
- Alexa Smart Home skill endpoint + OAuth2 flow.
- Home Assistant via MQTT discovery and state/command topics.

### 4.5 Observability

- Health endpoint.
- Metrics endpoint.
- Audit logs for every relay-affecting action.
- Device telemetry in periodic state reports.

## 5. Data Model (SQLite)

```sql
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  name TEXT NOT NULL,
  role TEXT DEFAULT 'user',
  is_active INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE devices (
  id TEXT PRIMARY KEY,
  device_uid TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  device_token_hash TEXT NOT NULL,
  model TEXT DEFAULT 'hexa-mini-switch-v1',
  relay_count INTEGER DEFAULT 3,
  button_count INTEGER DEFAULT 3,
  relay_names TEXT DEFAULT '["Relay 1","Relay 2","Relay 3"]',
  input_config TEXT DEFAULT '[]',
  power_restore_mode TEXT DEFAULT 'last_state',
  firmware_version TEXT,
  last_seen_at TEXT,
  last_ip TEXT,
  is_active INTEGER DEFAULT 1,
  config TEXT DEFAULT '{}',
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE user_devices (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  permission TEXT DEFAULT 'control',
  created_at TEXT DEFAULT (datetime('now')),
  UNIQUE (user_id, device_id)
);

CREATE TABLE relay_states (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  relay_index INTEGER NOT NULL,
  relay_name TEXT,
  is_on INTEGER DEFAULT 0,
  last_changed_at TEXT DEFAULT (datetime('now')),
  changed_by TEXT,
  UNIQUE (device_id, relay_index)
);

CREATE TABLE schedules (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  relay_index INTEGER,
  target_scope TEXT DEFAULT 'single',
  name TEXT,
  schedule_type TEXT NOT NULL,
  cron_expression TEXT,
  execute_at TEXT,
  timezone TEXT DEFAULT 'UTC',
  action TEXT NOT NULL,
  is_enabled INTEGER DEFAULT 1,
  last_executed TEXT,
  next_execution TEXT,
  execution_count INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE automation_rules (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id TEXT REFERENCES devices(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  trigger_type TEXT NOT NULL,
  trigger_config TEXT NOT NULL DEFAULT '{}',
  condition_config TEXT NOT NULL DEFAULT '{}',
  action_type TEXT NOT NULL,
  action_config TEXT NOT NULL DEFAULT '{}',
  cooldown_seconds INTEGER DEFAULT 0,
  is_enabled INTEGER DEFAULT 1,
  last_triggered_at TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE audit_log (
  id TEXT PRIMARY KEY,
  device_id TEXT REFERENCES devices(id) ON DELETE SET NULL,
  user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  schedule_id TEXT REFERENCES schedules(id) ON DELETE SET NULL,
  automation_id TEXT REFERENCES automation_rules(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  details TEXT DEFAULT '{}',
  source TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX idx_user_devices_user ON user_devices(user_id);
CREATE INDEX idx_user_devices_device ON user_devices(device_id);
CREATE INDEX idx_relay_states_device ON relay_states(device_id);
CREATE INDEX idx_schedules_next ON schedules(next_execution) WHERE is_enabled = 1;
CREATE INDEX idx_schedules_device ON schedules(device_id);
CREATE INDEX idx_automation_device ON automation_rules(device_id);
CREATE INDEX idx_automation_enabled ON automation_rules(is_enabled);
CREATE INDEX idx_audit_device ON audit_log(device_id, created_at);
CREATE INDEX idx_audit_created ON audit_log(created_at);
```

### Input Config JSON Shape (`devices.input_config`)

```json
[
  {
    "input_index": 0,
    "input_type": "push_button",
    "linked": true,
    "target_relay_index": 0,
    "rocker_mode": null,
    "invert_input": false,
    "hold_seconds": 10
  },
  {
    "input_index": 1,
    "input_type": "rocker_switch",
    "linked": true,
    "target_relay_index": 1,
    "rocker_mode": "follow_position",
    "invert_input": false,
    "hold_seconds": null
  }
]
```

## 6. In-Memory Cache

```ts
const cache = {
  // key: device_uid -> { ws, connectedAt, lastPing }
  devices: new Map(),

  // key: device_uid -> { relays, inputs, heap, rssi, uptime }
  deviceStates: new Map(),

  // key: visitorId -> { ws, userId, subscribedDevices }
  clients: new Map(),

  // key: identifier -> { count, resetAt }
  rateLimits: new Map(),

  // key: device_uid -> compiled automation rules for fast event handling
  automationRules: new Map(),
};

setInterval(() => {
  const now = Date.now();
  for (const [key, val] of cache.rateLimits) {
    if (val.resetAt < now) cache.rateLimits.delete(key);
  }
}, 300000);
```

## 7. API Specification

### Auth

- `POST /api/v1/auth/register` -> `{ user, access_token, refresh_token }`
- `POST /api/v1/auth/login` -> `{ user, access_token, refresh_token }`
- `POST /api/v1/auth/refresh` -> `{ access_token, refresh_token }`
- `POST /api/v1/auth/logout` -> `{ ok: true }`

### Devices

- `GET /api/v1/devices`
- `POST /api/v1/devices` (admin)
- `GET /api/v1/devices/:id`
- `PATCH /api/v1/devices/:id`
- `PATCH /api/v1/devices/:id/io-config`
- `PATCH /api/v1/devices/:id/power-restore-mode`
- `DELETE /api/v1/devices/:id` (admin)
- `POST /api/v1/devices/:id/token/rotate` (admin)

### Relay Control

- `POST /api/v1/devices/:id/relays/:index`
- `POST /api/v1/devices/:id/relays/all`

### Schedules

- `GET /api/v1/schedules`
- `POST /api/v1/schedules`
- `PATCH /api/v1/schedules/:id`
- `DELETE /api/v1/schedules/:id`
- `POST /api/v1/schedules/:id/enable`
- `POST /api/v1/schedules/:id/disable`

### Automations

- `GET /api/v1/automations`
- `POST /api/v1/automations`
- `PATCH /api/v1/automations/:id`
- `DELETE /api/v1/automations/:id`
- `POST /api/v1/automations/:id/enable`
- `POST /api/v1/automations/:id/disable`

### OTA Device Update

- `GET /api/v1/ota/check?device_uid=<uid>&current=<version>&channel=<channel>`
- `GET /api/v1/ota/manifest/:device_uid`
- `POST /api/v1/ota/report` (device update result, verification failure, rollback, success)

### Audit and Health

- `GET /api/v1/audit?device_id=X&limit=50&offset=0`
- `GET /health` -> status, online devices, uptime, db size
- `GET /metrics` -> Prometheus metrics

### API Contract Requirements

- All mutating endpoints support idempotency keys.
- Standard error response format (`code`, `message`, `details`, `request_id`).
- `/api/v1` versioning and deprecation policy for breaking changes.

## 8. WebSocket Protocol

### Endpoints

- Device: `wss://server.com/ws/device?uid=<device_uid>&token=<device_token>`
- Web client: `wss://server.com/ws/client` (client authenticates after connect)

### Device Messages

- `state_report`: relay states + input states + telemetry
- `set_relay` (server -> device)
- `set_all_relays` (server -> device)
- `ack` (device -> server)
- `input_event` (device -> server)
- `ota_status` (device -> server)

### Client Messages

- `auth` / `auth_ok`
- `cmd` (relay command request)
- `cmd_ack`
- `device_state`
- `device_online` / `device_offline`
- `automation_fired`

### Example `input_event`

```json
{
  "type": "input_event",
  "device_uid": "hexa-mini-001",
  "input_index": 0,
  "input_type": "push_button",
  "event": "hold",
  "duration_ms": 10050,
  "ts": "2026-02-13T10:21:11.123Z"
}
```

## 9. Scheduler and Automation Engine

### Scheduler

- Runs inside same Node.js process.
- Every 10 seconds, fetches due enabled schedules.
- Supports single-relay and all-relays actions.

### Rule Engine (IFTTT Style)

Automation flow: `IF trigger [AND condition] THEN action`.

- Rule evaluation is event-driven (`input_event`, `device_online`, etc.) and time-driven.
- Rule cooldown is enforced per rule.
- Every execution is written to `audit_log` with `automation_id`.

### Example Rule

- IF input 0 hold >= 10s on device `hexa-mini-001`
- THEN set all relays OFF

## 10. Smart Home Integrations

### 10.1 HomeKit (HAP-NodeJS)

- Each relay is a HomeKit Switch service.
- Bridge mode with one bridge and multiple services.
- State updates pushed when relay changes from any source.

### 10.2 Alexa Smart Home Skill

- Requires OAuth2 account linking.
- Endpoint: `POST /api/v1/alexa/smart-home`.
- Handles discovery, turn on/off, and report state directives.

### 10.3 Home Assistant (MQTT)

- Support MQTT discovery topics and relay state/command topics.
- Publish availability by device.
- Either embedded broker (Aedes) or external broker configuration.

### 10.4 Cross-Source State Sync

For any relay change (user, schedule, automation, homekit, alexa, ha, api, system):

1. Update in-memory cache.
2. Persist to `relay_states`.
3. Push WS updates to clients.
4. Update HomeKit characteristic.
5. Publish MQTT state.
6. Write audit log.

## 11. Firmware Requirements (ESP8266)

### Config (`LittleFS /config.json`)

```json
{
  "wifi_ssid": "MyNetwork",
  "wifi_pass": "MyPassword",
  "server_host": "relay.example.com",
  "server_port": 443,
  "device_uid": "hexa-mini-001",
  "device_token": "dt_...",
  "relay_pins": [5, 4, 14],
  "input_pins": [12, 13, 15],
  "relay_active_low": false,
  "report_interval": 30,
  "use_tls": true
}
```

### Fixed GPIO Assignments (Hexa Mini Switch v1)

| GPIO | Role | Electrical Mode | Notes |
| --- | --- | --- | --- |
| `GPIO0` | Service button | `INPUT_PULLUP`, active-low | Reserved for provisioning/reset; not user remappable |
| `GPIO2` | Built-in status LED | Output (active-low on most ESP8266 boards) | Driven by non-blocking LED state machine |

### GPIO0 Timing and Debounce Spec

| Condition | Threshold | Action |
| --- | --- | --- |
| Debounce stability window | 30 ms stable-low required | Valid press starts only after debounce passes |
| Press and hold `>= 800 ms` and `< 4 s` | Continuous hold | Enter provisioning mode (non-destructive) |
| Press and hold `>= 10 s` | Continuous hold | Factory reset (clear Wi-Fi + local config), then reboot to provisioning |
| Release gap during hold | `> 100 ms` high | Hold timer resets to zero |
| Boot safety guard | ignore GPIO0 actions until uptime `>= 3 s` | Prevent false trigger near reset/boot strap conditions |

### Wi-Fi Provisioning (WiFiManager)

- Use WiFi Manager captive portal for provisioning.
- Enter provisioning mode when:
- no valid Wi-Fi credentials exist
- Wi-Fi connection repeatedly fails on boot
- user triggers factory reset from `GPIO0`
- Provisioning AP default name format: `HexaMini-Setup-<last4_uid>`.
- After successful provisioning, device stores credentials, reboots, and reconnects to cloud.

### Behavior

- Boot: load config, init relays from restored state, connect Wi-Fi, connect WSS, send initial state.
- Main loop: process WS, process local inputs with debounce, periodic reports, reconnect handling.
- Disconnect: hold relay state, reconnect with backoff (5s/10s/20s/30s).
- Safety: watchdog, toggle rate limit, low-heap behavior, factory reset option.

### LED Status and Error Patterns (`GPIO2`)

| Priority (High -> Low) | State | Pattern | Timing |
| --- | --- | --- | --- |
| P0 | Fatal error | ON, OFF, repeat | ON 3000 ms, OFF 1000 ms |
| P1 | OTA signature/hash verify | Rapid blink | ON 100 ms, OFF 100 ms |
| P2 | OTA download | Slow pulse | ON 80 ms, OFF 420 ms |
| P3 | Provisioning portal active | Slow blink | ON 1000 ms, OFF 1000 ms |
| P4 | Wi-Fi connecting | Double blink | ON 100 ms, OFF 100 ms, ON 100 ms, OFF 1700 ms |
| P5 | Cloud connected healthy | Heartbeat pulse | ON 50 ms, OFF 4950 ms |
| P6 | Boot self-test | Fast blink | ON 200 ms, OFF 200 ms, max 10 seconds |

- Higher-priority state preempts all lower-priority states.
- LED control must be non-blocking (`millis()` scheduler), no `delay()` loops.
- LED driver must support active-low inversion at board profile level.

### Input Behavior Requirements

- Push button mode:
- short press: toggle linked relay when linked
- hold event generation for automation triggers
- Rocker switch mode:
- `edge_toggle`: state change toggles linked relay
- `follow_position`: linked relay is forced to match rocker position
- Inputs can be set to unlinked; events still reported for automations.
- All input behavior is remotely configurable from UI and synced to device.

### Power-Outage State Persistence (Low Flash Wear)

- Device must restore last relay state after power loss.
- Implement wear-aware persistence:
- write only when state actually changed
- debounce/coalesce writes (for example 1-2 second settle window)
- use rotating journal slots (wear leveling) in flash instead of single address
- include integrity marker/CRC and latest-sequence selection on boot
- target endurance: no single flash sector hot-spotted by frequent toggles

### OTA with Signature Verification (Low-Memory Security Profile)

Manifest contract fields required:

| Field | Requirement |
| --- | --- |
| `version` | Semantic version of candidate firmware |
| `security_version` | Monotonic integer for anti-rollback |
| `channel` | `dev`, `beta`, or `stable` |
| `url` | HTTPS artifact URL (allowlisted host) |
| `size_bytes` | Exact binary size |
| `sha256` | SHA-256 digest of binary |
| `signature_alg` | `ecdsa-p256-sha256` |
| `signature` | Detached signature over canonical manifest payload |
| `expires_at` | Manifest expiration timestamp |

Device OTA security and memory constraints:

- Verify manifest signature with pinned public key before download.
- Keep two public key slots in firmware (`active`, `next`) to support key rotation.
- Stream OTA in fixed chunks (target 1024-byte buffer), never buffer full image in RAM.
- Compute SHA-256 incrementally while writing to OTA partition.
- Reject update if `sha256` mismatch, expired manifest, or invalid signature.
- Enforce anti-rollback by rejecting `security_version` lower than stored minimum accepted version.
- Abort OTA if free heap drops below 18 KB during update and report failure reason.
- Pause non-essential periodic tasks during OTA to preserve heap.
- Use trial boot confirmation: mark update as pending and require `ota_boot_ok` report within 60 seconds of startup; otherwise rollback to prior image when supported by partition layout.
- Add randomized OTA check jitter (for example every 6h +/- 10%) to avoid fleet spikes.

## 12. Web App Requirements

### Stack

- React 18 + TypeScript
- Vite
- Tailwind + shadcn/ui
- Zustand
- React Router v6
- React Hook Form + Zod

### Pages

- `/login`
- `/dashboard`
- `/devices/:id`
- `/devices/:id/io-config`
- `/schedules`
- `/automations`
- `/automations/new`
- `/automations/:id/edit`
- `/audit`
- `/settings`
- `/admin/devices` (admin)
- `/admin/users` (admin)

### UX Requirements

- Real-time relay/input state updates via WS.
- Device online/offline indicators.
- Schedule creation with cron preview and timezone support.
- I/O config screen for each input:
- type selection (`push_button`, `rocker_switch`)
- linked/unlinked toggle
- relay target selection
- rocker mode selection when type is rocker
- Automation builder (`IF trigger THEN action`) with templates:
- time -> single relay on/off
- time -> all relays on/off
- hold input 10s -> all relays off
- Onboarding must show exact `GPIO0` timing spec and factory-reset behavior.
- Device help panel must show strict `GPIO2` LED code table with priorities.
- Device diagnostics must show OTA status (version, channel, signature/hash verification result, security version, last failure reason).

## 13. Security Requirements

### Authentication and Authorization

- Passwords: bcrypt (cost 12).
- Access token: JWT HS256, 15 minutes.
- Refresh token: opaque random, 30 days, hashed at rest, rotation on refresh.
- Device token: 256-bit random, SHA-256 hash at rest.
- RBAC: `admin`, `user`, `control`, `view`.

### Transport and Validation

- TLS for browser/server and ESP/server.
- Rate limits for login, API, WS commands, and device reports.
- Zod validation for API payloads.
- Parameterized SQL.
- WS payload size limit and safe JSON parsing.

### Security Operations

- Secrets managed via secret manager in production (not plain `.env` files).
- Token/key rotation policy for JWT and integration secrets.
- Security event logging and alerting (failed logins, token misuse, brute-force patterns).

### Device and OTA Security (Low Memory Focus)

- Private signing keys never ship on device; device stores verification public keys only.
- OTA must fail closed on any signature/hash/expiry/anti-rollback violation.
- OTA transport requires TLS and OTA host allowlist.
- Device tokens are excluded from logs and crash dumps.
- Security-sensitive failures emit structured telemetry (`reason_code`, `firmware_version`, `heap_kb`).

## 14. Deployment

### MVP Infra

- Single VPS (2 vCPU, 4 GB RAM, 40 GB SSD).
- Caddy for HTTPS and reverse proxy.
- Docker Compose with `app`, `caddy`, `backup` services.
- Daily SQLite backup retention (7 days).

### Production Hardening Path

- Staging environment mirrors production.
- Blue/green or rolling deploy strategy with rollback support.
- Restore drills and failover playbook.

### Key Files

- `docker-compose.yml`
- `Caddyfile`
- `deploy.sh`
- `.env.example`

## 15. Project Structure (Target)

```text
relay-platform/
├── server/
├── webapp/
├── firmware/
├── docker-compose.yml
├── Caddyfile
├── deploy.sh
└── docs/
```

## 16. Central Relay Service Rule

All relay state changes must go through one server function (`relayService.setRelay`) that handles validation, WS command dispatch, ACK waiting, persistence, audit logging, and fan-out updates.

## 17. Scaling Path

- Phase 1 (now): single VPS + SQLite + in-memory cache.
- Phase 2 (~500 devices): PostgreSQL migration, optional Redis.
- Phase 3 (1000+): multi-WS instances, load balancer, Redis pub/sub, dedicated scheduler worker.

## 18. Environment Variables

```bash
NODE_ENV=production
PORT=3000
DB_PATH=/app/data/relay.db
JWT_SECRET=change-me-64-chars-random
JWT_REFRESH_SECRET=change-me-another-64-chars
BCRYPT_ROUNDS=12
HOMEKIT_PIN=031-45-154
HOMEKIT_PORT=51826
MQTT_ENABLED=true
MQTT_PORT=1883
ALEXA_ENABLED=true
ALEXA_CLIENT_ID=...
ALEXA_CLIENT_SECRET=...
DOMAIN=relay.yourdomain.com
```

## 19. Milestones (6 Weeks)

- Week 1-2: foundation (DB, auth, devices, cache).
- Week 3-4: real-time core (WS + relay control + firmware + Hexa Mini input handling + GPIO0/GPIO2 behavior + WiFi Manager).
- Week 5: web app + schedules + automation builder + audit.
- Week 6: smart home integrations + deployment + launch.

## 20. Risks and Mitigations

| Risk | Mitigation |
| --- | --- |
| ESP8266 memory pressure | Strict memory budget, load tests, ESP32 fallback |
| SQLite write contention | WAL mode, move to PostgreSQL when needed |
| Single-server outage | Docker restart + daily backups + restore runbook |
| Smart-home state drift | Enforce central `setRelay` path for all sources |
| HomeKit pairing issues | Persist HAP state in data volume |
| Alexa certification delays | Start private skill first, public launch later |
| Flash wear from state persistence | Wear-leveled state journal + write coalescing |

## 21. Success Metrics

| Metric | Target |
| --- | --- |
| Devices online | >95% of registered |
| Command latency | <500 ms |
| Schedule/automation execution accuracy | >99% |
| Server uptime | >99.5% |
| Smart home response time | <2 s |
| ESP free heap in production | >20 KB |
| Power restore state correctness | >99.9% in outage tests |
| Provisioning success rate (factory reset path) | >99% |
| OTA success rate (stable channel) | >98% |
| OTA invalid signature acceptance | 0% (must always reject) |

## 22. Production Readiness Addendum

### 22.1 SLOs, Monitoring, and Alerting

- Define SLIs/SLOs for API availability, WS command success rate, automation success, and latency.
- Expose metrics (`/metrics`) and dashboards for:
- command latency p50/p95/p99
- device online count and churn
- scheduler lag and rule queue depth
- error rates by endpoint and integration
- Alerting rules:
- API 5xx above threshold
- command timeout rate above threshold
- scheduler lag exceeds threshold
- backup failures

### 22.2 Disaster Recovery and Backups

- Define RPO and RTO targets.
- Keep encrypted backups and verify retention.
- Run restore drill at least monthly.
- Document recovery runbook and ownership.

### 22.3 OTA Firmware Update Strategy

- Signed firmware artifacts required (`ecdsa-p256-sha256`).
- Detached manifest signature with expiration and anti-rollback `security_version`.
- Versioned release channels: `dev`, `beta`, `stable`.
- Staged rollout with canary percentages and rollout pause controls.
- Key rotation policy with `active` and `next` verification keys.
- Automatic rollback trigger on failed trial boot or health regression.
- Low-memory requirement: OTA pipeline must not require full-image buffering in RAM.

### 22.4 Secrets and Key Management

- Use managed secret store for production credentials.
- Rotate JWT and integration secrets regularly.
- Track key versions and support graceful rotation windows.

### 22.5 CI/CD and Change Management

- Required pipeline stages: lint, unit, integration, e2e smoke.
- Migration safety checks before deploy.
- Rollback command documented and tested.
- Staging sign-off required before production release.

### 22.6 Data Governance

- Define retention windows for audit logs and telemetry.
- Define data deletion flow (user/device deprovisioning).
- Minimize PII collection and document access policy.

### 22.7 API/Protocol Lifecycle

- Versioning policy for REST and WS contracts.
- Deprecation window and backward compatibility guarantees.
- Changelog required for external contract changes.

## 23. Acceptance Criteria for Production Gate

- All section 22 controls are implemented and validated.
- Restore drill executed successfully within defined RTO.
- OTA signed update and rollback tested on Hexa Mini Switch.
- OTA anti-rollback and invalid-signature rejection tests pass.
- OTA update path maintains free heap above 18 KB during verification/download.
- Automation engine passes failure-injection tests.
- Security review completed with no open critical findings.
