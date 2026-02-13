# Server Task & Progress

- Last Updated: 2026-02-13
- Scope: Backend API, WS gateway, schedule/rule execution, device configuration, production operations
- Overall Progress: 100%

## Milestone Status

| Milestone | Status | Target Window | Progress |
| --- | --- | --- | --- |
| M1 Foundation + Auth + Device Model | Completed | Week 1-2 | 100% |
| M2 Real-Time Command Path | Completed | Week 3 | 100% |
| M3 Scheduling + IFTTT Automation | Completed | Week 4-5 | 100% |
| M4 Device Config APIs + Sync | Completed | Week 5 | 100% |
| M5 Production Readiness Gate | Completed | Week 6+ | 100% |

## Testable Milestones

### M1 Foundation + Auth + Device Model

Implementation:
- [x] Initialize Fastify + TypeScript project structure
- [x] Implement PostgreSQL setup and migrations
- [x] Create schema: users, devices, user_devices, relay_states, schedules, automation_rules, audit_log
- [x] Add `hexa-mini-switch-v1` defaults (3 relays, 3 inputs)
- [x] Build auth routes (register/login/refresh/logout)
- [x] Implement refresh-token rotation + revocation
- [x] Implement device CRUD with RBAC

Validation Gate:
- [x] Migration up/down runs cleanly in CI
- [x] Unit tests pass for auth and RBAC device CRUD
- [x] API test confirms new device defaults to 3 relays and 3 inputs

### M2 Real-Time Command Path

Implementation:
- [x] Implement WS endpoint for devices (token auth)
- [x] Implement WS endpoint for web clients (JWT auth)
- [x] Implement message routing (`state_report`, `set_relay`, `set_all_relays`, `ack`, `input_event`)
- [x] Implement central `setRelay` and `setAllRelays` service path
- [x] Add timeout/ack correlation and latency tracking
- [x] Add online/offline heartbeat detection

Validation Gate:
- [x] Integration test: client command -> device ack -> DB state updated
- [x] Integration test: all-relays command toggles all 3 relays deterministically
- [x] Latency metric is emitted for successful and timeout flows

### M3 Scheduling + IFTTT Automation

Implementation:
- [x] Implement schedule CRUD (single relay + all relays)
- [x] Implement cron validation and next-execution calculator
- [x] Build scheduler tick loop (10 second scan)
- [x] Implement automation CRUD (`trigger`, `condition`, `action`)
- [x] Build event-driven automation executor (`input_event`, `device_online`, `device_offline`)
- [x] Implement cooldown and dedupe protections
- [x] Add default template rule: hold button 10s -> all relays OFF
- [x] Persist schedule/automation executions to `audit_log`

Validation Gate:
- [x] Integration test: scheduled all-relays ON/OFF executes at expected time window
- [x] Integration test: input hold event >=10s triggers all-relays OFF once
- [x] Audit records include `source` and `automation_id` where applicable

### M4 Device Config APIs + Sync

Implementation:
- [x] Implement `PATCH /api/v1/devices/:id/io-config`
- [x] Implement `PATCH /api/v1/devices/:id/power-restore-mode`
- [x] Validate mode matrix (push/rocker, linked/unlinked, rocker mode)
- [x] Push configuration updates to online device sessions
- [x] Store and expose provisioning/status fields needed by UI onboarding
- [x] Implement OTA device endpoints: `GET /api/v1/ota/check`, `GET /api/v1/ota/manifest/:device_uid`, `POST /api/v1/ota/report`

Validation Gate:
- [x] API contract tests reject invalid config combinations
- [x] Integration test confirms config update is received by connected firmware
- [x] Integration test verifies persisted config is returned on `GET /devices/:id`
- [x] Integration test verifies OTA check/manifest/report contract for a registered device

### M5 Production Readiness Gate

Implementation:
- [x] Implement `/metrics` and instrument command/scheduler/error SLIs
- [x] Add dashboards and alert rules
- [x] Define and document RPO/RTO
- [x] Implement encrypted backup retention and restore drill script
- [x] Implement idempotency-key support on mutating APIs
- [x] Define standardized API error format with request-id propagation
- [x] Add REST/WS versioning and deprecation policy docs
- [x] Integrate production secret manager and key rotation plan
- [x] Add CI/CD gates (lint, unit, integration, e2e smoke)
- [x] Add rollback runbook and staging sign-off gate
- [x] Build OTA manifest signer flow (`ecdsa-p256-sha256`) with expiration and channel support
- [x] Add anti-rollback policy (`security_version`) in OTA manifest generation and checks
- [x] Add OTA host allowlist and signed artifact metadata registry
- [x] Implement key rotation support (`active` and `next` verification key ids)

Validation Gate:
- [x] Restore drill completes within target RTO
- [x] Alert simulation triggers expected notifications
- [x] CI pipeline blocks release when quality gates fail
- [x] Security checklist has no open critical items
- [x] OTA tamper tests fail closed (invalid signature, hash mismatch, expired manifest)
- [x] OTA rollback test rejects lower `security_version` manifests

## Blockers

- None

## Notes

- All relay changes must pass through the central relay service path.
- Every milestone is complete only when all Validation Gate items are checked.
- Manual smoke checks passed for HTTP relay commands and WS `auth/cmd/cmd_ack` against a connected device session.
- Added migration `003_ota_support.sql` and verified `npm run migrate` completes.
- Added route groups `/api/v1/schedules`, `/api/v1/automations`, `/api/v1/ota` and scheduler worker lifecycle hooks.
- Added migration `004_idempotency_keys.sql` and global idempotency-key replay support on mutating APIs.
- Added integration suite `tests/integration/server.integration.test.ts` and verified `npm run test:integration` passes.
- Added dev seeding flow `npm run seed:dev` for admin + sample device + OTA release setup.
- Added smart-home integrations: HomeKit bridge runtime (HAP-NodeJS), Alexa directive endpoint (`/api/v1/alexa/smart-home`), and Home Assistant MQTT discovery/state/command bridge.
- Added cross-source sync fan-out: in-memory relay cache, DB persistence, WS updates, HomeKit characteristic updates, MQTT state/availability publishing, and audit writes for device-reported relay changes.
- Added admin operations API surface (`/api/v1/admin/*`) for overview, user/device ops, audit filtering, alert simulation, and backup/restore execution tracking.
- Added encrypted backup service with retention and restore drill runtime enforcement (`ops_backup_runs`) plus CLI scripts (`npm run backup:run`, `npm run restore:drill`).
- Added OTA manifest signing and verification key lifecycle (`active/next/retired`) with fail-closed release integrity checks and anti-rollback enforcement.
- Added CI/CD release gates (`server-ci`, `release-gate`) and staging sign-off validator (`npm run validate:signoff`).
- Added production transport-security gate (`npm run test:security`) validating HTTP rejection and proxy-aware HTTPS acceptance.
- Added M5 operations docs in `docs/` for versioning/deprecation, monitoring/alerts, disaster recovery, rollback, secret/key rotation, security checklist, and staging sign-off policy.
- Added comprehensive documentation index and live contract docs for architecture, REST APIs, webhook-style callbacks, and WebSocket protocol usage (`docs/README.md`, `docs/how-it-works.md`, `docs/api/rest-and-webhook-reference.md`, `docs/api/websocket-reference.md`).
- Added migration `006_future_device_extensibility.sql` with production-ready schema for device classes/capabilities, IR code library storage, sensor state/events, and per-user dashboard/preferences persistence.
- Added extensibility API surface under `/api/v1/devices/*` for capabilities, IR code CRUD, sensor-state and sensor-event ingestion/query, plus authenticated user preferences APIs at `/api/v1/preferences`.
- Expanded test coverage to close remaining validation gates (auth + RBAC device CRUD, default provisioning shape, WS client command/ACK persistence, all-relays determinism, invalid config rejection, and command latency/timeout metrics emission).
- Added domain-specific operations docs for `vistfiy.store` and Cloudflare split-plane deployment (`api.vistfiy.store` direct TLS, `admin.vistfiy.store` tunnel), plus a production firmware profile targeting `api.vistfiy.store:443` with TLS enabled.
- Added API-surface integration suite (`tests/integration/api-surface.integration.test.ts`) to cover previously untested admin/audit/schedule+automation lifecycle/device-feature/webhook routes and wired it into `npm run test:integration`.
- Hardened Home Assistant MQTT bridge for remote customer-hosted brokers with TLS controls (`HA_MQTT_REJECT_UNAUTHORIZED`, CA/cert/key files, SNI, keepalive/connect-timeout tuning) and deployment docs updates for outbound `mqtts` architecture.
