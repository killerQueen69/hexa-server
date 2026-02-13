# Web App Task & Progress

- Last Updated: 2026-02-13
- Scope: React app for auth, realtime control, Hexa Mini I/O config, automation builder, and device onboarding
- Overall Progress: 35%

## Milestone Status

| Milestone | Status | Target Window | Progress |
| --- | --- | --- | --- |
| M1 App Foundation + Auth | In Progress | Week 1-2 | 30% |
| M2 Realtime Dashboard + Device Control | In Progress | Week 3 | 45% |
| M3 I/O Config + Schedules + Automations | Not Started | Week 4-5 | 0% |
| M4 Device Onboarding + Diagnostics UX | Not Started | Week 5 | 0% |
| M5 QA + Release Gate | In Progress | Week 6 | 35% |

## Testable Milestones

### M1 App Foundation + Auth

Implementation:
- [ ] Initialize React 18 + TypeScript + Vite
- [ ] Configure Tailwind + component system
- [ ] Set up routing and auth-protected routes
- [ ] Build API client with token refresh handling
- [ ] Add global state with Zustand
- [ ] Add responsive base layout/navigation

Validation Gate:
- [ ] Auth flow e2e test: login, token refresh, logout
- [ ] Protected route test: unauthorized users redirected correctly

### M2 Realtime Dashboard + Device Control

Implementation:
- [ ] Build dashboard with device cards and relay toggles
- [ ] Add all-relays controls (all ON / all OFF)
- [ ] Build device detail page with relay/input/telemetry panels
- [ ] Implement WS client hook with reconnect
- [ ] Merge REST bootstrap state with WS events
- [ ] Show online/offline and command latency feedback

Validation Gate:
- [ ] e2e test: toggle single relay and observe live state update
- [ ] e2e test: all-relays control updates all 3 relays
- [ ] Reconnect test: UI rehydrates state after WS reconnect

### M3 I/O Config + Schedules + Automations

Implementation:
- [ ] Build `/devices/:id/io-config` page
- [ ] Add selectors for input type, linked/unlinked, relay target, rocker mode
- [ ] Add hold threshold input (default 10 seconds)
- [ ] Build schedule list/create/edit with single/all relay target support
- [ ] Build automation list/create/edit pages (`IF trigger THEN action`)
- [ ] Add templates (time -> relay, time -> all relays, hold 10s -> all relays OFF)
- [ ] Show automation execution items in activity feed

Validation Gate:
- [ ] Form tests reject invalid I/O config combinations
- [ ] e2e test: configure `follow_position` and confirm saved payload
- [ ] e2e test: create hold-10s automation template and verify displayed rule summary

### M4 Device Onboarding + Diagnostics UX

Implementation:
- [ ] Add onboarding flow for first-time device setup
- [ ] Add UI guidance for WiFi Manager provisioning steps
- [ ] Add service-button timing spec in UI (`GPIO0`: 800 ms-4 s provisioning, 10 s factory reset, debounce behavior)
- [ ] Add strict `GPIO2` LED code table in UI with pattern timings and priority order
- [ ] Add device diagnostics panel for provisioning and connection state
- [ ] Add OTA diagnostics panel (version, channel, last check, last result, signature/hash verification status, security version)

Validation Gate:
- [ ] UX acceptance test: new user can follow onboarding without external docs
- [ ] QA checklist confirms GPIO0 timing spec and GPIO2 code table are visible in device pages
- [ ] OTA diagnostics panel renders device-reported verification/rollback outcomes

### M5 QA + Release Gate

Implementation:
- [ ] Add form validation with React Hook Form + Zod
- [ ] Add error boundaries and loading/empty/error states
- [ ] Add accessibility checks for core flows
- [ ] Add API error contract handling (`code`, `message`, `request_id`)
- [ ] Build production bundle and smoke test against server
- [ ] Add high-value e2e suite (control, schedule, automation, io-config, onboarding)

Validation Gate:
- [ ] Lighthouse/accessibility baseline meets project threshold
- [ ] e2e smoke suite passes on release candidate build

## Blockers

- None

## Notes

- Milestones close only when Validation Gate items are complete.
- UI should remain consistent with backend contract for device config and automation schema.
- Added `webapp/app/dashboard.html` as an admin-first operations dashboard backed by live server APIs.
- Dashboard includes auth flow, fleet overview, user/device admin actions, relay controls, OTA signing key + release management, backup/restore drill operations, alert simulation, metrics, and audit log browsing.
