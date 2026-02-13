# Firmware Task & Progress

- Last Updated: 2026-02-13
- Scope: ESP8266 firmware for Hexa Mini Switch v1 (3 relays + 3 inputs) with GPIO0 provisioning/reset, GPIO2 status LED, and low-memory signed OTA
- Overall Progress: 38%

## Milestone Status

| Milestone | Status | Target Window | Progress |
| --- | --- | --- | --- |
| M1 Board Bring-Up + Provisioning Path | In Progress | Week 1-2 | 75% |
| M2 Cloud Connectivity + Realtime Control | In Progress | Week 3 | 65% |
| M3 Input Modes + Automation Events | Not Started | Week 3-4 | 0% |
| M4 State Persistence + Safety | In Progress | Week 4-5 | 20% |
| M5 Reliability + OTA Gate | Not Started | Week 5-6 | 0% |

## Testable Milestones

### M1 Board Bring-Up + Provisioning Path

Implementation:
- [x] Initialize PlatformIO/Arduino project structure
- [x] Define modules (`wifi_manager`, `ws_client`, `relay_manager`, `input_manager`, `status_led`, config loader)
- [x] Implement Hexa Mini profile (3 relay outputs, 3 local inputs)
- [x] Reserve `GPIO0` as service button and `GPIO2` as status LED
- [x] Integrate WiFi Manager captive portal flow
- [x] Enter provisioning mode when no Wi-Fi credentials or when reset requested
- [x] Implement `GPIO0` debounce logic (30 ms stable-low requirement)
- [x] Implement provisioning trigger on `GPIO0` hold `>= 800 ms` and `< 4 s`
- [x] Implement factory reset trigger on `GPIO0` hold `>= 10 s` continuous
- [x] Reset hold timer when `GPIO0` release gap exceeds 100 ms
- [x] Add boot safety guard (ignore `GPIO0` actions until uptime >= 3 s)
- [x] On factory reset, clear Wi-Fi/config and reboot into provisioning mode

Validation Gate:
- [ ] Fresh device with empty config enters WiFi Manager AP mode
- [ ] Button bounce test confirms no false action under 30 ms noise
- [ ] Holding `GPIO0` between 800 ms and 4 s enters provisioning without deleting config
- [ ] Holding `GPIO0` for 10 seconds clears credentials/config and re-enters AP mode
- [ ] Device exits provisioning and reconnects after valid credentials are saved

### M2 Cloud Connectivity + Realtime Control

Implementation:
- [x] Connect WSS to `/ws/device` with `uid` + token
- [x] Send initial `state_report` on connect
- [x] Send periodic `state_report` at configured interval
- [x] Handle incoming `set_relay` and `set_all_relays`
- [x] Emit `ack` with command id/result
- [ ] Process server config updates (`io-config`, restore mode)

Validation Gate:
- [ ] Integration test: relay command from server is applied and acked
- [ ] Integration test: all-relays command affects relays 0-2 correctly
- [ ] Telemetry fields (`heap`, `rssi`, `uptime`, `firmware`) appear in reports

### M3 Input Modes + Automation Events

Implementation:
- [ ] Implement debounce/edge detection for 3 inputs
- [ ] Implement input modes: `push_button`, `rocker_switch`
- [ ] Implement linked/unlinked behavior per input
- [ ] Implement rocker modes: `edge_toggle`, `follow_position`
- [ ] Implement hold detection with default 10s threshold (configurable)
- [ ] Emit `input_event` (`press`, `release`, `hold`) with duration metadata

Validation Gate:
- [ ] Functional test matrix passes for all input mode combinations
- [ ] `follow_position` keeps relay state aligned with rocker physical position
- [ ] Hold event fires once when hold duration crosses configured threshold

### M4 State Persistence + Safety

Implementation:
- [ ] Restore last relay state after power outage
- [ ] Implement wear-aware persistence with coalesced writes
- [ ] Implement rotating journal slots for wear leveling
- [ ] Implement checksum/sequence validation on restore
- [ ] Enforce max relay toggle rate (1/sec per relay)
- [ ] Keep relay state stable through reconnect cycles
- [ ] Add watchdog integration and low-heap protections
- [x] Implement `GPIO2` LED state machine with strict priority table
- [x] Enforce non-blocking LED scheduler (`millis()`-driven, no delay loops)
- [x] Support active-low LED inversion in board profile

Validation Gate:
- [ ] Power-cycle test confirms restored relay state correctness
- [ ] Flash-write stress test confirms no hot-spot write behavior
- [ ] LED pattern tests confirm exact timing codes and priority preemption rules

### M5 Reliability + OTA Gate

Implementation:
- [ ] Implement reconnect backoff (5s, 10s, 20s, 30s max)
- [ ] Add JSON parsing guards and message size limits
- [ ] Add robust logs for boot/reconnect/command failures
- [ ] Implement signed OTA manifest flow (`ecdsa-p256-sha256`) with pinned verification key
- [ ] Support dual verification key slots (`active`, `next`) for key rotation
- [ ] Validate manifest expiration and signature before download
- [ ] Stream OTA download using fixed 1024-byte buffer (no full-image RAM buffering)
- [ ] Compute SHA-256 incrementally during OTA write and verify against manifest
- [ ] Enforce anti-rollback by rejecting lower `security_version`
- [ ] Abort OTA and report error when free heap < 18 KB
- [ ] Pause non-critical periodic tasks while OTA is running
- [ ] Add rollback protection on failed boot after OTA
- [ ] Report OTA status events to server

Validation Gate:
- [ ] Long-run soak test passes with repeated network interruptions
- [ ] Invalid-signed OTA is rejected safely
- [ ] Hash mismatch and expired manifest are rejected safely
- [ ] OTA rollback protection rejects lower `security_version`
- [ ] Heap watermark test confirms >= 18 KB free during OTA verify/download path
- [ ] Rollback path restores last known good firmware after failed OTA

## Blockers

- None

## Notes

- Firmware must never accept inbound internet connections.
- Milestones close only when Validation Gate items are complete.
- `pio run` passes for `nodemcuv2` profile after scaffold and WS protocol implementation.
