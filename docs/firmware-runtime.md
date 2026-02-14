# Firmware Runtime Notes

This document describes the current firmware behavior for the ESP8266 relay device.

## Build Profiles

Default production profile:

```bash
pio run -e esp12e
```

Production binary with serial logs enabled (`LOGI/LOGW/LOGE`, `LOGD` disabled):

```bash
pio run -e esp12e-serial
```

Debug profile with serial + debug logs:

```bash
pio run -e esp12e-debug
```

## Runtime Transport Modes

The firmware has two transport modes, selected from persisted connectivity config:

- `cloud_ws`: talks to the Hexa server over WSS (`/ws/device`).
- `local_mqtt`: talks directly to a local MQTT broker (for offline/Home Assistant local control).

Boot logs print mode and build flags:

- `Boot transport mode: cloud_ws|local_mqtt`
- `FW=<version> serial_logs=<0|1> debug_logs=<0|1>`
- `Claim code: <8 hex chars>`

## Claim Code Behavior

- Claim code is stable and derived from the last 8 hex chars of device MAC/chip id fallback.
- The same value is used as WiFiManager AP password:
  - `Hexa-Provision-AP`
  - `Hexa-Manual-AP`
- The code is printed on serial at boot when serial logs are enabled.

## Local MQTT Contract

When local MQTT mode is active:

- Discovery and state topics use `<base_topic>/<device_key>/...` (default base topic: `d`).
- Typical device key is provisioned `device_uid` (for example: `hexa-c9d0fe`).
- The firmware subscribes to:
  - `cmd/#`
- Supported command topics:
  - `cmd/relay/<index>` (`ON`/`OFF`)
  - `cmd/all` (`ON`/`OFF`)
  - `cmd/button_mode/<index>` (`push_button`, `rocker_switch`, `rocker_switch_follow`)
  - `cmd/button_link/<index>` (`ON`/`OFF`)
  - `cmd/control_mode` (`cloud_ws`/`local_mqtt` or `ON`/`OFF`)
- Published state/event topics include:
  - `state`
  - `status`
  - `input_event`
  - `buttons`
  - `config_state`
  - `link_state`
  - `response`
- Legacy JSON command payload on shared `cmd` topic is still accepted for compatibility.

## Mode Switch and Restart

A restart is expected when transport mode changes:

- Cloud `config_update` that changes connectivity mode schedules reboot.
- Local MQTT `cmd/control_mode=cloud_ws` schedules reboot.
- Cloud `config_update.connectivity.wifi` can schedule reboot when `reboot=true`.

This is intentional so the device cleanly tears down one transport stack and brings up the other.

## Remote Device Control (WS)

Over cloud WS, firmware supports device lifecycle control messages:

- `device_control` with `operation: "reboot"`:
  - sends ACK and schedules controlled restart.
- `device_control` with `operation: "factory_reset"`:
  - sends ACK
  - sends best-effort `unclaim`
  - clears Wi-Fi credentials and persisted automation/device state
  - restarts.

## Required Production Hardening

Set these before shipping:

- `PROVISION_KEY`: real provisioning secret
- `TLS_CERT_FINGERPRINT`: SHA1 fingerprint for your TLS endpoint
- `HEXA_ALLOW_INSECURE_TLS=0`
- `HEXA_ALLOW_UNSIGNED_OTA=0`

For GPIO3 button hardware, keep serial logs disabled in production:

- `HEXA_ENABLE_SERIAL_LOGS=0`

## Factory Reset

Holding `GPIO0` for `FACTORY_RESET_HOLD_TIME`:

- sends best-effort `unclaim` (cloud mode)
- resets Wi-Fi manager settings
- clears automations
- clears EEPROM persistence blocks
- reboots
