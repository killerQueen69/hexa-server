# Monitoring, Dashboards, and Alert Rules

## Dashboard Source

Primary runtime dashboard: `GET /dashboard`.

It surfaces:
- Fleet/device/user/schedule/OTA KPIs (`/api/v1/admin/overview`)
- Raw Prometheus metrics (`/metrics`)
- Alert simulation (`/api/v1/admin/ops/alerts/simulate`)
- Backup runs and restore-drill history
- Device command controls plus recent action/input-event visibility

## Core Alert Rules

1. API 5xx spike
- Metric: `hexa_api_errors_total{status_code=~"5.."}`
- Trigger: total increase above threshold for 5-minute window

2. Command timeout spike
- Metric: `hexa_command_total{result="timeout"}`
- Trigger: increase above threshold for 5-minute window

3. Scheduler error spike
- Metrics:
  - `hexa_scheduler_tick_total{result="error"}`
  - `hexa_scheduler_execution_total{result="error"}`
- Trigger: combined increase above threshold

4. Backup failures
- Source: `ops_backup_runs` with `status='error'`
- Trigger: one or more failures in 24 hours

## Alert Simulation

Use `POST /api/v1/admin/ops/alerts/simulate` with optional thresholds to verify notification behavior before production.

## Notifications

Recommended channels:
- Pager/phone for critical (`api_5xx_spike`, `backup_failures_recent`)
- Chat/email for high (`command_timeout_spike`, `scheduler_error_spike`)
