# Rollback Runbook

## Preconditions

- Confirm incident scope and rollback trigger.
- Freeze new deployments.
- Confirm latest healthy release artifact is available.

## Application Rollback

1. Deploy previous stable server artifact/container image.
2. Confirm startup health (`/health`) and metrics endpoint (`/metrics`).
3. Confirm admin dashboard loads and data paths are healthy.
4. Run smoke checks:
   - auth login
   - device list
   - relay command path
   - OTA release listing

## Data Rollback / Recovery

1. Identify latest encrypted backup before incident window.
2. Run restore drill first to validate backup integrity and timing.
3. Restore backup according to infrastructure procedure.
4. Re-validate:
   - row counts for critical tables
   - OTA release/signing key integrity checks
   - scheduler and automation execution health

## Post-Rollback Validation Checklist

- API error rate back to baseline.
- Command timeout rate back to baseline.
- Scheduler errors not increasing.
- No backup failures in latest run.

## Communication

- Record rollback reason, timestamp, and approver.
- Publish incident summary with mitigation and follow-up actions.
