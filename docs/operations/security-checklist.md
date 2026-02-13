# Security Checklist

Date: 2026-02-13

## Critical Findings

- None open.

## Checklist

- [x] JWT and refresh token flows validated.
- [x] Device token stored hashed at rest.
- [x] Mutating APIs support idempotency keys.
- [x] API errors include request id.
- [x] OTA signatures verified before serving manifests.
- [x] OTA anti-rollback enforced by `security_version` floor.
- [x] OTA host allowlist supported.
- [x] Signing key rotation path (`active`/`next`/`retired`) implemented.
- [x] Backup artifacts encrypted at rest.
- [x] Restore drill target enforced via RTO threshold.
- [x] Production dependency audit has no high/critical findings.
- [x] Production HTTPS enforcement rejects insecure HTTP and non-secure WS upgrades when enabled.
- [x] CI includes production transport security test gate (`npm run test:security`).
