# CI/CD Gates

## Mandatory Gates

- Lint/type gate: `npm run lint`
- Unit tests: `npm run test:unit`
- Production transport security tests: `npm run test:security`
- Integration tests: `npm run test:integration`
- E2E smoke tests: `npm run test:e2e`

Combined command:

- `npm run test:ci`
  - includes `npm run migrate:smoke` (migration down/up smoke validation)
  - integration stage runs both:
    - `tests/integration/server.integration.test.ts` (state/WS/OTA flow)
    - `tests/integration/api-surface.integration.test.ts` (admin, audit, schedules/automations lifecycle, device feature APIs, webhook routes)

## Workflows

- `.github/workflows/server-ci.yml`
  - Runs on push and pull requests
  - Provisions PostgreSQL
  - Runs migration + quality gates

- `.github/workflows/release-gate.yml`
  - Manual production release gate
  - Runs full quality gates
  - Requires approved staging sign-off (`npm run validate:signoff`)
  - Production deployment must keep HTTPS enforcement enabled (`ENFORCE_HTTPS=true`)

## Rollback Requirement

If release gate fails after deploy validation, execute rollback runbook: `docs/operations/rollback-runbook.md`.
