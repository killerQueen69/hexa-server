# Staging Sign-Off Gate

Production release requires an approved staging sign-off document.

## Validation Command

- `npm run validate:signoff`

The command checks `docs/operations/staging-signoff.json` (or `SIGNOFF_FILE`) and fails when:
- file is missing
- JSON is invalid
- `approved` is not `true`
- required metadata fields are missing

## Required Fields

- `approved`
- `approved_by`
- `approved_at`
- `release_version`

## Release Workflow

1. Execute full CI suite.
2. Deploy to staging.
3. Run staging smoke checks.
4. Update sign-off JSON to approved state.
5. Trigger release pipeline with sign-off validation.
