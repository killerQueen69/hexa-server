# API and WS Versioning Policy

## Scope

- REST APIs are versioned under `/api/v1`.
- WebSocket contract version is `v1` and applies to `/ws/device` and `/ws/client` payload schema.

## Compatibility Rules

1. Additive changes are allowed in-place in `v1` (new optional fields/endpoints/events).
2. Breaking changes require a new major version (`/api/v2`, `ws=v2`).
3. Existing required fields and message types in `v1` cannot change semantics.

## Deprecation Window

- Minimum deprecation window: **180 days** before removal.
- Deprecation notice must include:
  - affected endpoint/event
  - replacement endpoint/event
  - deprecation announcement date
  - planned removal date

## Communication Requirements

- Changelog entry is mandatory for all external contract changes.
- Deprecated REST responses include warning metadata via release notes/docs.
- WS deprecations are documented in server release notes and dashboard admin notices.

## Operational Controls

- Current runtime versions are exposed at `GET /api/v1/admin/versioning`.
- CI release gates require updated changelog and staging sign-off before production.
