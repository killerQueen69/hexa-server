# Hexa Platform Documentation

## Start Here

- System architecture and runtime behavior:
  - `docs/how-it-works.md`
- Full REST API and webhook-style HTTP callback reference:
  - `docs/api/rest-and-webhook-reference.md`
  - includes device extensibility APIs (`capabilities`, `ir-codes`, `sensor-*`) and user preferences APIs (`/api/v1/preferences`)
- Full WebSocket protocol reference (device + client channels):
  - `docs/api/websocket-reference.md`

## Operations and Production Gate Docs

- API/WS versioning policy: `docs/api/versioning-policy.md`
- Disaster recovery (RPO/RTO): `docs/operations/disaster-recovery.md`
- Monitoring and alerting: `docs/operations/monitoring-alerts.md`
- Prometheus alert examples: `docs/operations/alert-rules.yml`
- Rollback runbook: `docs/operations/rollback-runbook.md`
- Server update runbook: `docs/operations/server-update-runbook.md`
- Secrets and key rotation: `docs/operations/secret-and-key-rotation.md`
- CI/CD gates: `docs/operations/ci-cd-gates.md`
- Security checklist: `docs/operations/security-checklist.md`
- Staging sign-off gate: `docs/operations/staging-signoff.md`
- Sign-off state file: `docs/operations/staging-signoff.json`
- HP t530 production deployment plan: `docs/operations/deployment-plan-hp-t530.md`
- Cloudflare domain/tunnel setup for `vistfiy.store`: `docs/operations/cloudflare-vistfiy-setup.md`
- Automatic deploy workflow: `.github/workflows/deploy-server.yml`
