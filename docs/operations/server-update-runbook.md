# Server Update Runbook (Debian)

This runbook is for routine production updates on the Debian host.

## 1. One-time setup

1. Pull latest repo once and ensure script exists:
   - `/opt/hexa/resltime/server/scripts/ops-update-server.sh`
2. Make it executable:
   - `chmod +x /opt/hexa/resltime/server/scripts/ops-update-server.sh`
3. Ensure service name is correct:
   - default expected service: `hexa-server.service`

## 2. Recommended update command

Run as root (or sudo):

```bash
sudo /opt/hexa/resltime/server/scripts/ops-update-server.sh
```

This performs:
- git fetch/pull (fast-forward only)
- `npm ci`
- `npm run build`
- `npm run migrate`
- `npm run test:unit`
- `systemctl restart hexa-server.service`
- health check on `http://127.0.0.1:3000/health`

## 3. Fast update (skip tests)

```bash
sudo /opt/hexa/resltime/server/scripts/ops-update-server.sh --fast
```

## 4. Update from already-checked-out revision

If you manually checked out a commit/tag and only want build/migrate/restart:

```bash
cd /opt/hexa/resltime
git checkout <commit-or-tag>
sudo /opt/hexa/resltime/server/scripts/ops-update-server.sh --skip-pull
```

## 5. Health and logs after update

```bash
curl -fsS http://127.0.0.1:3000/health
systemctl status hexa-server.service --no-pager
journalctl -u hexa-server.service -n 200 --no-pager
```

## 6. Failure handling

- If update script fails health check:
  1. inspect service logs
  2. check DB migration output
  3. rollback using `docs/operations/rollback-runbook.md`
