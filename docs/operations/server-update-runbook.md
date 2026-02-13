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
- `systemctl restart hexa-server.service`
- health check on `http://127.0.0.1:3000/health`

Note: unit tests are skipped by default in production updates to avoid mutating the live database.

If you explicitly want to run unit tests during update:

```bash
sudo /opt/hexa/resltime/server/scripts/ops-update-server.sh --run-tests
```

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

## 7. Automatic update on GitHub push (recommended)

This repo includes workflow:
- `.github/workflows/deploy-server.yml`

Behavior:
- On every successful `server-ci` run for `main`, deploy job runs over SSH.
- Also supports manual run from GitHub Actions UI (`workflow_dispatch`), with optional `fast` mode.

### Required GitHub secrets

Set these repository secrets:
- `PROD_SSH_HOST`
- `PROD_SSH_PORT`
- `PROD_SSH_USER`
- `PROD_SSH_KEY` (private key content)

### Debian host setup for deploy user

1. Create deploy user (example `deployer`) and add its public key to:
   - `/home/deployer/.ssh/authorized_keys`
2. Allow passwordless sudo only for updater script:

```bash
sudo visudo -f /etc/sudoers.d/hexa-deployer
```

Add:

```text
deployer ALL=(root) NOPASSWD:/opt/hexa/resltime/server/scripts/ops-update-server.sh
```

3. Validate manually once:

```bash
ssh deployer@<server-ip>
sudo /opt/hexa/resltime/server/scripts/ops-update-server.sh --help
```
