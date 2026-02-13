#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Hexa production updater

Usage:
  ops-update-server.sh [options]

Options:
  --repo-dir <path>         Repository root (default: /opt/hexa/resltime)
  --service <name>          systemd service name (default: hexa-server.service)
  --branch <name>           Git branch to deploy (default: main)
  --health-url <url>        Healthcheck URL (default: http://127.0.0.1:3000/health)
  --run-tests               Run npm test:unit during update (off by default on production updates)
  --skip-tests              Skip npm test:unit during update
  --skip-migrate            Skip npm run migrate
  --skip-pull               Skip git fetch/pull (use current working tree)
  --fast                    Shortcut for --skip-tests
  -h, --help                Show help

Examples:
  sudo ./scripts/ops-update-server.sh
  sudo ./scripts/ops-update-server.sh --branch main --service hexa-server.service
  sudo ./scripts/ops-update-server.sh --fast
EOF
}

REPO_DIR="/opt/hexa/resltime"
SERVICE_NAME="hexa-server.service"
BRANCH_NAME="main"
HEALTH_URL="http://127.0.0.1:3000/health"
# Production updates should not mutate the live DB via unit tests.
SKIP_TESTS=1
SKIP_MIGRATE=0
SKIP_PULL=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-dir)
      REPO_DIR="${2:-}"
      shift 2
      ;;
    --service)
      SERVICE_NAME="${2:-}"
      shift 2
      ;;
    --branch)
      BRANCH_NAME="${2:-}"
      shift 2
      ;;
    --health-url)
      HEALTH_URL="${2:-}"
      shift 2
      ;;
    --skip-tests)
      SKIP_TESTS=1
      shift
      ;;
    --run-tests)
      SKIP_TESTS=0
      shift
      ;;
    --skip-migrate)
      SKIP_MIGRATE=1
      shift
      ;;
    --skip-pull)
      SKIP_PULL=1
      shift
      ;;
    --fast)
      SKIP_TESTS=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$REPO_DIR" || -z "$SERVICE_NAME" || -z "$BRANCH_NAME" || -z "$HEALTH_URL" ]]; then
  echo "Invalid empty argument." >&2
  exit 1
fi

echo "==> Hexa update started at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "    repo:    $REPO_DIR"
echo "    branch:  $BRANCH_NAME"
echo "    service: $SERVICE_NAME"
echo "    health:  $HEALTH_URL"

cd "$REPO_DIR"

if [[ ! -d .git ]]; then
  echo "Repository not found: $REPO_DIR" >&2
  exit 1
fi

if [[ $SKIP_PULL -eq 0 ]]; then
  echo "==> Fetch latest code"
  git fetch --prune origin

  echo "==> Checkout branch $BRANCH_NAME"
  git checkout "$BRANCH_NAME"

  echo "==> Pull latest changes"
  git pull --ff-only origin "$BRANCH_NAME"
fi

DEPLOY_REV="$(git rev-parse --short HEAD)"
echo "==> Deploying revision $DEPLOY_REV"

cd "$REPO_DIR/server"

echo "==> Installing dependencies"
npm ci

echo "==> Building server"
npm run build

if [[ $SKIP_MIGRATE -eq 0 ]]; then
  echo "==> Running database migrations"
  npm run migrate
fi

if [[ $SKIP_TESTS -eq 0 ]]; then
  echo "==> Running unit tests"
  npm run test:unit
fi

echo "==> Restarting service"
systemctl restart "$SERVICE_NAME"

echo "==> Waiting for service health"
for i in {1..20}; do
  if curl -fsS "$HEALTH_URL" >/dev/null; then
    echo "==> Health check passed"
    echo "==> Update completed successfully at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "    deployed revision: $DEPLOY_REV"
    exit 0
  fi
  sleep 1
done

echo "Health check failed for $HEALTH_URL after restart." >&2
systemctl status "$SERVICE_NAME" --no-pager || true
exit 1
