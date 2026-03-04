#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT_DIR"

ENV_FILE="scripts/deploy/master/master_env"
if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
fi

NATS_CONTAINER_NAME="${NATS_CONTAINER_NAME:-rsiem-nats-lan}"
KEEP_NATS=0
KEEP_DB=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep-nats) KEEP_NATS=1; shift ;;
    --keep-db) KEEP_DB=1; shift ;;
    *)
      echo "Usage: $0 [--keep-nats] [--keep-db]" >&2
      exit 1
      ;;
  esac
done

./scripts/demo_down.sh >/dev/null 2>&1 || true

if [[ "$KEEP_DB" -eq 0 ]]; then
  ./scripts/db_down.sh >/dev/null 2>&1 || true
fi

if [[ "$KEEP_NATS" -eq 0 ]]; then
  if docker ps -a --format '{{.Names}}' | grep -qx "$NATS_CONTAINER_NAME"; then
    docker rm -f "$NATS_CONTAINER_NAME" >/dev/null || true
  fi
fi

echo "PASS: master LAN stack stopped"
