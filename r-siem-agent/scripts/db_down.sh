#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "FAIL: missing command: $1" >&2
    exit 1
  }
}

need_cmd docker

CONTAINER_NAME="${DB_CONTAINER_NAME:-rsiem-timescale}"
VOLUME_NAME="${DB_VOLUME_NAME:-rsiem_timescale_data}"
PURGE="${1:-}"

if docker ps -a --format '{{.Names}}' | grep -qx "${CONTAINER_NAME}"; then
  docker rm -f "${CONTAINER_NAME}" >/dev/null
fi

if [[ "${PURGE}" == "--purge" ]]; then
  if docker volume ls --format '{{.Name}}' | grep -qx "${VOLUME_NAME}"; then
    docker volume rm "${VOLUME_NAME}" >/dev/null || true
  fi
fi

echo "PASS: db_down completed"
