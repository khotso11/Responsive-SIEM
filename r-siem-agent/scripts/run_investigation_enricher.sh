#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${INVESTIGATION_ENV_FILE:-$ROOT_DIR/.env.investigation.local}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "missing env file: $ENV_FILE" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

: "${DB_DSN:?DB_DSN is required}"
: "${NATS_URL:?NATS_URL is required}"
: "${INVESTIGATION_ENABLED_PROVIDERS:?INVESTIGATION_ENABLED_PROVIDERS is required}"

cd "$ROOT_DIR"
exec env GOCACHE="${GOCACHE:-$ROOT_DIR/.cache/go-build}" go run ./cmd/investigation-enricher
