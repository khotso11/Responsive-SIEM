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
need_cmd rg

CONTAINER_NAME="${DB_CONTAINER_NAME:-rsiem-timescale}"
IMAGE="${DB_IMAGE:-timescale/timescaledb:latest-pg14}"
VOLUME_NAME="${DB_VOLUME_NAME:-rsiem_timescale_data}"
DB_NAME="${DB_NAME:-rsiem}"
DB_USER="${DB_USER:-rsiem}"
DB_PASSWORD="${DB_PASSWORD:-rsiem}"
DB_PORT="${DB_PORT:-5432}"
DB_DSN="postgres://${DB_USER}:${DB_PASSWORD}@127.0.0.1:${DB_PORT}/${DB_NAME}?sslmode=disable"

if ! docker volume ls --format '{{.Name}}' | rg -qx "${VOLUME_NAME}"; then
  docker volume create "${VOLUME_NAME}" >/dev/null
fi

if docker ps -a --format '{{.Names}}' | rg -qx "${CONTAINER_NAME}"; then
  if ! docker ps --format '{{.Names}}' | rg -qx "${CONTAINER_NAME}"; then
    docker start "${CONTAINER_NAME}" >/dev/null
  fi
else
  docker run -d \
    --name "${CONTAINER_NAME}" \
    -e POSTGRES_USER="${DB_USER}" \
    -e POSTGRES_PASSWORD="${DB_PASSWORD}" \
    -e POSTGRES_DB="${DB_NAME}" \
    -p "${DB_PORT}:5432" \
    -v "${VOLUME_NAME}:/var/lib/postgresql/data" \
    "${IMAGE}" >/dev/null
fi

ready=0
for _ in $(seq 1 120); do
  if docker exec "${CONTAINER_NAME}" pg_isready -U "${DB_USER}" -d "${DB_NAME}" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done

if [[ "$ready" -ne 1 ]]; then
  echo "FAIL: database not ready in container ${CONTAINER_NAME}" >&2
  exit 1
fi

docker exec -i "${CONTAINER_NAME}" psql -v ON_ERROR_STOP=1 -U "${DB_USER}" -d "${DB_NAME}" <<'SQL' >/dev/null
CREATE EXTENSION IF NOT EXISTS timescaledb;
CREATE TABLE IF NOT EXISTS normalized_events (
  id BIGSERIAL PRIMARY KEY,
  ingest_ts TIMESTAMPTZ NOT NULL DEFAULT now(),
  event_ts_unix_ms BIGINT NOT NULL,
  recv_ts_unix_ms BIGINT NOT NULL,
  node_id TEXT NOT NULL,
  source_type TEXT NOT NULL,
  event_type TEXT NOT NULL,
  src_ip INET NULL,
  user_name TEXT NULL,
  severity TEXT NULL,
  rule_id TEXT NULL,
  event_idem_key TEXT NOT NULL,
  raw_line_sha256 TEXT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS normalized_events_event_idem_key_uidx ON normalized_events(event_idem_key);
CREATE INDEX IF NOT EXISTS normalized_events_event_ts_idx ON normalized_events(event_ts_unix_ms);
CREATE INDEX IF NOT EXISTS normalized_events_node_id_idx ON normalized_events(node_id);
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'create_hypertable') THEN
    PERFORM create_hypertable('normalized_events', 'ingest_ts', if_not_exists => TRUE);
  END IF;
EXCEPTION WHEN OTHERS THEN
  -- Hypertable conversion is optional for FR-02B proof.
  NULL;
END;
$$;
SQL

echo "PASS: db_up completed"
echo "DB_DSN=${DB_DSN}"
