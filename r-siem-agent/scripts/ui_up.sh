#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

command -v go >/dev/null 2>&1 || { echo "FAIL: missing go"; exit 1; }
command -v npm >/dev/null 2>&1 || { echo "FAIL: missing npm"; exit 1; }

mkdir -p logs .pids .cache/go-build

UI_API_ADDR="${UI_API_ADDR:-127.0.0.1:8090}"
UI_WEB_HOST="${UI_WEB_HOST:-127.0.0.1}"
UI_WEB_PORT="${UI_WEB_PORT:-3000}"
UI_API_KEY="${UI_API_KEY:-dev-ui-key}"
UI_API_BASE="http://${UI_API_ADDR}"

cleanup_stale_ui_procs() {
  pkill -x ui-api >/dev/null 2>&1 || true
  pkill -f '/tmp/go-build.*/exe/ui-api' >/dev/null 2>&1 || true
  pkill -f 'cmd/ui-api --addr 127.0.0.1:8090' >/dev/null 2>&1 || true
  pkill -f 'next dev --hostname 127.0.0.1 --port 3000' >/dev/null 2>&1 || true
  pkill -f 'next dev --hostname 127.0.0.1 --port 3100' >/dev/null 2>&1 || true
}

start_if_needed() {
  local name="$1" pid_file="$2" log_file="$3"
  shift 3

  if [[ -f "$pid_file" ]]; then
    local old_pid
    old_pid="$(cat "$pid_file" 2>/dev/null || true)"
    if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
      echo "$name already running pid=$old_pid"
      return
    fi
  fi

  echo "Starting $name..."
  "$@" >> "$log_file" 2>&1 &
  local pid="$!"
  echo "$pid" > "$pid_file"
  sleep 1
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "FAIL: $name failed to start; see $log_file"
    exit 1
  fi
  echo "$name started pid=$pid"
}

cleanup_stale_ui_procs

start_if_needed "ui-api" ".pids/ui-api.pid" "logs/ui-api.log" env \
  UI_API_KEY="$UI_API_KEY" \
  GOCACHE="$ROOT_DIR/.cache/go-build" \
  go run -mod=vendor ./cmd/ui-api --addr "$UI_API_ADDR" --master-config configs/master.yaml

if [[ ! -d ui/node_modules ]]; then
  echo "Installing UI dependencies (first run)..."
  npm --prefix ui install --no-audit --no-fund
fi

start_if_needed "ui-web" ".pids/ui-web.pid" "logs/ui-web.log" env \
  NEXT_PUBLIC_UI_API_BASE="$UI_API_BASE" \
  NEXT_PUBLIC_UI_API_KEY="$UI_API_KEY" \
  npm --prefix ui run dev -- --hostname "$UI_WEB_HOST" --port "$UI_WEB_PORT"

echo "PASS: FR-06 UI services started"
echo "UI_WEB_URL=http://${UI_WEB_HOST}:${UI_WEB_PORT}"
echo "UI_API_URL=${UI_API_BASE}"
