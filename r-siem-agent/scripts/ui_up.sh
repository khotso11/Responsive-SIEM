#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

command -v go >/dev/null 2>&1 || { echo "FAIL: missing go"; exit 1; }
command -v npm >/dev/null 2>&1 || { echo "FAIL: missing npm"; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "FAIL: missing curl"; exit 1; }

mkdir -p logs .pids .cache/go-build

UI_API_ADDR="${UI_API_ADDR:-127.0.0.1:8090}"
UI_WEB_HOST="${UI_WEB_HOST:-127.0.0.1}"
UI_WEB_PORT="${UI_WEB_PORT:-3000}"
UI_API_KEY="${UI_API_KEY:-dev-ui-key}"
UI_API_BASE="http://${UI_API_ADDR}"
UI_DEV_DIST_DIR="${UI_DEV_DIST_DIR:-.next-dev}"

cleanup_stale_ui_procs() {
  pkill -x ui-api >/dev/null 2>&1 || true
  pkill -f '/tmp/go-build.*/exe/ui-api' >/dev/null 2>&1 || true
  pkill -f 'cmd/ui-api --addr 127.0.0.1:8090' >/dev/null 2>&1 || true
  pkill -f 'next dev --hostname 127.0.0.1 --port 3000' >/dev/null 2>&1 || true
  pkill -f 'next dev --hostname 127.0.0.1 --port 3100' >/dev/null 2>&1 || true
}

prepare_ui_dev_cache() {
  local dist_path="ui/${UI_DEV_DIST_DIR}"
  if [[ -d "$dist_path" ]]; then
    local stale_dir
    stale_dir="/tmp/rsiem-ui-next-$(date +%s)"
    mv "$dist_path" "$stale_dir"
    echo "Moved stale ${dist_path} to $stale_dir"
  fi
}

wait_for_http_ready() {
  local name="$1" url="$2" tries="${3:-30}"
  for _ in $(seq 1 "$tries"); do
    if curl -fsS --max-time 2 "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "FAIL: ${name} not ready at ${url}" >&2
  return 1
}

resolve_child_pid() {
  local pattern="$1"
  pgrep -f "$pattern" | tail -n1 || true
}

start_if_needed() {
  local name="$1" pid_file="$2" log_file="$3" ready_url="$4" process_pattern="$5"
  shift 5

  if [[ -f "$pid_file" ]]; then
    local old_pid
    old_pid="$(cat "$pid_file" 2>/dev/null || true)"
    if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
      if wait_for_http_ready "$name" "$ready_url" 3; then
        echo "$name already running pid=$old_pid"
        return
      fi
    fi
    rm -f "$pid_file"
  fi

  if wait_for_http_ready "$name" "$ready_url" 1; then
    local discovered_pid
    discovered_pid="$(resolve_child_pid "$process_pattern")"
    if [[ -n "$discovered_pid" ]]; then
      echo "$discovered_pid" > "$pid_file"
      echo "$name already running pid=$discovered_pid"
      return
    fi
    echo "$name already running and ready"
    return
  fi

  echo "Starting $name..."
  nohup "$@" >> "$log_file" 2>&1 < /dev/null &
  local launcher_pid="$!"
  echo "$launcher_pid" > "$pid_file"
  if ! wait_for_http_ready "$name" "$ready_url" 30; then
    tail -n 40 "$log_file" >&2 || true
    exit 1
  fi
  local runtime_pid
  runtime_pid="$(resolve_child_pid "$process_pattern")"
  if [[ -n "$runtime_pid" ]]; then
    echo "$runtime_pid" > "$pid_file"
    echo "$name started pid=$runtime_pid"
  else
    rm -f "$pid_file"
    echo "FAIL: ${name} became ready but no stable child pid matched pattern ${process_pattern}" >&2
    tail -n 40 "$log_file" >&2 || true
    exit 1
  fi
}

cleanup_stale_ui_procs
prepare_ui_dev_cache

start_if_needed "ui-api" ".pids/ui-api.pid" "logs/ui-api.log" "${UI_API_BASE}/api/health" "/tmp/go-build.*/exe/ui-api|cmd/ui-api --addr ${UI_API_ADDR}" env \
  UI_API_KEY="$UI_API_KEY" \
  GOFLAGS="${GOFLAGS:--mod=mod}" \
  GOCACHE="$ROOT_DIR/.cache/go-build" \
  go run ./cmd/ui-api --addr "$UI_API_ADDR" --master-config configs/master.yaml

if [[ ! -d ui/node_modules ]]; then
  echo "Installing UI dependencies (first run)..."
  npm --prefix ui install --no-audit --no-fund
fi

start_if_needed "ui-web" ".pids/ui-web.pid" "logs/ui-web.log" "http://${UI_WEB_HOST}:${UI_WEB_PORT}" "next dev --hostname ${UI_WEB_HOST} --port ${UI_WEB_PORT}|next/dist/bin/next" env \
  NEXT_PUBLIC_UI_API_BASE="$UI_API_BASE" \
  NEXT_PUBLIC_UI_API_KEY="$UI_API_KEY" \
  RSIEM_UI_DIST_DIR="$UI_DEV_DIST_DIR" \
  npm --prefix ui run dev -- --hostname "$UI_WEB_HOST" --port "$UI_WEB_PORT"

echo "PASS: FR-06 UI services started"
echo "UI_WEB_URL=http://${UI_WEB_HOST}:${UI_WEB_PORT}"
echo "UI_API_URL=${UI_API_BASE}"
