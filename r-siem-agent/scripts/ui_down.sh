#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

UI_API_ADDR="${UI_API_ADDR:-127.0.0.1:8090}"
UI_WEB_PORT="${UI_WEB_PORT:-3000}"

stop_pid() {
  local name="$1" pid_file="$2"
  if [[ ! -f "$pid_file" ]]; then
    echo "$name not running"
    return
  fi
  local pid
  pid="$(cat "$pid_file" 2>/dev/null || true)"
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    sleep 1
    if kill -0 "$pid" 2>/dev/null; then
      kill -9 "$pid" 2>/dev/null || true
    fi
    echo "$name stopped pid=$pid"
  else
    echo "$name stale pid file"
  fi
  rm -f "$pid_file"
}

stop_port() {
  local label="$1" port="$2"
  local pids
  pids="$(ss -ltnp 2>/dev/null | awk -v p=":${port}" '$4 ~ p {print $NF}' | sed -n 's/.*pid=\([0-9]\+\).*/\1/p' | sort -u)"
  if [[ -z "$pids" ]]; then
    return
  fi
  for pid in $pids; do
    kill "$pid" 2>/dev/null || true
    sleep 0.2
    kill -9 "$pid" 2>/dev/null || true
  done
  echo "$label stopped by port :$port"
}

stop_pid "ui-web" ".pids/ui-web.pid"
stop_pid "ui-api" ".pids/ui-api.pid"
stop_port "ui-api" "${UI_API_ADDR##*:}"
stop_port "ui-web" "${UI_WEB_PORT}"

echo "PASS: FR-06 UI services stopped"
