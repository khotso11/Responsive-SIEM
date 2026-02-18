#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PID_DIR=".pids"

stop_from_pidfile() {
  local name="$1"
  local pid_file="$2"

  if [[ ! -f "$pid_file" ]]; then
    echo "$name not running (no pid file)"
    return 0
  fi

  local pid
  pid="$(cat "$pid_file" 2>/dev/null || true)"
  if [[ -z "$pid" ]]; then
    rm -f "$pid_file"
    echo "$name stopped (stale pid file removed)"
    return 0
  fi

  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    local i=0
    while (( i < 30 )); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.1
      i=$((i+1))
    done
    kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null || true
    echo "$name stopped pid=$pid"
  else
    echo "$name already stopped (stale pid=$pid)"
  fi

  rm -f "$pid_file"
}

stop_from_pidfile "collector-tail" "$PID_DIR/collector.pid"
stop_from_pidfile "detector-v0" "$PID_DIR/detector.pid"
stop_from_pidfile "agent" "$PID_DIR/agent.pid"
stop_from_pidfile "master-roe-worker" "$PID_DIR/worker.pid"
stop_from_pidfile "master-roe" "$PID_DIR/master-roe.pid"

exit 0
