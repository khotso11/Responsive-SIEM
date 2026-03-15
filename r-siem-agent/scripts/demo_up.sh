#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

LOG_DIR="logs"
TMP_DIR="tmp"
PID_DIR=".pids"
GOCACHE_DIR=".cache/go-build"

MASTER_LOG="$LOG_DIR/master-roe.log"
WORKER_LOG="$LOG_DIR/worker.log"
AGENT_LOG="$LOG_DIR/agent.log"
DETECTOR_LOG="$LOG_DIR/detector.log"
COLLECTOR_LOG="$LOG_DIR/collector.log"

MASTER_PID_FILE="$PID_DIR/master-roe.pid"
WORKER_PID_FILE="$PID_DIR/worker.pid"
AGENT_PID_FILE="$PID_DIR/agent.pid"
DETECTOR_PID_FILE="$PID_DIR/detector.pid"
COLLECTOR_PID_FILE="$PID_DIR/collector.pid"

need_cmd() {
  local cmd="$1"
  local hint="${2:-}"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $cmd" >&2
    [[ -n "$hint" ]] && echo "$hint" >&2
    exit 1
  fi
}

need_cmd go
need_cmd rg
need_cmd nats "Install nats CLI and ensure it is in PATH, then rerun."

[[ -f configs/master.yaml ]] || { echo "ERROR: missing configs/master.yaml" >&2; exit 1; }
[[ -f configs/agent.yaml ]] || { echo "ERROR: missing configs/agent.yaml" >&2; exit 1; }
[[ -f configs/detector.yaml ]] || { echo "ERROR: missing configs/detector.yaml" >&2; exit 1; }
[[ -f configs/collector.yaml ]] || { echo "ERROR: missing configs/collector.yaml" >&2; exit 1; }

mkdir -p "$LOG_DIR" "$TMP_DIR" "$PID_DIR" "$GOCACHE_DIR"
[[ -w "$LOG_DIR" ]] || { echo "ERROR: logs directory is not writable: $LOG_DIR" >&2; exit 1; }

if ! nats pub rsiem.demo.precheck "{\"ts\":$(date +%s)}" >/dev/null 2>&1; then
  echo "ERROR: NATS server is not reachable by nats CLI." >&2
  echo "Start NATS separately (example: nats-server -js or docker run --rm --name nats --network host nats:2 -js) and rerun ./scripts/demo_up.sh" >&2
  exit 1
fi

start_process() {
  local name="$1"
  local pid_file="$2"
  local log_file="$3"
  shift 3

  if [[ -f "$pid_file" ]]; then
    local old_pid
    old_pid="$(cat "$pid_file" 2>/dev/null || true)"
    if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
      echo "$name already running pid=$old_pid"
      return 0
    fi
  fi

  echo "Starting $name..."
  env GOCACHE="$ROOT_DIR/$GOCACHE_DIR" "$@" >> "$log_file" 2>&1 &
  local pid="$!"
  echo "$pid" > "$pid_file"
  sleep 1
  if kill -0 "$pid" 2>/dev/null; then
    echo "$name started pid=$pid log=$log_file"
    return 0
  fi

  echo "ERROR: failed to start $name. Check $log_file" >&2
  rm -f "$pid_file"
  exit 1
}

start_process "master-roe" "$MASTER_PID_FILE" "$MASTER_LOG" go run -mod=vendor ./cmd/master-roe --config configs/master.yaml
start_process "master-roe-worker" "$WORKER_PID_FILE" "$WORKER_LOG" go run -mod=vendor ./cmd/master-roe-worker --config configs/master.yaml --lane BOTH
start_process "agent" "$AGENT_PID_FILE" "$AGENT_LOG" env RSIEM_AGENT_LATERAL_CONTROL_MODE=marker go run -mod=vendor ./cmd/agent --config configs/agent.yaml
start_process "detector-v0" "$DETECTOR_PID_FILE" "$DETECTOR_LOG" go run -mod=vendor ./cmd/detector-v0 --config configs/detector.yaml
start_process "collector-tail" "$COLLECTOR_PID_FILE" "$COLLECTOR_LOG" go run -mod=vendor ./cmd/collector-tail --config configs/collector.yaml

cat <<'GUIDE'

=== DEMO GUIDE ===

Tail logs (separate terminals):
  tail -f logs/master-roe.log
  tail -f logs/worker.log
  tail -f logs/agent.log
  tail -f logs/detector.log
  tail -f logs/collector.log

Trigger one deterministic run:
  NOW=$(date +%s)
  echo "FAILED login user=khotso src=10.0.0.8 ts=${NOW}" >> tmp/demo.log

Alternative trigger (legacy demo line):
  NOW=$(date +%s)
  OCT=$(( (NOW % 180) + 20 ))
  echo "DEMO invalid user from 10.0.0.${OCT} ts=${NOW}" >> tmp/demo.log

Extract latest run_id from master log:
  RUN_ID=$(rg '"msg":"response_run_created".*"rule_id":"R-COLLECT-INVALID-USER".*"playbook_id":"PB-AGENT-PING-LOCALHOST"' logs/master-roe.log | tail -n 1 | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')
  echo "$RUN_ID"

Approve (canonical):
  RUN_ID="PUT_RUN_ID_HERE"
  nats pub rsiem.response.approvals "{\"run_id\":\"$RUN_ID\",\"decision\":\"approve\",\"actor\":\"khotso\"}"

What to look at:
  rg '"msg":"response_run_created"' logs/master-roe.log
  rg '"msg":"response_run_waiting_approval"' logs/master-roe.log
  rg '"msg":"detector_rule_matched"' logs/detector.log
  rg '"msg":"approval_received"' logs/master-roe.log
  rg '"msg":"response_step_published"' logs/master-roe.log
  rg '"msg":"step_received"' logs/worker.log
  rg '"msg":"agent_command_exec_start"' logs/agent.log
  rg '"msg":"response_step_result_received".*"status":"SUCCEEDED"' logs/master-roe.log

Stop everything started by this script:
  ./scripts/demo_down.sh
GUIDE
