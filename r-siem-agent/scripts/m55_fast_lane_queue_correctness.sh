#!/usr/bin/env bash
set -euo pipefail

LOG_COLLECTOR="logs/collector-tail.log"
LOG_DETECTOR="logs/detector-v0.log"
LOG_MASTER="logs/master-roe.log"
LOG_WORKER="logs/roe-worker.log"
LOG_AGENT="logs/agent.log"
LOG_EXPORT="exports/roe_steps_latest.jsonl"
DEMO_LOG="tmp/demo.log"

require_log() {
  local file="$1"
  local label="$2"
  if [[ ! -s "$file" ]]; then
    echo "FAIL: missing or empty ${file}. Start ${label} first." >&2
    exit 2
  fi
}

line_count() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    echo 0
    return
  fi
  wc -l < "$file" | tr -d ' '
}

tail_from() {
  local file="$1"
  local base="$2"
  tail -n +"$((base + 1))" "$file" 2>/dev/null || true
}

wait_in_tail() {
  local pattern="$1"
  local file="$2"
  local baseline_count="$3"
  local max_wait="$4"
  local elapsed=0
  while (( elapsed < max_wait )); do
    local match
    match="$(tail_from "$file" "$baseline_count" | rg "$pattern" | head -n 1 || true)"
    if [[ -n "$match" ]]; then
      echo "$match"
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  return 1
}

debug_recent() {
  local pattern="$1"
  local file="$2"
  echo "Context: last 80 relevant lines from ${file}:" >&2
  rg "$pattern" "$file" | tail -n 80 >&2 || true
}

find_fast_worker_pids() {
  ps -eo pid=,args= | rg 'master-roe-worker' | rg '\-lane FAST' | awk '{print $1}' || true
}

echo "=== M55 FAST lane queue correctness ==="

require_log "$LOG_COLLECTOR" "Terminal H (collector-tail)"
require_log "$LOG_DETECTOR" "Terminal I (detector-v0)"
require_log "$LOG_MASTER" "Terminal E (master-roe)"
require_log "$LOG_WORKER" "Terminal F (roe-worker)"
require_log "$LOG_AGENT" "Terminal G (agent)"
require_log "$LOG_EXPORT" "exports/roe_steps_latest.jsonl"

mkdir -p tmp logs .cache/go-build

AUTO_STOPPED=0
AUTO_STARTED=0
STARTED_PID=""

fast_pids="$(find_fast_worker_pids)"
if [[ -n "$fast_pids" ]]; then
  AUTO_STOPPED=1
  echo "Detected FAST worker PIDs: ${fast_pids}"
  echo "$fast_pids" | xargs -r kill
  sleep 1
  still_fast="$(find_fast_worker_pids)"
  if [[ -n "$still_fast" ]]; then
    echo "FAIL: unable to stop FAST worker pids: ${still_fast}" >&2
    exit 1
  fi
else
  echo "No dedicated FAST worker with '-lane FAST' detected."
  read -r -p "Stop FAST worker manually now, then press Enter." _
fi

base_detector="$(line_count "$LOG_DETECTOR")"
base_master="$(line_count "$LOG_MASTER")"
base_worker="$(line_count "$LOG_WORKER")"
base_agent="$(line_count "$LOG_AGENT")"
base_export="$(line_count "$LOG_EXPORT")"

NOW="$(date +%s)"
octet=$(( (NOW % 180) + 20 ))
echo "M41 invalid user from 10.0.0.${octet} ts=${NOW}" >> "$DEMO_LOG"

trigger_line="$(wait_in_tail "\"msg\":\"trigger_published\".*\"alert_key\":\"A-COLLECT-INVALID-USER-" "$LOG_DETECTOR" "$base_detector" 60 || true)"
if [[ -z "$trigger_line" ]]; then
  echo "FAIL: timeout waiting for invalid-user trigger_published" >&2
  debug_recent '"msg":"rule_matched"|"msg":"trigger_published".*"A-COLLECT-INVALID-USER-' "$LOG_DETECTOR"
  exit 1
fi

run_line="$(wait_in_tail "\"msg\":\"response_run_created\".*\"rule_id\":\"R-COLLECT-INVALID-USER\".*\"playbook_id\":\"PB-AGENT-PING-LOCALHOST\"" "$LOG_MASTER" "$base_master" 60 || true)"
if [[ -z "$run_line" ]]; then
  echo "FAIL: timeout waiting for response_run_created invalid-user run" >&2
  debug_recent '"msg":"response_run_created".*"R-COLLECT-INVALID-USER"' "$LOG_MASTER"
  exit 1
fi
RUN_ID="$(printf "%s\n" "$run_line" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"
if [[ -z "$RUN_ID" ]]; then
  echo "FAIL: unable to extract run_id" >&2
  echo "$run_line" >&2
  exit 1
fi

if ! go run -mod=vendor ./cmd/master-roe-approve -config configs/master.yaml -run_id "$RUN_ID" -decision approve -actor khotso -reason "m55"; then
  echo "FAIL: approval command failed for run_id=${RUN_ID}" >&2
  exit 1
fi

step_pub_line="$(wait_in_tail "\"msg\":\"response_step_published\".*\"run_id\":\"${RUN_ID}\".*\"step_subject\":\"rsiem.response.steps.fast\".*\"action_type\":\"agent_command\"" "$LOG_MASTER" "$base_master" 60 || true)"
if [[ -z "$step_pub_line" ]]; then
  echo "FAIL: timeout waiting for FAST response_step_published for run_id=${RUN_ID}" >&2
  debug_recent "\"msg\":\"response_step_published\".*\"run_id\":\"${RUN_ID}\"|approval_received|approval_not_needed|response_run_waiting_approval" "$LOG_MASTER"
  exit 1
fi
STEP_ID="$(printf "%s\n" "$step_pub_line" | sed -n 's/.*"step_id":"\([^"]*\)".*/\1/p')"
if [[ -z "$STEP_ID" ]]; then
  echo "FAIL: unable to extract step_id from response_step_published" >&2
  echo "$step_pub_line" >&2
  exit 1
fi

pre_restart_received="$(tail_from "$LOG_WORKER" "$base_worker" | rg "\"msg\":\"step_received\".*\"run_id\":\"${RUN_ID}\"" | head -n 1 || true)"
if [[ -n "$pre_restart_received" ]]; then
  echo "FAIL: FAST step was consumed before FAST worker restart (worker still running)" >&2
  echo "$pre_restart_received" >&2
  debug_recent "\"msg\":\"step_received\".*\"run_id\":\"${RUN_ID}\"|step_failed_|step_succeeded" "$LOG_WORKER"
  exit 1
fi

if [[ "$AUTO_STOPPED" == "1" ]]; then
  echo "Starting FAST worker in background..."
  env GOCACHE="$(pwd)/.cache/go-build" go run -mod=vendor ./cmd/master-roe-worker --config configs/master.yaml -lane FAST >> "$LOG_WORKER" 2>&1 &
  STARTED_PID="$!"
  AUTO_STARTED=1
  sleep 1
  if ! kill -0 "$STARTED_PID" 2>/dev/null; then
    AUTO_STARTED=0
    echo "WARN: auto-start failed; start FAST worker manually now." >&2
    read -r -p "Start FAST worker manually, then press Enter." _
  fi
else
  read -r -p "Start FAST worker now, then press Enter." _
fi

step_received_line="$(wait_in_tail "\"msg\":\"step_received\".*\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\".*\"action_type\":\"agent_command\"" "$LOG_WORKER" "$base_worker" 60 || true)"
if [[ -z "$step_received_line" ]]; then
  echo "FAIL: timeout waiting for step_received run_id=${RUN_ID} step_id=${STEP_ID}" >&2
  debug_recent "\"msg\":\"step_received\".*\"run_id\":\"${RUN_ID}\"|step_failed_|step_succeeded" "$LOG_WORKER"
  exit 1
fi

step_succeeded_line="$(wait_in_tail "\"msg\":\"step_succeeded\".*\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\"" "$LOG_WORKER" "$base_worker" 60 || true)"
if [[ -z "$step_succeeded_line" ]]; then
  echo "FAIL: timeout waiting for step_succeeded run_id=${RUN_ID} step_id=${STEP_ID}" >&2
  debug_recent "\"msg\":\"step_received\".*\"run_id\":\"${RUN_ID}\"|step_failed_|step_succeeded" "$LOG_WORKER"
  exit 1
fi

agent_start_count="$(rg "\"msg\":\"agent_command_exec_start\".*\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\".*\"command_id\":\"ping\"" "$LOG_AGENT" | wc -l | tr -d ' ')"
if [[ "$agent_start_count" != "1" ]]; then
  echo "FAIL: expected exactly one agent_command_exec_start for run_id=${RUN_ID} step_id=${STEP_ID}, got ${agent_start_count}" >&2
  debug_recent "\"msg\":\"agent_command_exec_(start|done|denied)\".*\"run_id\":\"${RUN_ID}\"" "$LOG_AGENT"
  exit 1
fi

export_line="$(tail_from "$LOG_EXPORT" "$base_export" | rg "\"run_id\":\"${RUN_ID}\"" | rg '"\"action_type\":\"agent_command\"' | rg '"\"step_index\":0|\"step_index\":1' | rg '"\"status\":\"SUCCEEDED\"' | head -n 1 || true)"
if [[ -z "$export_line" ]]; then
  echo "FAIL: missing SUCCEEDED export line for run_id=${RUN_ID}" >&2
  tail_from "$LOG_EXPORT" "$base_export" | rg "\"run_id\":\"${RUN_ID}\"" | tail -n 20 >&2 || true
  exit 1
fi

echo "$trigger_line"
echo "$run_line"
echo "$step_pub_line"
echo "$step_received_line"
echo "$step_succeeded_line"
echo "$export_line"
echo "PASS: M55 fast lane queue correctness run_id=${RUN_ID} step_id=${STEP_ID} exec_start_count=${agent_start_count}"

if [[ "$AUTO_STARTED" == "1" ]]; then
  echo "INFO: fast worker auto-started with pid=${STARTED_PID}"
fi
