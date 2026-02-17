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
    local slice
    slice="$(tail_from "$file" "$baseline_count")"
    local match
    match="$(printf "%s\n" "$slice" | rg "$pattern" | head -n 1 || true)"
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
  echo "Context: last 10 relevant lines from ${file}:" >&2
  rg "$pattern" "$file" | tail -n 10 >&2 || true
}

find_standard_worker_pids() {
  ps -eo pid=,args= | rg 'master-roe-worker' | rg '\-lane STANDARD' | awk '{print $1}' || true
}

echo "=== M51 standard lane queue correctness v2 ==="

require_log "$LOG_COLLECTOR" "Terminal H (collector-tail)"
require_log "$LOG_DETECTOR" "Terminal I (detector-v0)"
require_log "$LOG_MASTER" "Terminal E (master-roe)"
require_log "$LOG_WORKER" "Terminal F standard worker log (roe-worker)"
require_log "$LOG_AGENT" "Terminal G (agent)"
require_log "$LOG_EXPORT" "exports/roe_steps_latest.jsonl"

mkdir -p tmp logs

AUTO_STOPPED=0
AUTO_STARTED=0
STARTED_PID=""

standard_pids="$(find_standard_worker_pids)"
if [[ -n "$standard_pids" ]]; then
  AUTO_STOPPED=1
  echo "Detected STANDARD worker process IDs: ${standard_pids}"
  echo "$standard_pids" | xargs -r kill
  sleep 1
  still_running="$(find_standard_worker_pids)"
  if [[ -n "$still_running" ]]; then
    echo "FAIL: unable to stop STANDARD worker PIDs: ${still_running}" >&2
    exit 1
  fi
else
  echo "No dedicated STANDARD worker process with '-lane STANDARD' detected."
  read -r -p "Stop STANDARD worker manually now, then press Enter." _
fi

base_detector="$(line_count "$LOG_DETECTOR")"
base_master="$(line_count "$LOG_MASTER")"
base_worker="$(line_count "$LOG_WORKER")"
base_agent="$(line_count "$LOG_AGENT")"
base_export="$(line_count "$LOG_EXPORT")"

NOW="$(date +%s)"
HOST_ID="m51-${NOW}"
echo "M42 process count host=${HOST_ID} ts=${NOW} process_count=3" >> "$DEMO_LOG"

trigger_line="$(wait_in_tail "\"msg\":\"trigger_published\".*\"alert_key\":\"A-COUNT-PROCESS-HOST-" "$LOG_DETECTOR" "$base_detector" 45 || true)"
if [[ -z "$trigger_line" ]]; then
  echo "FAIL: timeout waiting for detector trigger_published for M51 host=${HOST_ID}" >&2
  debug_recent '"msg":"rule_matched"|"msg":"trigger_published"' "$LOG_DETECTOR"
  exit 1
fi

run_line="$(wait_in_tail "\"msg\":\"response_run_created\".*\"rule_id\":\"R-COUNT-PROCESS-HOST\".*\"playbook_id\":\"PB-COUNT-PROCESS-HOST\"" "$LOG_MASTER" "$base_master" 45 || true)"
if [[ -z "$run_line" ]]; then
  echo "FAIL: timeout waiting for response_run_created for process-count run" >&2
  debug_recent '"msg":"response_run_created".*"rule_id":"R-COUNT-PROCESS-HOST"' "$LOG_MASTER"
  exit 1
fi
RUN_ID="$(printf "%s\n" "$run_line" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"
if [[ -z "$RUN_ID" ]]; then
  echo "FAIL: unable to extract run_id from response_run_created line" >&2
  echo "$run_line" >&2
  exit 1
fi

wait_line="$(wait_in_tail "\"msg\":\"response_run_waiting_approval\".*\"run_id\":\"${RUN_ID}\"" "$LOG_MASTER" "$base_master" 6 || true)"
if [[ -n "$wait_line" ]]; then
  echo "$wait_line"
  if ! go run -mod=vendor ./cmd/master-roe-approve -config configs/master.yaml -run_id "$RUN_ID" -decision approve -actor khotso -reason "m51 queue correctness"; then
    echo "FAIL: approval command failed for run_id=${RUN_ID}" >&2
    exit 1
  fi
fi

step_pub_line="$(wait_in_tail "\"msg\":\"response_step_published\".*\"run_id\":\"${RUN_ID}\".*\"action_type\":\"agent_command\".*\"step_subject\":\"rsiem.response.steps.standard\"" "$LOG_MASTER" "$base_master" 45 || true)"
if [[ -z "$step_pub_line" ]]; then
  echo "FAIL: timeout waiting for STANDARD agent_command step publication for run_id=${RUN_ID}" >&2
  debug_recent "\"msg\":\"response_step_published\".*\"run_id\":\"${RUN_ID}\"" "$LOG_MASTER"
  exit 1
fi
STEP_ID="$(printf "%s\n" "$step_pub_line" | sed -n 's/.*"step_id":"\([^"]*\)".*/\1/p')"
if [[ -z "$STEP_ID" ]]; then
  echo "FAIL: unable to extract agent_command step_id for run_id=${RUN_ID}" >&2
  echo "$step_pub_line" >&2
  exit 1
fi

sleep 2
pre_restart_received="$(tail_from "$LOG_WORKER" "$base_worker" | rg "\"msg\":\"step_received\".*\"run_id\":\"${RUN_ID}\"" | head -n 1 || true)"
if [[ -n "$pre_restart_received" ]]; then
  echo "FAIL: standard worker consumed queued step before restart (worker still running)" >&2
  echo "$pre_restart_received" >&2
  debug_recent "\"msg\":\"step_received\".*\"run_id\":\"${RUN_ID}\"" "$LOG_WORKER"
  exit 1
fi

if [[ "$AUTO_STOPPED" == "1" ]]; then
  echo "Starting STANDARD worker in background for resume phase..."
  mkdir -p .cache/go-build
  env GOCACHE="$(pwd)/.cache/go-build" go run -mod=vendor ./cmd/master-roe-worker --config configs/master.yaml -lane STANDARD >> "$LOG_WORKER" 2>&1 &
  STARTED_PID="$!"
  AUTO_STARTED=1
  sleep 1
  if ! kill -0 "$STARTED_PID" 2>/dev/null; then
    AUTO_STARTED=0
    echo "WARN: auto-start failed; start STANDARD worker manually now." >&2
    read -r -p "Start STANDARD worker manually, then press Enter." _
  fi
else
  read -r -p "Start STANDARD worker now, then press Enter." _
fi

step_received_line="$(wait_in_tail "\"msg\":\"step_received\".*\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\".*\"action_type\":\"agent_command\"" "$LOG_WORKER" "$base_worker" 60 || true)"
if [[ -z "$step_received_line" ]]; then
  echo "FAIL: timeout waiting for worker step_received run_id=${RUN_ID} step_id=${STEP_ID}" >&2
  debug_recent "\"msg\":\"step_received\".*\"run_id\":\"${RUN_ID}\"" "$LOG_WORKER"
  debug_recent "\"msg\":\"response_step_published\".*\"run_id\":\"${RUN_ID}\"" "$LOG_MASTER"
  exit 1
fi

step_succeeded_line="$(wait_in_tail "\"msg\":\"step_succeeded\".*\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\"" "$LOG_WORKER" "$base_worker" 60 || true)"
if [[ -z "$step_succeeded_line" ]]; then
  echo "FAIL: timeout waiting for worker step_succeeded run_id=${RUN_ID} step_id=${STEP_ID}" >&2
  debug_recent "\"msg\":\"step_succeeded\"|\"msg\":\"step_failed_safe\"|\"msg\":\"step_failed_transient\"" "$LOG_WORKER"
  debug_recent "\"msg\":\"response_step_result_received\".*\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\"" "$LOG_MASTER"
  debug_recent "\"msg\":\"agent_command_exec_start\"|\"msg\":\"agent_command_exec_denied\"" "$LOG_AGENT"
  exit 1
fi

agent_start_line="$(wait_in_tail "\"msg\":\"agent_command_exec_start\".*\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\".*\"command_id\":\"ping\"" "$LOG_AGENT" "$base_agent" 60 || true)"
if [[ -z "$agent_start_line" ]]; then
  echo "FAIL: timeout waiting for agent_command_exec_start command_id=ping run_id=${RUN_ID} step_id=${STEP_ID}" >&2
  debug_recent "\"msg\":\"agent_command_exec_start\"|\"msg\":\"agent_command_exec_denied\"" "$LOG_AGENT"
  exit 1
fi

exec_start_count="$(rg "\"msg\":\"agent_command_exec_start\".*\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\".*\"command_id\":\"ping\"" "$LOG_AGENT" | wc -l | tr -d ' ')"
if [[ "$exec_start_count" != "1" ]]; then
  echo "FAIL: expected exactly one agent_command_exec_start for run_id=${RUN_ID} step_id=${STEP_ID}, got ${exec_start_count}" >&2
  debug_recent "\"msg\":\"agent_command_exec_start\".*\"run_id\":\"${RUN_ID}\"" "$LOG_AGENT"
  exit 1
fi

export_slice="$(tail_from "$LOG_EXPORT" "$base_export" | rg "\"run_id\":\"${RUN_ID}\"" || true)"
agent_export_line="$(printf "%s\n" "$export_slice" | rg "\"action_type\":\"agent_command\"" | rg "\"step_id\":\"${STEP_ID}\"" | rg "\"status\":\"SUCCEEDED\"" | tail -n 1 || true)"
notify0_export_line="$(printf "%s\n" "$export_slice" | rg "\"action_type\":\"notify\"" | rg "\"step_index\":0" | rg "\"status\":\"SUCCEEDED\"" | tail -n 1 || true)"
notify2_export_line="$(printf "%s\n" "$export_slice" | rg "\"action_type\":\"notify\"" | rg "\"step_index\":2" | rg "\"status\":\"SUCCEEDED\"" | tail -n 1 || true)"
if [[ -z "$agent_export_line" || -z "$notify0_export_line" || -z "$notify2_export_line" ]]; then
  echo "FAIL: expected SUCCEEDED export rows for agent_command and notify steps, run_id=${RUN_ID}" >&2
  echo "Context: export rows for run_id=${RUN_ID}:" >&2
  printf "%s\n" "$export_slice" | tail -n 10 >&2
  debug_recent "\"msg\":\"response_step_result_received\".*\"run_id\":\"${RUN_ID}\"" "$LOG_MASTER"
  debug_recent "\"msg\":\"step_received\"|\"msg\":\"step_succeeded\"|\"msg\":\"step_failed_safe\"|\"msg\":\"step_failed_transient\"" "$LOG_WORKER"
  debug_recent "\"msg\":\"agent_command_exec_denied\"|\"msg\":\"agent_command_exec_start\"|\"msg\":\"agent_command_exec_done\"" "$LOG_AGENT"
  exit 1
fi

echo "$trigger_line"
echo "$run_line"
echo "$step_pub_line"
echo "$step_received_line"
echo "$step_succeeded_line"
echo "$agent_start_line"
echo "$agent_export_line"
echo "$notify0_export_line"
echo "$notify2_export_line"
echo "PASS: M51 standard lane queue correctness v2 run_id=${RUN_ID} step_id=${STEP_ID} exec_start_count=${exec_start_count}"

if [[ "$AUTO_STARTED" == "1" ]]; then
  echo "INFO: standard worker auto-started with pid=${STARTED_PID}"
fi
