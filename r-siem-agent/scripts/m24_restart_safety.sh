#!/usr/bin/env bash
set -euo pipefail

LOG_MASTER="logs/master-roe.log"
LOG_WORKER="logs/roe-worker.log"
LOG_AGENT="logs/agent.log"
LOG_COLLECTOR="logs/collector-tail.log"
LOG_DETECTOR="logs/detector-v0.log"
DEMO_LOG="tmp/demo.log"

require_log() {
  local file="$1"
  local label="$2"
  if [[ ! -s "$file" ]]; then
    echo "FAIL: missing or empty ${file}. Start Terminal ${label} first." >&2
    exit 2
  fi
}

last_line_num() {
  local pattern="$1"
  local file="$2"
  local last
  last="$(rg -n "$pattern" "$file" | tail -n 1 || true)"
  if [[ -z "$last" ]]; then
    echo 0
    return
  fi
  echo "${last%%:*}"
}

wait_in_slice() {
  local pattern="$1"
  local file="$2"
  local start_line="$3"
  local span="$4"
  local max_wait="$5"
  local elapsed=0
  while (( elapsed < max_wait )); do
    if (( start_line < 1 )); then
      start_line=1
    fi
    local end_line=$((start_line + span))
    local slice
    slice="$(sed -n "${start_line},${end_line}p" "$file" | nl -ba -v "$start_line" -s ":")"
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

echo "=== M24 restart-safety proof ==="

require_log "$LOG_MASTER" "E (master-roe)"
require_log "$LOG_WORKER" "F (roe-worker)"
require_log "$LOG_AGENT" "G (agent)"
require_log "$LOG_COLLECTOR" "H (collector-tail)"
require_log "$LOG_DETECTOR" "I (detector-v0)"

mkdir -p logs tmp

baseline_waiting="$(last_line_num '"msg":"response_run_waiting_approval"' "$LOG_MASTER")"
baseline_step_received="$(last_line_num '"msg":"step_received"' "$LOG_WORKER")"
baseline_agent_start="$(last_line_num '"msg":"agent_command_exec_start"' "$LOG_AGENT")"
baseline_step_result="$(last_line_num '"msg":"response_step_result_received"' "$LOG_MASTER")"

octet=$(( ( $(date +%s) % 200 ) + 1 ))
echo "M24 invalid user from 10.0.0.${octet} ts=$(date +%s)" >> "$DEMO_LOG"
echo "Published invalid-user event to trigger approval-gated run."

read -r -p "Stop worker terminal now (Terminal F, Ctrl+C). Press Enter when stopped." _

waiting_line="$(wait_in_slice '"msg":"response_run_waiting_approval"' "$LOG_MASTER" "$((baseline_waiting + 1))" 500 45 || true)"
if [[ -z "$waiting_line" ]]; then
  echo "FAIL: timeout waiting for response_run_waiting_approval" >&2
  debug_recent '"msg":"response_run_waiting_approval"' "$LOG_MASTER"
  exit 1
fi

RUN_ID="$(printf "%s\n" "$waiting_line" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"
if [[ -z "$RUN_ID" ]]; then
  echo "FAIL: unable to extract run_id from response_run_waiting_approval" >&2
  echo "$waiting_line" >&2
  exit 1
fi

echo "$waiting_line"
echo "run_id: ${RUN_ID}"
APPROVAL_CMD="nats pub rsiem.response.approvals '{\"run_id\":\"${RUN_ID}\",\"decision\":\"approve\",\"actor\":\"khotso\",\"reason\":\"lab approval\"}'"
echo "Manual approval command:"
echo "${APPROVAL_CMD}"
read -r -p "Run the approval command in another terminal, then press Enter." _

read -r -p "Start worker terminal again (Terminal F). Press Enter when it is running." _

step_received_line="$(wait_in_slice "\"msg\":\"step_received\".*\"run_id\":\"${RUN_ID}\"" "$LOG_WORKER" "$((baseline_step_received + 1))" 500 60 || true)"
if [[ -z "$step_received_line" ]]; then
  echo "FAIL: timeout waiting for worker step_received run_id=${RUN_ID}" >&2
  debug_recent "\"msg\":\"step_received\".*\"run_id\":\"${RUN_ID}\"" "$LOG_WORKER"
  exit 1
fi

STEP_ID="$(printf "%s\n" "$step_received_line" | sed -n 's/.*"step_id":"\([^"]*\)".*/\1/p')"
if [[ -z "$STEP_ID" ]]; then
  echo "FAIL: unable to extract step_id from worker step_received" >&2
  echo "$step_received_line" >&2
  exit 1
fi

agent_start_line="$(wait_in_slice "\"msg\":\"agent_command_exec_start\".*\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\"" "$LOG_AGENT" "$((baseline_agent_start + 1))" 500 60 || true)"
if [[ -z "$agent_start_line" ]]; then
  echo "FAIL: timeout waiting for agent_command_exec_start run_id=${RUN_ID} step_id=${STEP_ID}" >&2
  debug_recent "\"msg\":\"agent_command_exec_start\".*\"run_id\":\"${RUN_ID}\"" "$LOG_AGENT"
  exit 1
fi

step_result_line="$(wait_in_slice "\"msg\":\"response_step_result_received\".*\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\".*\"status\":\"SUCCEEDED\"" "$LOG_MASTER" "$((baseline_step_result + 1))" 700 60 || true)"
if [[ -z "$step_result_line" ]]; then
  echo "FAIL: timeout waiting for response_step_result_received SUCCEEDED run_id=${RUN_ID} step_id=${STEP_ID}" >&2
  debug_recent "\"msg\":\"response_step_result_received\".*\"run_id\":\"${RUN_ID}\"" "$LOG_MASTER"
  exit 1
fi

worker_count="$(rg "\"msg\":\"step_received\".*\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\"" "$LOG_WORKER" | wc -l | tr -d ' ')"
agent_count="$(rg "\"msg\":\"agent_command_exec_start\".*\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\"" "$LOG_AGENT" | wc -l | tr -d ' ')"
master_success_count="$(rg "\"msg\":\"response_step_result_received\".*\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\".*\"status\":\"SUCCEEDED\"" "$LOG_MASTER" | wc -l | tr -d ' ')"

if [[ "$worker_count" != "1" ]]; then
  echo "FAIL: expected exactly one worker step_received for run_id=${RUN_ID} step_id=${STEP_ID}, got ${worker_count}" >&2
  debug_recent "\"msg\":\"step_received\".*\"run_id\":\"${RUN_ID}\"" "$LOG_WORKER"
  exit 1
fi
if [[ "$agent_count" != "1" ]]; then
  echo "FAIL: expected exactly one agent_command_exec_start for run_id=${RUN_ID} step_id=${STEP_ID}, got ${agent_count}" >&2
  debug_recent "\"msg\":\"agent_command_exec_start\".*\"run_id\":\"${RUN_ID}\"" "$LOG_AGENT"
  exit 1
fi
if [[ "$master_success_count" != "1" ]]; then
  echo "FAIL: expected exactly one response_step_result_received SUCCEEDED for run_id=${RUN_ID} step_id=${STEP_ID}, got ${master_success_count}" >&2
  debug_recent "\"msg\":\"response_step_result_received\".*\"run_id\":\"${RUN_ID}\"" "$LOG_MASTER"
  exit 1
fi

echo "$step_received_line"
echo "$agent_start_line"
echo "$step_result_line"
echo "PASS: M24 restart-safety proof run_id=${RUN_ID} step_id=${STEP_ID}"
