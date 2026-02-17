#!/usr/bin/env bash
set -euo pipefail

LOG_COLLECTOR="logs/collector-tail.log"
LOG_DETECTOR="logs/detector-v0.log"
LOG_MASTER="logs/master-roe.log"
LOG_WORKER="logs/roe-worker.log"
LOG_AGENT="logs/agent.log"
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
  local max_lines="${3:-120}"
  echo "Context: last ${max_lines} relevant lines from ${file}:" >&2
  rg "$pattern" "$file" | tail -n "$max_lines" >&2 || true
}

echo "=== M57 approval timeout proof ==="

require_log "$LOG_COLLECTOR" "Terminal H (collector-tail)"
require_log "$LOG_DETECTOR" "Terminal I (detector-v0)"
require_log "$LOG_MASTER" "Terminal E (master-roe)"
require_log "$LOG_WORKER" "Terminal F (roe-worker)"
require_log "$LOG_AGENT" "Terminal G (agent)"

mkdir -p tmp

base_detector="$(line_count "$LOG_DETECTOR")"
base_master="$(line_count "$LOG_MASTER")"
base_worker="$(line_count "$LOG_WORKER")"
base_agent="$(line_count "$LOG_AGENT")"

NOW="$(date +%s)"
octet=$(( (NOW % 180) + 20 ))
echo "M57 invalid user from 10.0.0.${octet} ts=${NOW}" >> "$DEMO_LOG"

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

waiting_line="$(wait_in_tail "\"msg\":\"response_run_waiting_approval\".*\"run_id\":\"${RUN_ID}\"" "$LOG_MASTER" "$base_master" 60 || true)"
if [[ -z "$waiting_line" ]]; then
  echo "FAIL: timeout waiting for response_run_waiting_approval run_id=${RUN_ID}" >&2
  debug_recent "\"msg\":\"response_run_waiting_approval\"|approval_requested|approval_timed_out" "$LOG_MASTER"
  exit 1
fi

timeout_ms="$(printf "%s\n" "$waiting_line" | sed -n 's/.*"timeout_ms":\([0-9]\+\).*/\1/p')"
if [[ -z "$timeout_ms" ]]; then
  timeout_ms="300000"
fi
timeout_wait_s=$(( (timeout_ms + 5000) / 1000 ))
if (( timeout_wait_s < 5 )); then
  timeout_wait_s=5
fi

echo "Waiting for timeout: run_id=${RUN_ID} timeout_ms=${timeout_ms} (wait_s=${timeout_wait_s})"
elapsed=0
while (( elapsed < timeout_wait_s )); do
  if (( elapsed % 30 == 0 )); then
    echo "  ...elapsed ${elapsed}s/${timeout_wait_s}s"
  fi
  sleep 1
  elapsed=$((elapsed + 1))
done

timed_out_line="$(wait_in_tail "\"msg\":\"approval_timed_out\".*\"run_id\":\"${RUN_ID}\"" "$LOG_MASTER" "$base_master" 20 || true)"
if [[ -z "$timed_out_line" ]]; then
  echo "FAIL: approval_timed_out not observed for run_id=${RUN_ID}" >&2
  debug_recent "\"msg\":\"response_run_waiting_approval\"|\"msg\":\"approval_timed_out\"|\"msg\":\"approval_not_needed\"|\"msg\":\"response_step_published\"" "$LOG_MASTER"
  exit 1
fi

pre_late_step_count="$(tail_from "$LOG_MASTER" "$base_master" | rg -c "\"msg\":\"response_step_published\".*\"run_id\":\"${RUN_ID}\"" || true)"
if [[ "$pre_late_step_count" != "0" ]]; then
  echo "FAIL: step published before late approval despite timeout run_id=${RUN_ID}" >&2
  debug_recent "\"msg\":\"response_step_published\".*\"run_id\":\"${RUN_ID}\"|\"msg\":\"approval_timed_out\".*\"run_id\":\"${RUN_ID}\"" "$LOG_MASTER"
  exit 1
fi

if ! go run -mod=vendor ./cmd/master-roe-approve -config configs/master.yaml -run_id "$RUN_ID" -decision approve -actor khotso -reason "m57 late approval"; then
  echo "FAIL: late approval command failed run_id=${RUN_ID}" >&2
  exit 1
fi

approval_received_line="$(wait_in_tail "\"msg\":\"approval_received\".*\"run_id\":\"${RUN_ID}\"" "$LOG_MASTER" "$base_master" 20 || true)"
if [[ -z "$approval_received_line" ]]; then
  echo "FAIL: late approval_received not observed run_id=${RUN_ID}" >&2
  debug_recent "\"msg\":\"approval_received\"|\"msg\":\"approval_not_needed\".*\"run_id\":\"${RUN_ID}\"" "$LOG_MASTER"
  exit 1
fi

not_needed_line="$(wait_in_tail "\"msg\":\"approval_not_needed\".*\"run_id\":\"${RUN_ID}\".*\"status\":\"FAILED_SAFE\"" "$LOG_MASTER" "$base_master" 20 || true)"
if [[ -z "$not_needed_line" ]]; then
  echo "FAIL: approval_not_needed status FAILED_SAFE not observed after late approval run_id=${RUN_ID}" >&2
  debug_recent "\"msg\":\"approval_not_needed\".*\"run_id\":\"${RUN_ID}\"|\"msg\":\"approval_received\".*\"run_id\":\"${RUN_ID}\"" "$LOG_MASTER"
  exit 1
fi

post_late_step_count="$(tail_from "$LOG_MASTER" "$base_master" | rg -c "\"msg\":\"response_step_published\".*\"run_id\":\"${RUN_ID}\"" || true)"
worker_step_count="$(tail_from "$LOG_WORKER" "$base_worker" | rg -c "\"msg\":\"step_received\".*\"run_id\":\"${RUN_ID}\"" || true)"
agent_exec_count="$(tail_from "$LOG_AGENT" "$base_agent" | rg -c "\"msg\":\"agent_command_exec_start\".*\"run_id\":\"${RUN_ID}\"" || true)"
if [[ "$post_late_step_count" != "0" || "$worker_step_count" != "0" || "$agent_exec_count" != "0" ]]; then
  echo "FAIL: late approval caused execution for timed-out run_id=${RUN_ID} (step_published=${post_late_step_count} step_received=${worker_step_count} exec_start=${agent_exec_count})" >&2
  debug_recent "\"msg\":\"response_step_published\".*\"run_id\":\"${RUN_ID}\"|\"msg\":\"approval_\".*\"run_id\":\"${RUN_ID}\"|\"msg\":\"approval_timed_out\".*\"run_id\":\"${RUN_ID}\"" "$LOG_MASTER"
  debug_recent "\"msg\":\"step_received\"|\"msg\":\"step_succeeded\"|\"msg\":\"step_failed_\".*\"run_id\":\"${RUN_ID}\"" "$LOG_WORKER"
  debug_recent "\"msg\":\"agent_command_exec_(start|done|denied)\".*\"run_id\":\"${RUN_ID}\"" "$LOG_AGENT"
  exit 1
fi

echo "$trigger_line"
echo "$run_line"
echo "$waiting_line"
echo "$timed_out_line"
echo "$approval_received_line"
echo "$not_needed_line"
echo "PASS: M57 approval timeout proof run_id=${RUN_ID} timeout_ms=${timeout_ms}"
