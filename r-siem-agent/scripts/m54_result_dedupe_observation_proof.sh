#!/usr/bin/env bash
set -euo pipefail

LOG_COLLECTOR="logs/collector-tail.log"
LOG_DETECTOR="logs/detector-v0.log"
LOG_MASTER="logs/master-roe.log"
LOG_AGENT="logs/agent.log"
LOG_EXPORT_PRIMARY="exports/roe_steps_latest.jsonl"
LOG_EXPORT_FALLBACK="exports/roe_steps.jsonl"
DEMO_LOG="tmp/demo.log"

RUN_ID=""
AGENT_STEP_ID=""
EXPORT_ROWS=""
base_detector=0
base_master=0
base_export=0

require_log() {
  local file="$1"
  local label="$2"
  if [[ ! -s "$file" ]]; then
    echo "FAIL: missing or empty ${file}. Start ${label} first."
    exit 1
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

wait_for() {
  local pattern="$1"
  local file="$2"
  local base="$3"
  local timeout_s="$4"
  local elapsed=0
  while (( elapsed < timeout_s )); do
    local match
    match="$(tail_from "$file" "$base" | rg "$pattern" | head -n 1 || true)"
    if [[ -n "$match" ]]; then
      echo "$match"
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  return 1
}

die() {
  local reason="$1"
  echo "FAIL: ${reason}"

  echo "Context: detector (new slice, last 40 relevant)"
  tail_from "$LOG_DETECTOR" "$base_detector" | rg 'R-COUNT-PROCESS-HOST|trigger_published|rule_matched' | tail -n 40 || true

  echo "Context: master (new slice, last 60 relevant)"
  tail_from "$LOG_MASTER" "$base_master" | rg 'response_run_created|response_step_result_received|response_result_duplicate|roe_lock_contended_result|R-COUNT-PROCESS-HOST' | tail -n 60 || true

  echo "Context: export rows found"
  if [[ -n "$EXPORT_ROWS" ]]; then
    printf "%s\n" "$EXPORT_ROWS" | tail -n 60
  else
    echo "(none)"
  fi

  echo "Context: agent exec lines for run"
  if [[ -n "$RUN_ID" ]]; then
    rg "\"run_id\":\"${RUN_ID}\".*\"msg\":\"agent_command_exec_(start|done|denied)\"" "$LOG_AGENT" | tail -n 40 || true
  else
    echo "(run_id not available)"
  fi

  exit 1
}

echo "=== M54 result dedupe observation proof ==="

require_log "$LOG_COLLECTOR" "Terminal H (collector-tail)"
require_log "$LOG_DETECTOR" "Terminal I (detector-v0)"
require_log "$LOG_MASTER" "Terminal E (master-roe)"
require_log "$LOG_AGENT" "Terminal G (agent)"

EXPORT_FILE="$LOG_EXPORT_PRIMARY"
if [[ ! -f "$EXPORT_FILE" ]]; then
  EXPORT_FILE="$LOG_EXPORT_FALLBACK"
fi
if [[ ! -f "$EXPORT_FILE" ]]; then
  die "missing export file (checked ${LOG_EXPORT_PRIMARY} and ${LOG_EXPORT_FALLBACK})"
fi

mkdir -p tmp

base_detector="$(line_count "$LOG_DETECTOR")"
base_master="$(line_count "$LOG_MASTER")"
base_export="$(line_count "$EXPORT_FILE")"

NOW="$(date +%s)"
echo "M42 process count host=m54-${NOW} ts=${NOW} process_count=3" >> "$DEMO_LOG"

trigger_line="$(wait_for "\"msg\":\"trigger_published\".*\"alert_key\":\"A-COUNT-PROCESS-HOST-" "$LOG_DETECTOR" "$base_detector" 60 || true)"
if [[ -z "$trigger_line" ]]; then
  die "timeout waiting for detector trigger_published A-COUNT-PROCESS-HOST"
fi

run_line="$(wait_for "\"msg\":\"response_run_created\".*\"rule_id\":\"R-COUNT-PROCESS-HOST\".*\"playbook_id\":\"PB-COUNT-PROCESS-HOST\"" "$LOG_MASTER" "$base_master" 60 || true)"
if [[ -z "$run_line" ]]; then
  die "timeout waiting for master response_run_created for R-COUNT-PROCESS-HOST/PB-COUNT-PROCESS-HOST"
fi
RUN_ID="$(printf "%s\n" "$run_line" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"
if [[ -z "$RUN_ID" ]]; then
  die "unable to extract run_id from response_run_created"
fi

elapsed=0
notify0_line=""
agent1_line=""
notify2_line=""
unique_succeeded_count="0"
while (( elapsed < 60 )); do
  EXPORT_ROWS="$(tail_from "$EXPORT_FILE" "$base_export" | rg "\"run_id\":\"${RUN_ID}\"" | rg '"msg":"response_step_result"' | rg '"status":"SUCCEEDED"' || true)"
  unique_succeeded_count="$(printf "%s\n" "$EXPORT_ROWS" | sed -n 's/.*"step_key":"\([^"]*\)".*/\1/p' | sort -u | awk 'NF>0' | wc -l | tr -d ' ')"
  notify0_line="$(printf "%s\n" "$EXPORT_ROWS" | rg '"action_type":"notify"' | rg '"step_index":0' | head -n 1 || true)"
  agent1_line="$(printf "%s\n" "$EXPORT_ROWS" | rg '"action_type":"agent_command"' | rg '"step_index":1' | head -n 1 || true)"
  notify2_line="$(printf "%s\n" "$EXPORT_ROWS" | rg '"action_type":"notify"' | rg '"step_index":2' | head -n 1 || true)"
  if [[ "$unique_succeeded_count" == "3" && -n "$notify0_line" && -n "$agent1_line" && -n "$notify2_line" ]]; then
    break
  fi
  sleep 1
  elapsed=$((elapsed + 1))
done

if [[ "$unique_succeeded_count" != "3" || -z "$notify0_line" || -z "$agent1_line" || -z "$notify2_line" ]]; then
  die "expected exactly 3 unique SUCCEEDED step results (idx0 notify, idx1 agent_command, idx2 notify), got unique=${unique_succeeded_count}"
fi

AGENT_STEP_ID="$(printf "%s\n" "$agent1_line" | sed -n 's/.*"step_id":"\([^"]*\)".*/\1/p')"
if [[ -z "$AGENT_STEP_ID" ]]; then
  die "unable to extract agent_command step_id from export row"
fi

master_rows_for_run="$(tail_from "$LOG_MASTER" "$base_master" | rg "\"run_id\":\"${RUN_ID}\"" || true)"
result_received_rows="$(printf "%s\n" "$master_rows_for_run" | rg '"msg":"response_step_result_received"' || true)"
dup_key_rows="$(printf "%s\n" "$master_rows_for_run" | rg '"msg":"response_result_duplicate"' || true)"
contend_rows="$(printf "%s\n" "$master_rows_for_run" | rg '"msg":"roe_lock_contended_result"' || true)"

result_received_count="$(printf "%s\n" "$result_received_rows" | rg -c 'response_step_result_received' || true)"
result_unique_step_count="$(printf "%s\n" "$result_received_rows" | sed -n 's/.*"step_id":"\([^"]*\)".*/\1/p' | sort -u | awk 'NF>0' | wc -l | tr -d ' ')"
dup_key_count="$(printf "%s\n" "$dup_key_rows" | rg -c 'response_result_duplicate' || true)"
contend_count="$(printf "%s\n" "$contend_rows" | rg -c 'roe_lock_contended_result' || true)"

if (( result_received_count < 6 )); then
  die "expected duplicate receptions this run (response_step_result_received_count>=6), got ${result_received_count}"
fi
if (( dup_key_count == 0 && contend_count == 0 )); then
  die "no duplicate indicators found (need response_result_duplicate or roe_lock_contended_result)"
fi

exec_start_count="$(rg "\"msg\":\"agent_command_exec_start\".*\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${AGENT_STEP_ID}\"" "$LOG_AGENT" | wc -l | tr -d ' ')"
if [[ "$exec_start_count" != "1" ]]; then
  die "expected exactly one agent_command_exec_start for run_id=${RUN_ID} step_id=${AGENT_STEP_ID}, got ${exec_start_count}"
fi

echo "$trigger_line"
echo "$run_line"
echo "$notify0_line"
echo "$agent1_line"
echo "$notify2_line"
echo "duplicates_observation: response_step_result_received_count=${result_received_count} unique_step_ids=${result_unique_step_count} response_result_duplicate_count=${dup_key_count} roe_lock_contended_result_count=${contend_count}"
echo "PASS: M54 result dedupe observation proof run_id=${RUN_ID} dup_received=${result_received_count} dup_key=${dup_key_count} exec_start_count=1"
exit 0
