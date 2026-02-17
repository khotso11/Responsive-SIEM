#!/usr/bin/env bash
set -euo pipefail

LOG_COLLECTOR="logs/collector-tail.log"
LOG_DETECTOR="logs/detector-v0.log"
LOG_MASTER="logs/master-roe.log"
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

count_new_runs() {
  local base_master="$1"
  tail_from "$LOG_MASTER" "$base_master" | rg '"msg":"response_run_created".*"rule_id":"R-COUNT-PROCESS-HOST".*"playbook_id":"PB-COUNT-PROCESS-HOST"' | wc -l | tr -d ' '
}

count_new_triggers() {
  local base_detector="$1"
  tail_from "$LOG_DETECTOR" "$base_detector" | rg '"msg":"trigger_published".*"alert_key":"A-COUNT-PROCESS-HOST-' | wc -l | tr -d ' '
}

debug_recent() {
  local pattern="$1"
  local file="$2"
  echo "Context: last 10 relevant lines from ${file}:" >&2
  rg "$pattern" "$file" | tail -n 10 >&2 || true
}

echo "=== M50 count-process dedupe proof ==="

require_log "$LOG_COLLECTOR" "Terminal H (collector-tail)"
require_log "$LOG_DETECTOR" "Terminal I (detector-v0)"
require_log "$LOG_MASTER" "Terminal E (master-roe)"

mkdir -p tmp

base_detector="$(line_count "$LOG_DETECTOR")"
base_master="$(line_count "$LOG_MASTER")"

NOW="$(date +%s)"
HOST_A="m50-a-${NOW}"
HOST_B="m50-b-${NOW}"

echo "M42 process count host=${HOST_A} ts=${NOW} process_count=3" >> "$DEMO_LOG"

matched_a_1="$(wait_in_tail "\"msg\":\"rule_matched\".*\"rule_id\":\"R-COUNT-PROCESS-HOST\".*\"group_key\":\"${HOST_A}\"" "$LOG_DETECTOR" "$base_detector" 45 || true)"
if [[ -z "$matched_a_1" ]]; then
  echo "FAIL: timeout waiting for first rule_matched for host A (${HOST_A})" >&2
  debug_recent '"msg":"rule_matched".*"rule_id":"R-COUNT-PROCESS-HOST"' "$LOG_DETECTOR"
  exit 1
fi

trigger_1="$(wait_in_tail "\"msg\":\"trigger_published\".*\"alert_key\":\"A-COUNT-PROCESS-HOST-" "$LOG_DETECTOR" "$base_detector" 45 || true)"
if [[ -z "$trigger_1" ]]; then
  echo "FAIL: timeout waiting for first trigger_published for host A (${HOST_A})" >&2
  debug_recent '"msg":"trigger_published".*"alert_key":"A-COUNT-PROCESS-HOST-' "$LOG_DETECTOR"
  exit 1
fi

elapsed=0
while (( elapsed < 45 )); do
  if [[ "$(count_new_runs "$base_master")" == "1" ]]; then
    break
  fi
  sleep 1
  elapsed=$((elapsed + 1))
done
if [[ "$(count_new_runs "$base_master")" != "1" ]]; then
  echo "FAIL: expected exactly 1 process-count run after first host A trigger" >&2
  debug_recent '"msg":"response_run_created".*"rule_id":"R-COUNT-PROCESS-HOST"' "$LOG_MASTER"
  exit 1
fi

base_detector_phase2="$(line_count "$LOG_DETECTOR")"
echo "M42 process count host=${HOST_A} ts=$(date +%s) process_count=3" >> "$DEMO_LOG"

cooldown_a="$(wait_in_tail "\"msg\":\"cooldown_hit\".*\"rule_id\":\"R-COUNT-PROCESS-HOST\".*\"group_key\":\"${HOST_A}\"" "$LOG_DETECTOR" "$base_detector_phase2" 45 || true)"
if [[ -z "$cooldown_a" ]]; then
  echo "FAIL: timeout waiting for cooldown_hit for second host A trigger (${HOST_A})" >&2
  debug_recent '"msg":"cooldown_hit".*"rule_id":"R-COUNT-PROCESS-HOST"|msg":"detect_dedup_hit"' "$LOG_DETECTOR"
  exit 1
fi

triggers_after_second_a="$(count_new_triggers "$base_detector")"
if [[ "$triggers_after_second_a" != "1" ]]; then
  echo "FAIL: expected exactly 1 process-count trigger_published after two host A events, got ${triggers_after_second_a}" >&2
  debug_recent '"msg":"trigger_published".*"alert_key":"A-COUNT-PROCESS-HOST-' "$LOG_DETECTOR"
  exit 1
fi

runs_after_second_a="$(count_new_runs "$base_master")"
if [[ "$runs_after_second_a" != "1" ]]; then
  echo "FAIL: expected exactly 1 process-count run after second host A event, got ${runs_after_second_a}" >&2
  debug_recent '"msg":"response_run_created".*"rule_id":"R-COUNT-PROCESS-HOST"' "$LOG_MASTER"
  exit 1
fi

base_detector_phase3="$(line_count "$LOG_DETECTOR")"
echo "M42 process count host=${HOST_B} ts=$(date +%s) process_count=3" >> "$DEMO_LOG"

matched_b="$(wait_in_tail "\"msg\":\"rule_matched\".*\"rule_id\":\"R-COUNT-PROCESS-HOST\".*\"group_key\":\"${HOST_B}\"" "$LOG_DETECTOR" "$base_detector_phase3" 45 || true)"
if [[ -z "$matched_b" ]]; then
  echo "FAIL: timeout waiting for rule_matched for host B (${HOST_B})" >&2
  debug_recent '"msg":"rule_matched".*"rule_id":"R-COUNT-PROCESS-HOST"' "$LOG_DETECTOR"
  exit 1
fi

trigger_2="$(wait_in_tail "\"msg\":\"trigger_published\".*\"alert_key\":\"A-COUNT-PROCESS-HOST-" "$LOG_DETECTOR" "$base_detector_phase3" 45 || true)"
if [[ -z "$trigger_2" ]]; then
  echo "FAIL: timeout waiting for trigger_published for host B (${HOST_B})" >&2
  debug_recent '"msg":"trigger_published".*"alert_key":"A-COUNT-PROCESS-HOST-' "$LOG_DETECTOR"
  exit 1
fi

elapsed=0
while (( elapsed < 45 )); do
  if [[ "$(count_new_runs "$base_master")" == "2" ]]; then
    break
  fi
  sleep 1
  elapsed=$((elapsed + 1))
done
if [[ "$(count_new_runs "$base_master")" != "2" ]]; then
  echo "FAIL: expected exactly 2 process-count runs total in window (1 host A + 1 host B)" >&2
  debug_recent '"msg":"response_run_created".*"rule_id":"R-COUNT-PROCESS-HOST"' "$LOG_MASTER"
  exit 1
fi

run_lines="$(tail_from "$LOG_MASTER" "$base_master" | rg '"msg":"response_run_created".*"rule_id":"R-COUNT-PROCESS-HOST".*"playbook_id":"PB-COUNT-PROCESS-HOST"' || true)"
RUN_A="$(printf "%s\n" "$run_lines" | sed -n '1p' | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"
RUN_B="$(printf "%s\n" "$run_lines" | sed -n '2p' | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"

echo "$matched_a_1"
echo "$trigger_1"
echo "$cooldown_a"
echo "$matched_b"
echo "$trigger_2"
echo "$run_lines"
echo "PASS: M50 count-process dedupe proof host_a=${HOST_A} host_b=${HOST_B} run_a=${RUN_A} run_b=${RUN_B}"
