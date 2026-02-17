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

line_count() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    echo 0
    return
  fi
  wc -l < "$file" | tr -d ' '
}

wait_in_tail() {
  local pattern="$1"
  local file="$2"
  local baseline_count="$3"
  local max_wait="$4"
  local elapsed=0
  while (( elapsed < max_wait )); do
    local slice
    slice="$(tail -n +"$((baseline_count + 1))" "$file" 2>/dev/null || true)"
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

count_new_runs_since() {
  local baseline_count="$1"
  local slice
  slice="$(tail -n +"$((baseline_count + 1))" "$LOG_MASTER" 2>/dev/null || true)"
  printf "%s\n" "$slice" | rg '"msg":"response_run_created".*"rule_id":"R-COLLECT-INVALID-USER".*"playbook_id":"PB-AGENT-PING-LOCALHOST"' | wc -l | tr -d ' '
}

debug_recent() {
  local pattern="$1"
  local file="$2"
  echo "Context: last 10 relevant lines from ${file}:" >&2
  rg "$pattern" "$file" | tail -n 10 >&2 || true
}

echo "=== M44 cooldown + dedupe proof ==="

require_log "$LOG_COLLECTOR" "H (collector-tail)"
require_log "$LOG_DETECTOR" "I (detector-v0)"
require_log "$LOG_MASTER" "E (master-roe)"

mkdir -p tmp

NOW="$(date +%s)"
octet_a=$(( (NOW % 180) + 20 ))
octet_b=$((octet_a + 1))
if (( octet_b > 254 )); then
  octet_b=20
fi
IP_A="10.0.0.${octet_a}"
IP_B="10.0.0.${octet_b}"

base_detector_1="$(line_count "$LOG_DETECTOR")"
base_master_1="$(line_count "$LOG_MASTER")"

echo "M44 invalid user from ${IP_A} ts=$(date +%s)" >> "$DEMO_LOG"

first_trigger_line="$(wait_in_tail "\"msg\":\"trigger_published\".*\"alert_key\":\"A-COLLECT-INVALID-USER-" "$LOG_DETECTOR" "$base_detector_1" 60 || true)"
if [[ -z "$first_trigger_line" ]]; then
  echo "FAIL: timeout waiting for first trigger_published for IP_A=${IP_A}" >&2
  debug_recent '"msg":"trigger_published"|"msg":"rule_matched"' "$LOG_DETECTOR"
  exit 1
fi

rule_matched_a_line="$(wait_in_tail "\"msg\":\"rule_matched\".*\"rule_id\":\"R-COLLECT-INVALID-USER\".*\"group_key\":\"${IP_A}\"" "$LOG_DETECTOR" "$base_detector_1" 60 || true)"
if [[ -z "$rule_matched_a_line" ]]; then
  echo "FAIL: timeout waiting for rule_matched for IP_A=${IP_A}" >&2
  debug_recent '"msg":"rule_matched".*"rule_id":"R-COLLECT-INVALID-USER"' "$LOG_DETECTOR"
  exit 1
fi

elapsed=0
runs_after_first=0
while (( elapsed < 60 )); do
  runs_after_first="$(count_new_runs_since "$base_master_1")"
  if [[ "$runs_after_first" == "1" ]]; then
    break
  fi
  sleep 1
  elapsed=$((elapsed + 1))
done
if [[ "$runs_after_first" != "1" ]]; then
  echo "FAIL: expected exactly 1 new invalid-user run after first IP_A trigger, got ${runs_after_first}" >&2
  debug_recent '"msg":"response_run_created".*"rule_id":"R-COLLECT-INVALID-USER"' "$LOG_MASTER"
  exit 1
fi

base_detector_2="$(line_count "$LOG_DETECTOR")"

echo "M44 invalid user from ${IP_A} ts=$(date +%s)" >> "$DEMO_LOG"

cooldown_line="$(wait_in_tail "\"msg\":\"cooldown_hit\".*\"rule_id\":\"R-COLLECT-INVALID-USER\".*\"group_key\":\"${IP_A}\"" "$LOG_DETECTOR" "$base_detector_2" 60 || true)"
if [[ -z "$cooldown_line" ]]; then
  echo "FAIL: timeout waiting for cooldown_hit for IP_A=${IP_A}" >&2
  debug_recent '"msg":"cooldown_hit"|"msg":"rule_matched"' "$LOG_DETECTOR"
  exit 1
fi

runs_after_second="$(count_new_runs_since "$base_master_1")"
if [[ "$runs_after_second" != "1" ]]; then
  echo "FAIL: expected still exactly 1 invalid-user run after second IP_A trigger, got ${runs_after_second}" >&2
  debug_recent '"msg":"response_run_created".*"rule_id":"R-COLLECT-INVALID-USER"' "$LOG_MASTER"
  exit 1
fi

base_detector_3="$(line_count "$LOG_DETECTOR")"
echo "M44 invalid user from ${IP_B} ts=$(date +%s)" >> "$DEMO_LOG"

rule_matched_b_line="$(wait_in_tail "\"msg\":\"rule_matched\".*\"rule_id\":\"R-COLLECT-INVALID-USER\".*\"group_key\":\"${IP_B}\"" "$LOG_DETECTOR" "$base_detector_3" 60 || true)"
if [[ -z "$rule_matched_b_line" ]]; then
  echo "FAIL: timeout waiting for rule_matched for IP_B=${IP_B}" >&2
  debug_recent '"msg":"rule_matched".*"rule_id":"R-COLLECT-INVALID-USER"' "$LOG_DETECTOR"
  exit 1
fi

second_trigger_line="$(wait_in_tail "\"msg\":\"trigger_published\".*\"alert_key\":\"A-COLLECT-INVALID-USER-" "$LOG_DETECTOR" "$base_detector_3" 60 || true)"
if [[ -z "$second_trigger_line" ]]; then
  echo "FAIL: timeout waiting for trigger_published for IP_B=${IP_B}" >&2
  debug_recent '"msg":"trigger_published"|"msg":"rule_matched"' "$LOG_DETECTOR"
  exit 1
fi

target_runs=2
elapsed=0
while (( elapsed < 20 )); do
  current_runs="$(count_new_runs_since "$base_master_1")"
  if [[ "$current_runs" == "${target_runs}" ]]; then
    break
  fi
  sleep 1
  elapsed=$((elapsed + 1))
done
final_runs="$(count_new_runs_since "$base_master_1")"
if [[ "$final_runs" != "2" ]]; then
  echo "FAIL: expected exactly 2 new invalid-user runs in window (1 for IP_A + 1 for IP_B), got ${final_runs}" >&2
  debug_recent '"msg":"response_run_created".*"rule_id":"R-COLLECT-INVALID-USER"' "$LOG_MASTER"
  exit 1
fi

run_lines_window="$(tail -n +"$((base_master_1 + 1))" "$LOG_MASTER" | rg '"msg":"response_run_created".*"rule_id":"R-COLLECT-INVALID-USER".*"playbook_id":"PB-AGENT-PING-LOCALHOST"' || true)"
RUN_A="$(printf "%s\n" "$run_lines_window" | sed -n '1p' | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"
RUN_B="$(printf "%s\n" "$run_lines_window" | sed -n '2p' | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"
if [[ -z "$RUN_A" || -z "$RUN_B" ]]; then
  echo "FAIL: unable to extract run IDs for IP_A/IP_B window" >&2
  echo "$run_lines_window" >&2
  exit 1
fi

echo "$first_trigger_line"
echo "$rule_matched_a_line"
echo "$cooldown_line"
echo "$rule_matched_b_line"
echo "$second_trigger_line"
echo "$run_lines_window"
echo "PASS: M44 cooldown + dedupe proof ip_a=${IP_A} ip_b=${IP_B} run_a=${RUN_A} run_b=${RUN_B}"
