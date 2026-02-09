#!/usr/bin/env bash
set -euo pipefail

LOG_DETECTOR="logs/detector-v0.log"
LOG_MASTER="logs/master-roe.log"
DEMO_LOG="tmp/demo.log"

if [[ ! -f "$LOG_DETECTOR" ]]; then
  echo "Missing $LOG_DETECTOR. Start Terminal I (detector-v0) first." >&2
  exit 1
fi
if [[ ! -f "$LOG_MASTER" ]]; then
  echo "Missing $LOG_MASTER. Start Terminal E (master-roe) first." >&2
  exit 1
fi

mkdir -p logs tmp

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

wait_new_line() {
  local pattern="$1"
  local file="$2"
  local baseline="$3"
  local last line
  while true; do
    last="$(rg -n "$pattern" "$file" | tail -n 1 || true)"
    if [[ -n "$last" ]]; then
      line="${last%%:*}"
      if [[ "$line" =~ ^[0-9]+$ ]] && (( line > baseline )); then
        echo "$last"
        return
      fi
    fi
    sleep 1
  done
}

assert_no_new_line() {
  local pattern="$1"
  local file="$2"
  local baseline="$3"
  local last line
  last="$(rg -n "$pattern" "$file" | tail -n 1 || true)"
  if [[ -z "$last" ]]; then
    return
  fi
  line="${last%%:*}"
  if [[ "$line" =~ ^[0-9]+$ ]] && (( line > baseline )); then
    echo "ERROR: unexpected new match for pattern [$pattern] in $file" >&2
    echo "$last" >&2
    exit 1
  fi
}

echo "=== M26 negative case: missing group_key should not publish ==="

baseline_missing="$(last_line_num '"msg":"missing_group_key"' "$LOG_DETECTOR")"
baseline_trigger="$(last_line_num '"msg":"trigger_published"' "$LOG_DETECTOR")"
baseline_waiting="$(last_line_num '"msg":"response_run_waiting_approval"' "$LOG_MASTER")"

echo "M26 invalid user ts=$(date +%s)" >> "$DEMO_LOG"

missing_line="$(wait_new_line '"msg":"missing_group_key"' "$LOG_DETECTOR" "$baseline_missing")"
echo "$missing_line"

sleep 3
assert_no_new_line '"msg":"trigger_published"' "$LOG_DETECTOR" "$baseline_trigger"
assert_no_new_line '"msg":"response_run_waiting_approval"' "$LOG_MASTER" "$baseline_waiting"

echo "OK: no trigger published and no new response run for M26"

echo "\n=== M27 cooldown by group_key ==="

baseline_trigger="$(last_line_num '"msg":"trigger_published"' "$LOG_DETECTOR")"
baseline_waiting="$(last_line_num '"msg":"response_run_waiting_approval"' "$LOG_MASTER")"

echo "M27 invalid user from 10.0.0.77 ts=$(date +%s)" >> "$DEMO_LOG"

trigger_line_1="$(wait_new_line '"msg":"trigger_published"' "$LOG_DETECTOR" "$baseline_trigger")"
waiting_line_1="$(wait_new_line '"msg":"response_run_waiting_approval"' "$LOG_MASTER" "$baseline_waiting")"

echo "$trigger_line_1"
echo "$waiting_line_1"

baseline_trigger_2="$(last_line_num '"msg":"trigger_published"' "$LOG_DETECTOR")"
baseline_waiting_2="$(last_line_num '"msg":"response_run_waiting_approval"' "$LOG_MASTER")"
baseline_cooldown="$(last_line_num '"msg":"cooldown_hit"' "$LOG_DETECTOR")"

echo "M27 invalid user from 10.0.0.77 ts=$(date +%s)" >> "$DEMO_LOG"

cooldown_line="$(wait_new_line '"msg":"cooldown_hit"' "$LOG_DETECTOR" "$baseline_cooldown")"
echo "$cooldown_line"

sleep 3
assert_no_new_line '"msg":"trigger_published"' "$LOG_DETECTOR" "$baseline_trigger_2"
assert_no_new_line '"msg":"response_run_waiting_approval"' "$LOG_MASTER" "$baseline_waiting_2"

echo "OK: cooldown hit and no new run for same IP"

baseline_trigger_3="$(last_line_num '"msg":"trigger_published"' "$LOG_DETECTOR")"
baseline_waiting_3="$(last_line_num '"msg":"response_run_waiting_approval"' "$LOG_MASTER")"

echo "M27 invalid user from 10.0.0.88 ts=$(date +%s)" >> "$DEMO_LOG"

trigger_line_2="$(wait_new_line '"msg":"trigger_published"' "$LOG_DETECTOR" "$baseline_trigger_3")"
waiting_line_2="$(wait_new_line '"msg":"response_run_waiting_approval"' "$LOG_MASTER" "$baseline_waiting_3")"

echo "$trigger_line_2"
echo "$waiting_line_2"

echo "OK: different IP bypassed cooldown and created new run"
