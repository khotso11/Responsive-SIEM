#!/usr/bin/env bash
set -euo pipefail

LOG_COLLECTOR="logs/collector-tail.log"
LOG_DETECTOR="logs/detector-v0.log"
LOG_MASTER="logs/master-roe.log"
NOTIFY_EXPORT="exports/notify.jsonl"
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

echo "=== M52 notify artifact fields proof ==="

require_log "$LOG_COLLECTOR" "Terminal H (collector-tail)"
require_log "$LOG_DETECTOR" "Terminal I (detector-v0)"
require_log "$LOG_MASTER" "Terminal E (master-roe)"
if [[ ! -f "$NOTIFY_EXPORT" ]]; then
  echo "FAIL: missing ${NOTIFY_EXPORT}" >&2
  exit 2
fi

mkdir -p tmp

base_detector="$(line_count "$LOG_DETECTOR")"
base_master="$(line_count "$LOG_MASTER")"
base_notify="$(line_count "$NOTIFY_EXPORT")"

NOW="$(date +%s)"
HOST_ID="m52-${NOW}"
echo "M42 process count host=${HOST_ID} ts=${NOW} process_count=3" >> "$DEMO_LOG"

trigger_line="$(wait_in_tail "\"msg\":\"trigger_published\".*\"alert_key\":\"A-COUNT-PROCESS-HOST-" "$LOG_DETECTOR" "$base_detector" 45 || true)"
if [[ -z "$trigger_line" ]]; then
  echo "FAIL: timeout waiting for process-count trigger for host=${HOST_ID}" >&2
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
  echo "FAIL: unable to extract run_id" >&2
  echo "$run_line" >&2
  exit 1
fi

elapsed=0
notify_slice=""
while (( elapsed < 60 )); do
  notify_slice="$(tail_from "$NOTIFY_EXPORT" "$base_notify" | rg "\"run_id\":\"${RUN_ID}\"" || true)"
  notify_count="$(printf "%s\n" "$notify_slice" | rg -c '"action_type":"notify"' || true)"
  if [[ "$notify_count" -ge 2 ]]; then
    break
  fi
  sleep 1
  elapsed=$((elapsed + 1))
done

if [[ -z "$notify_slice" ]]; then
  echo "FAIL: no notify artifact rows found for run_id=${RUN_ID}" >&2
  tail -n 10 "$NOTIFY_EXPORT" >&2 || true
  exit 1
fi

bad_line=""
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  step_id="$(printf "%s\n" "$line" | sed -n 's/.*"step_id":"\([^"]*\)".*/\1/p')"
  step_idx="$(printf "%s\n" "$line" | sed -n 's/.*"step_index":\([0-9]\+\).*/\1/p')"
  step_key="$(printf "%s\n" "$line" | sed -n 's/.*"step_key":"\([^"]*\)".*/\1/p')"
  action_type="$(printf "%s\n" "$line" | sed -n 's/.*"action_type":"\([^"]*\)".*/\1/p')"
  expected_key="step.${RUN_ID}.${step_id}"
  if [[ -z "$step_id" || -z "$step_idx" || -z "$step_key" || "$action_type" != "notify" || "$step_key" != "$expected_key" ]]; then
    bad_line="$line"
    break
  fi
done <<< "$notify_slice"

if [[ -n "$bad_line" ]]; then
  echo "FAIL: notify artifact row missing fields or step_key mismatch for run_id=${RUN_ID}" >&2
  echo "$bad_line" >&2
  echo "Context: notify rows for run_id=${RUN_ID}:" >&2
  printf "%s\n" "$notify_slice" | tail -n 10 >&2
  exit 1
fi

echo "$trigger_line"
echo "$run_line"
printf "%s\n" "$notify_slice"
echo "PASS: M52 notify artifact fields proof run_id=${RUN_ID}"
