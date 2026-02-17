#!/usr/bin/env bash
set -euo pipefail

LOG_COLLECTOR="logs/collector-tail.log"
LOG_DETECTOR="logs/detector-v0.log"
LOG_MASTER="logs/master-roe.log"
LOG_WORKER="logs/roe-worker.log"
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

echo "=== M49 notify artifact hardening proof ==="

require_log "$LOG_COLLECTOR" "Terminal H (collector-tail)"
require_log "$LOG_DETECTOR" "Terminal I (detector-v0)"
require_log "$LOG_MASTER" "Terminal E (master-roe)"
require_log "$LOG_WORKER" "Terminal F (roe-worker)"

mkdir -p tmp exports
touch "$NOTIFY_EXPORT"

base_detector="$(line_count "$LOG_DETECTOR")"
base_master="$(line_count "$LOG_MASTER")"
base_worker="$(line_count "$LOG_WORKER")"
base_notify="$(line_count "$NOTIFY_EXPORT")"

NOW="$(date +%s)"
HOST_ID="m49-${NOW}"
echo "M42 process count host=${HOST_ID} ts=${NOW} process_count=3" >> "$DEMO_LOG"

trigger_line="$(wait_in_tail "\"msg\":\"trigger_published\".*\"alert_key\":\"A-COUNT-PROCESS-HOST-" "$LOG_DETECTOR" "$base_detector" 45 || true)"
if [[ -z "$trigger_line" ]]; then
  echo "FAIL: timeout waiting for trigger_published for M49 host=${HOST_ID}" >&2
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

notify_file_written_line="$(wait_in_tail "\"msg\":\"notify_file_written\".*\"run_id\":\"${RUN_ID}\"" "$LOG_WORKER" "$base_worker" 60 || true)"
if [[ -z "$notify_file_written_line" ]]; then
  echo "FAIL: timeout waiting for notify_file_written for run_id=${RUN_ID}" >&2
  debug_recent "\"msg\":\"notify_file_written\"|\"msg\":\"notify_noop_missing_webhook\"" "$LOG_WORKER"
  exit 1
fi

notify_slice="$(tail_from "$NOTIFY_EXPORT" "$base_notify" | rg "\"run_id\":\"${RUN_ID}\"" || true)"
notify0_line="$(printf "%s\n" "$notify_slice" | rg "\"step_index\":0" | tail -n 1 || true)"
notify2_line="$(printf "%s\n" "$notify_slice" | rg "\"step_index\":2" | tail -n 1 || true)"
if [[ -z "$notify0_line" || -z "$notify2_line" ]]; then
  echo "FAIL: expected notify export rows for step_index 0 and 2, run_id=${RUN_ID}" >&2
  echo "Context: recent notify export rows:" >&2
  tail -n 10 "$NOTIFY_EXPORT" >&2 || true
  exit 1
fi

if ! printf "%s\n%s\n" "$notify0_line" "$notify2_line" | rg -q '^\{.+\}$'; then
  echo "FAIL: notify export rows are not valid JSONL object lines for run_id=${RUN_ID}" >&2
  printf "%s\n%s\n" "$notify0_line" "$notify2_line" >&2
  exit 1
fi

echo "$trigger_line"
echo "$run_line"
echo "$notify_file_written_line"
echo "$notify0_line"
echo "$notify2_line"
echo "PASS: M49 notify artifact hardening proof run_id=${RUN_ID}"
