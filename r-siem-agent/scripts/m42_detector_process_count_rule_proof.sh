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
    echo "Missing or empty $file. Start Terminal $label first." >&2
    exit 2
  fi
}

require_log "$LOG_COLLECTOR" "H (collector-tail)"
require_log "$LOG_DETECTOR" "I (detector-v0)"
require_log "$LOG_MASTER" "E (master-roe)"

mkdir -p tmp

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

echo "=== M42 process_count rule proof ==="

baseline_trigger="$(last_line_num '\"msg\":\"trigger_published\"' "$LOG_DETECTOR")"
baseline_run_created="$(last_line_num '\"msg\":\"response_run_created\"' "$LOG_MASTER")"


host_id="m42-$(date +%s)"
for i in 1 2 3; do
  echo "M42 process_count=3 host=${host_id} ts=$(date +%s) idx=${i}" >> "$DEMO_LOG"
done

trigger_line="$(wait_in_slice '\"msg\":\"trigger_published\".*\"alert_key\":\"A-COUNT-PROCESS-HOST-' "$LOG_DETECTOR" "$((baseline_trigger + 1))" 300 20 || true)"
if [[ -z "$trigger_line" ]]; then
  echo "FAIL: timeout waiting for detector trigger_published (A-COUNT-PROCESS-HOST)" >&2
  debug_recent '\"msg\":\"trigger_published\"' "$LOG_DETECTOR"
  exit 1
fi
if ! printf "%s" "$trigger_line" | rg -q '\"alert_key\":\"A-COUNT-PROCESS-HOST-'; then
  echo "FAIL: trigger_published did not match A-COUNT-PROCESS-HOST" >&2
  debug_recent '\"msg\":\"trigger_published\"' "$LOG_DETECTOR"
  exit 1
fi
if printf "%s" "$trigger_line" | rg -q '\"alert_key\":\"A-COLLECT-INVALID-USER-'; then
  echo "FAIL: trigger_published matched invalid-user alert_key" >&2
  echo "$trigger_line" >&2
  exit 1
fi

run_created_line="$(wait_in_slice '\"msg\":\"response_run_created\".*\"rule_id\":\"R-COUNT-PROCESS-HOST\".*\"playbook_id\":\"PB-COUNT-PROCESS-HOST\"' "$LOG_MASTER" "$((baseline_run_created + 1))" 300 20 || true)"
if [[ -z "$run_created_line" ]]; then
  echo "FAIL: timeout waiting for response_run_created (R-COUNT-PROCESS-HOST / PB-COUNT-PROCESS-HOST)" >&2
  debug_recent '\"msg\":\"response_run_created\"' "$LOG_MASTER"
  exit 1
fi
RUN_ID="$(printf "%s\n" "$run_created_line" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"
if [[ -z "$RUN_ID" ]]; then
  echo "FAIL: unable to extract run_id from response_run_created" >&2
  echo "$run_created_line" >&2
  debug_recent '\"msg\":\"response_run_created\".*\"rule_id\":\"R-COUNT-PROCESS-HOST\".*\"playbook_id\":\"PB-COUNT-PROCESS-HOST\"' "$LOG_MASTER"
  exit 1
fi
if ! printf "%s" "$run_created_line" | rg -q '\"rule_id\":\"R-COUNT-PROCESS-HOST\"'; then
  echo "FAIL: response_run_created rule_id mismatch" >&2
  echo "$run_created_line" >&2
  debug_recent '\"msg\":\"response_run_created\"' "$LOG_MASTER"
  exit 1
fi
if ! printf "%s" "$run_created_line" | rg -q '\"playbook_id\":\"PB-COUNT-PROCESS-HOST\"'; then
  echo "FAIL: response_run_created playbook_id mismatch" >&2
  echo "$run_created_line" >&2
  debug_recent '\"msg\":\"response_run_created\"' "$LOG_MASTER"
  exit 1
fi
if printf "%s" "$run_created_line" | rg -q '\"rule_id\":\"R-COLLECT-INVALID-USER\"|\"playbook_id\":\"PB-AGENT-PING-LOCALHOST\"'; then
  echo "FAIL: response_run_created matched invalid-user rule/playbook" >&2
  echo "$run_created_line" >&2
  exit 1
fi

ALERT_KEY="$(printf "%s\n" "$trigger_line" | sed -n 's/.*"alert_key":"\([^"]*\)".*/\1/p')"
if [[ -z "$ALERT_KEY" ]]; then
  ALERT_KEY="unknown"
fi

echo "$trigger_line"
echo "$run_created_line"

echo "PASS: M42 process_count rule proof alert_key=${ALERT_KEY} run_id=${RUN_ID}"
