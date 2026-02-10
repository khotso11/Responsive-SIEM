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
    slice="$(sed -n "${start_line},${end_line}p" "$file")"
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

echo "=== M41 invalid user rule proof ==="

baseline_trigger="$(last_line_num '"msg":"trigger_published"' "$LOG_DETECTOR")"
baseline_run_created="$(last_line_num '"msg":"response_run_created"' "$LOG_MASTER")"


octet=$(( ( $(date +%s) % 200 ) + 1 ))
echo "M41 invalid user from 10.0.0.${octet} ts=$(date +%s)" >> "$DEMO_LOG"

trigger_line="$(wait_in_slice '"msg":"trigger_published".*"alert_key":"A-COLLECT-INVALID-USER-' "$LOG_DETECTOR" "$((baseline_trigger + 1))" 300 20 || true)"
if [[ -z "$trigger_line" ]]; then
  echo "FAIL: timeout waiting for detector trigger_published alert_key=A-COLLECT-INVALID-USER-*" >&2
  debug_recent '"msg":"trigger_published"|"msg":"rule_matched"' "$LOG_DETECTOR"
  exit 1
fi
ALERT_KEY="$(printf "%s\n" "$trigger_line" | sed -n 's/.*"alert_key":"\([^"]*\)".*/\1/p')"
if [[ -z "$ALERT_KEY" ]]; then
  echo "FAIL: unable to extract alert_key from trigger_published" >&2
  echo "$trigger_line" >&2
  exit 1
fi
if [[ "$ALERT_KEY" != A-COLLECT-INVALID-USER-* ]]; then
  echo "FAIL: alert_key prefix mismatch alert_key=${ALERT_KEY}" >&2
  echo "$trigger_line" >&2
  exit 1
fi

run_created_line="$(wait_in_slice '"msg":"response_run_created".*"rule_id":"R-COLLECT-INVALID-USER".*"playbook_id":"PB-AGENT-PING-LOCALHOST"' "$LOG_MASTER" "$((baseline_run_created + 1))" 300 20 || true)"
if [[ -z "$run_created_line" ]]; then
  echo "FAIL: timeout waiting for response_run_created R-COLLECT-INVALID-USER/PB-AGENT-PING-LOCALHOST" >&2
  debug_recent '"msg":"response_run_created"' "$LOG_MASTER"
  exit 1
fi
RUN_ID="$(printf "%s\n" "$run_created_line" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"
if [[ -z "$RUN_ID" ]]; then
  echo "FAIL: unable to extract run_id from response_run_created" >&2
  echo "$run_created_line" >&2
  exit 1
fi

echo "$trigger_line"
echo "$run_created_line"

echo "PASS: M41 invalid user rule proof alert_key=${ALERT_KEY} run_id=${RUN_ID}"
