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

echo "=== M41 invalid user rule proof ==="

baseline_trigger="$(last_line_num '"msg":"trigger_published"' "$LOG_DETECTOR")"
baseline_waiting="$(last_line_num '"msg":"response_run_waiting_approval"' "$LOG_MASTER")"


octet=$(( ( $(date +%s) % 200 ) + 1 ))
echo "M41 invalid user from 10.0.0.${octet} ts=$(date +%s)" >> "$DEMO_LOG"

trigger_line="$(wait_in_slice '"msg":"trigger_published"' "$LOG_DETECTOR" "$baseline_trigger" 300 20 || true)"
if [[ -z "$trigger_line" ]]; then
  echo "FAIL: timeout waiting for detector trigger_published" >&2
  echo "Context: recent detector lines:" >&2
  rg '"msg":"trigger_published"|"msg":"rule_matched"' "$LOG_DETECTOR" | tail -n 10 >&2 || true
  exit 1
fi

waiting_line="$(wait_in_slice '"msg":"response_run_waiting_approval"' "$LOG_MASTER" "$baseline_waiting" 300 20 || true)"
if [[ -z "$waiting_line" ]]; then
  echo "FAIL: timeout waiting for response_run_waiting_approval" >&2
  echo "Context: recent master-roe lines:" >&2
  rg '"msg":"response_run_waiting_approval"' "$LOG_MASTER" | tail -n 10 >&2 || true
  exit 1
fi

echo "$trigger_line"
echo "$waiting_line"

echo "PASS: M41 invalid user rule proof"
