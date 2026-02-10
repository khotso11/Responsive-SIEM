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
  echo "Context: recent trigger_published lines:" >&2
  rg '\"msg\":\"trigger_published\"' "$LOG_DETECTOR" | tail -n 15 >&2 || true
  exit 1
fi
if ! printf "%s" "$trigger_line" | rg -q '\"alert_key\":\"A-COUNT-PROCESS-HOST-'; then
  echo "FAIL: trigger_published did not match A-COUNT-PROCESS-HOST" >&2
  echo "Context: recent trigger_published lines:" >&2
  rg '\"msg\":\"trigger_published\"' "$LOG_DETECTOR" | tail -n 15 >&2 || true
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
  echo "Context: recent response_run_created lines:" >&2
  rg '\"msg\":\"response_run_created\"' "$LOG_MASTER" | tail -n 15 >&2 || true
  exit 1
fi
RUN_LINE="$(grep -E '\"msg\":\"response_run_created\".*\"rule_id\":\"R-COUNT-PROCESS-HOST\".*\"playbook_id\":\"PB-COUNT-PROCESS-HOST\"' "$LOG_MASTER" | tail -n 1 || true)"
RUN_ID="$(printf "%s\n" "$RUN_LINE" | awk 'match($0, /"run_id":"([^"]+)"/, a){print a[1]}')"
if [[ -z "$RUN_ID" ]]; then
  echo "FAIL: unable to extract run_id from response_run_created" >&2
  echo "Context: raw line parsed:" >&2
  echo "$RUN_LINE" >&2
  echo "Context: last 10 matching response_run_created lines (rule/playbook):" >&2
  grep -E '\"msg\":\"response_run_created\".*\"rule_id\":\"R-COUNT-PROCESS-HOST\".*\"playbook_id\":\"PB-COUNT-PROCESS-HOST\"' "$LOG_MASTER" | tail -n 10 >&2 || true
  exit 1
fi
if ! printf "%s" "$run_created_line" | rg -q '\"rule_id\":\"R-COUNT-PROCESS-HOST\"'; then
  echo "FAIL: response_run_created rule_id mismatch" >&2
  echo "$run_created_line" >&2
  echo "Context: response_run_created lines around start:" >&2
  start_line="${run_created_line%%:*}"
  end_line=$((start_line + 300))
  sed -n "${start_line},${end_line}p" "$LOG_MASTER" | rg '\"msg\":\"response_run_created\"' >&2 || true
  exit 1
fi
if ! printf "%s" "$run_created_line" | rg -q '\"playbook_id\":\"PB-COUNT-PROCESS-HOST\"'; then
  echo "FAIL: response_run_created playbook_id mismatch" >&2
  echo "$run_created_line" >&2
  echo "Context: response_run_created lines around start:" >&2
  start_line="${run_created_line%%:*}"
  end_line=$((start_line + 300))
  sed -n "${start_line},${end_line}p" "$LOG_MASTER" | rg '\"msg\":\"response_run_created\"' >&2 || true
  exit 1
fi
if printf "%s" "$run_created_line" | rg -q '\"rule_id\":\"R-COLLECT-INVALID-USER\"|\"playbook_id\":\"PB-AGENT-PING-LOCALHOST\"'; then
  echo "FAIL: response_run_created matched invalid-user rule/playbook" >&2
  echo "$run_created_line" >&2
  exit 1
fi

start_line="${run_created_line%%:*}"
if [[ -z "$start_line" || ! "$start_line" =~ ^[0-9]+$ ]]; then
  echo "FAIL: unable to derive response_run_created line number" >&2
  echo "$run_created_line" >&2
  exit 1
fi
end_line=$((start_line + 300))
slice="$(sed -n "${start_line},${end_line}p" "$LOG_MASTER")"
context_created="$(printf "%s\n" "$slice" | rg '\"msg\":\"response_run_created\"' || true)"
if [[ -z "$context_created" ]]; then
  echo "Context: response_run_created lines around start (bounded slice) is empty" >&2
else
  echo "Context: response_run_created lines around start (bounded slice):" >&2
  printf "%s\n" "$context_created" >&2
fi

echo "$trigger_line"
echo "$run_created_line"

echo "PASS: M42 process_count rule proof"
