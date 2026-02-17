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

debug_recent() {
  local pattern="$1"
  local file="$2"
  echo "Context: last 10 relevant lines from ${file}:" >&2
  rg "$pattern" "$file" | tail -n 10 >&2 || true
}

echo "=== M53 invalid-user negative proof ==="

require_log "$LOG_COLLECTOR" "Terminal H (collector-tail)"
require_log "$LOG_DETECTOR" "Terminal I (detector-v0)"
require_log "$LOG_MASTER" "Terminal E (master-roe)"

mkdir -p tmp

base_collector="$(line_count "$LOG_COLLECTOR")"
base_detector="$(line_count "$LOG_DETECTOR")"
base_master="$(line_count "$LOG_MASTER")"

NOW="$(date +%s)"
LINE="M53 invalid user 10.0.0.44 ts=${NOW}"
echo "$LINE" >> "$DEMO_LOG"

collector_line="$(wait_in_tail '"msg":"event_published"' "$LOG_COLLECTOR" "$base_collector" 20 || true)"
if [[ -z "$collector_line" ]]; then
  echo "FAIL: timeout waiting for collector event_published after malformed M53 line" >&2
  debug_recent '"msg":"event_published"' "$LOG_COLLECTOR"
  exit 1
fi

elapsed=0
while (( elapsed < 25 )); do
  det_slice="$(tail_from "$LOG_DETECTOR" "$base_detector")"
  mst_slice="$(tail_from "$LOG_MASTER" "$base_master")"
  bad_match="$(printf "%s\n" "$det_slice" | rg '"msg":"rule_matched".*"rule_id":"R-COLLECT-INVALID-USER"' | head -n 1 || true)"
  bad_trigger="$(printf "%s\n" "$det_slice" | rg '"msg":"trigger_published".*"alert_key":"A-COLLECT-INVALID-USER-' | head -n 1 || true)"
  bad_run="$(printf "%s\n" "$mst_slice" | rg '"msg":"response_run_created".*"rule_id":"R-COLLECT-INVALID-USER".*"playbook_id":"PB-AGENT-PING-LOCALHOST"' | head -n 1 || true)"
  if [[ -n "$bad_match" || -n "$bad_trigger" || -n "$bad_run" ]]; then
    echo "FAIL: malformed invalid-user line unexpectedly produced invalid-user match/trigger/run" >&2
    [[ -n "$bad_match" ]] && echo "Unexpected rule_matched: $bad_match" >&2
    [[ -n "$bad_trigger" ]] && echo "Unexpected trigger_published: $bad_trigger" >&2
    [[ -n "$bad_run" ]] && echo "Unexpected response_run_created: $bad_run" >&2
    debug_recent '"msg":"missing_group_key"|"msg":"rule_matched"|"msg":"trigger_published"' "$LOG_DETECTOR"
    debug_recent '"msg":"response_run_created".*"rule_id":"R-COLLECT-INVALID-USER"' "$LOG_MASTER"
    exit 1
  fi
  sleep 1
  elapsed=$((elapsed + 1))
done

echo "$collector_line"
echo "PASS: M53 invalid-user negative proof no invalid-user trigger/run after malformed line"
