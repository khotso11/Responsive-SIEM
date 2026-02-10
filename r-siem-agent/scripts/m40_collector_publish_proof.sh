#!/usr/bin/env bash
set -euo pipefail

LOG_COLLECTOR="logs/collector-tail.log"
DEMO_LOG="tmp/demo.log"

if [[ ! -s "$LOG_COLLECTOR" ]]; then
  echo "Missing or empty $LOG_COLLECTOR. Start Terminal H (collector-tail) first." >&2
  exit 2
fi

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

echo "=== M40 collector publish proof ==="

baseline_line="$(last_line_num '"msg":"event_published"' "$LOG_COLLECTOR")"

echo "M40 collector publish ts=$(date +%s)" >> "$DEMO_LOG"

match_line="$(wait_in_slice '"msg":"event_published"' "$LOG_COLLECTOR" "$((baseline_line + 1))" 300 20 || true)"
if [[ -z "$match_line" ]]; then
  echo "FAIL: timeout waiting for event_published" >&2
  debug_recent '"msg":"event_published"' "$LOG_COLLECTOR"
  exit 1
fi

EVENT_ID="$(printf "%s\n" "$match_line" | sed -n 's/.*"event_idem_key":"\([^"]*\)".*/\1/p')"
if [[ -z "$EVENT_ID" ]]; then
  EVENT_ID="unknown"
fi

echo "$match_line"
echo "PASS: M40 collector publish proof event_idem_key=${EVENT_ID}"
