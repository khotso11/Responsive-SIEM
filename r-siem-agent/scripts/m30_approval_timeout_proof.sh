#!/usr/bin/env bash
set -euo pipefail

LOG_MASTER="logs/master-roe.log"
DEMO_LOG="tmp/demo.log"

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

baseline_waiting="$(last_line_num '"msg":"response_run_waiting_approval"' "$LOG_MASTER")"

echo "M30 invalid user from 10.0.0.77 ts=$(date +%s)" >> "$DEMO_LOG"

waiting_line="$(wait_new_line '"msg":"response_run_waiting_approval"' "$LOG_MASTER" "$baseline_waiting")"
RUN_ID="$(printf "%s\n" "$waiting_line" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"
TIMEOUT_MS="$(printf "%s\n" "$waiting_line" | sed -n 's/.*"timeout_ms":\([0-9]*\).*/\1/p')"
if [[ -z "${TIMEOUT_MS}" ]]; then
  TIMEOUT_MS=300000
fi

MAX_WAIT_SECS=$(( (TIMEOUT_MS / 1000) + 20 ))

echo "RUN_ID: ${RUN_ID}"
echo "waiting_approval: ${waiting_line}"

baseline_timeout="$(last_line_num '"msg":"approval_timed_out"' "$LOG_MASTER")"

elapsed=0
while true; do
  if rg "\"msg\":\"approval_timed_out\"" "$LOG_MASTER" | rg -q "\"run_id\":\"${RUN_ID}\""; then
    break
  fi
  if (( elapsed >= MAX_WAIT_SECS )); then
    echo "ERROR: timed out waiting for approval_timed_out (waited ${MAX_WAIT_SECS}s)" >&2
    exit 1
  fi
  if (( elapsed % 10 == 0 )); then
    echo "...waiting (${elapsed}s/${MAX_WAIT_SECS}s)"
  fi
  sleep 1
  elapsed=$((elapsed + 1))
done

timeout_line="$(wait_new_line '"msg":"approval_timed_out"' "$LOG_MASTER" "$baseline_timeout")"

echo "timeout: ${timeout_line}"
