#!/usr/bin/env bash
set -euo pipefail

LOG_MASTER="logs/master-roe.log"

if [[ ! -f "$LOG_MASTER" ]]; then
  echo "Missing $LOG_MASTER. Start Terminal E (master-roe) first." >&2
  exit 1
fi

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
  local max_wait="$4"
  local last line elapsed=0
  while (( elapsed < max_wait )); do
    last="$(rg -n "$pattern" "$file" | tail -n 1 || true)"
    if [[ -n "$last" ]]; then
      line="${last%%:*}"
      if [[ "$line" =~ ^[0-9]+$ ]] && (( line > baseline )); then
        echo "$last"
        return 0
      fi
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  return 1
}

echo "=== M36 approval timeout fail-safe proof (optional) ==="

EVENT_ID="evt.m36.$(date +%s)"
LINE="M36 invalid user from 10.0.0.77 ts=$(date +%s)"
TRIGGER_IDEM_KEY="trig.alert.A-COLLECT-INVALID-USER-${EVENT_ID}"

baseline_waiting="$(last_line_num '"msg":"response_run_waiting_approval"' "$LOG_MASTER")"


go run -mod=vendor ./cmd/master-pubevent -config configs/master.yaml -event_idem_key "$EVENT_ID" -line "$LINE"

waiting_line="$(wait_new_line '"msg":"response_run_waiting_approval"' "$LOG_MASTER" "$baseline_waiting" 20 || true)"
if [[ -z "$waiting_line" ]]; then
  echo "FAIL: timeout waiting for response_run_waiting_approval for event_idem_key=${EVENT_ID}" >&2
  exit 1
fi

RUN_ID="$(printf "%s\n" "$waiting_line" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"
if [[ -z "$RUN_ID" ]]; then
  echo "FAIL: unable to extract run_id from waiting_approval line" >&2
  exit 1
fi

echo "$waiting_line"
echo "event_idem_key: ${EVENT_ID}"
echo "trigger_idem_key: ${TRIGGER_IDEM_KEY}"
echo "run_id: ${RUN_ID}"

baseline_fail_state="$(last_line_num '"msg":"approval_timed_out"|"msg":"approval_not_needed"' "$LOG_MASTER")"

max_wait=420
elapsed=0
while (( elapsed < max_wait )); do
  timed_out="$(rg -n "\"run_id\":\"${RUN_ID}\"" "$LOG_MASTER" | rg '"msg":"approval_timed_out"' | tail -n 1 || true)"
  if [[ -n "$timed_out" ]]; then
    line="${timed_out%%:*}"
    if [[ "$line" =~ ^[0-9]+$ ]] && (( line > baseline_fail_state )); then
      echo "$timed_out"
      echo "PASS: approval_timed_out observed event_idem_key=${EVENT_ID} trigger_idem_key=${TRIGGER_IDEM_KEY} run_id=${RUN_ID}"
      exit 0
    fi
  fi

  failed_safe="$(rg -n "\"run_id\":\"${RUN_ID}\"" "$LOG_MASTER" | rg '"msg":"approval_not_needed"' | rg '"status":"FAILED_SAFE"' | tail -n 1 || true)"
  if [[ -n "$failed_safe" ]]; then
    line="${failed_safe%%:*}"
    if [[ "$line" =~ ^[0-9]+$ ]] && (( line > baseline_fail_state )); then
      echo "$failed_safe"
      echo "PASS: FAILED_SAFE observed event_idem_key=${EVENT_ID} trigger_idem_key=${TRIGGER_IDEM_KEY} run_id=${RUN_ID}"
      exit 0
    fi
  fi

  if (( elapsed % 10 == 0 )); then
    echo "...waiting (${elapsed}s/${max_wait}s)"
  fi

  sleep 1
  elapsed=$((elapsed + 1))
done

echo "FAIL: timeout waiting for approval timeout/FAILED_SAFE for run_id=${RUN_ID}" >&2
exit 1
