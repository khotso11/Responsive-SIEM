#!/usr/bin/env bash
set -euo pipefail

LOG_DETECTOR="logs/detector-v0.log"
LOG_MASTER="logs/master-roe.log"

if [[ ! -f "$LOG_DETECTOR" ]]; then
  echo "Missing $LOG_DETECTOR. Start Terminal I (detector-v0) first." >&2
  exit 1
fi
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

echo "=== M35 detector restart replay safety ==="

EVENT_ID="evt.m35.$(date +%s)"
LINE="M35 invalid user from 10.0.0.77 ts=$(date +%s)"
TRIGGER_IDEM_KEY="trig.alert.A-COLLECT-INVALID-USER-${EVENT_ID}"

baseline_trigger="$(last_line_num '"msg":"trigger_published"' "$LOG_DETECTOR")"
baseline_waiting="$(last_line_num '"msg":"response_run_waiting_approval"' "$LOG_MASTER")"


go run -mod=vendor ./cmd/master-pubevent -config configs/master.yaml -event_idem_key "$EVENT_ID" -line "$LINE"

trigger_line_1="$(wait_new_line '"msg":"trigger_published"' "$LOG_DETECTOR" "$baseline_trigger" 15 || true)"
if [[ -z "$trigger_line_1" ]]; then
  echo "FAIL: timeout waiting for trigger_published for event_idem_key=${EVENT_ID}" >&2
  exit 1
fi
waiting_line_1="$(wait_new_line '"msg":"response_run_waiting_approval"' "$LOG_MASTER" "$baseline_waiting" 15 || true)"
if [[ -z "$waiting_line_1" ]]; then
  echo "FAIL: timeout waiting for response_run_waiting_approval for event_idem_key=${EVENT_ID}" >&2
  exit 1
fi

RUN_ID="$(printf "%s\n" "$waiting_line_1" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"
if [[ -z "$RUN_ID" ]]; then
  echo "FAIL: unable to extract run_id from waiting_approval line" >&2
  exit 1
fi


echo "$trigger_line_1"
echo "$waiting_line_1"
echo "event_idem_key: ${EVENT_ID}"
echo "trigger_idem_key: ${TRIGGER_IDEM_KEY}"
echo "run_id: ${RUN_ID}"

read -r -p "Restart detector (Terminal I) now (Ctrl+C then re-run), press Enter" _

baseline_trigger_dup="$(last_line_num '"msg":"response_trigger_duplicate"' "$LOG_MASTER")"
baseline_run_created="$(last_line_num '"msg":"response_run_created"' "$LOG_MASTER")"
baseline_waiting_2="$(last_line_num '"msg":"response_run_waiting_approval"' "$LOG_MASTER")"
baseline_fail_state="$(last_line_num '"msg":"approval_timed_out"|"msg":"approval_not_needed"' "$LOG_MASTER")"


go run -mod=vendor ./cmd/master-pubevent -config configs/master.yaml -event_idem_key "$EVENT_ID" -line "$LINE"

max_wait=15
elapsed=0
while (( elapsed < max_wait )); do
  # Fail-fast: approval timeout for this run
  timed_out="$(rg -n "\"run_id\":\"${RUN_ID}\"" "$LOG_MASTER" | rg '"msg":"approval_timed_out"' | tail -n 1 || true)"
  if [[ -n "$timed_out" ]]; then
    line="${timed_out%%:*}"
    if [[ "$line" =~ ^[0-9]+$ ]] && (( line > baseline_fail_state )); then
      echo "FAIL: approval_timed_out for RUN_ID=${RUN_ID}" >&2
      exit 1
    fi
  fi

  failed_safe="$(rg -n "\"run_id\":\"${RUN_ID}\"" "$LOG_MASTER" | rg '"msg":"approval_not_needed"' | rg '"status":"FAILED_SAFE"' | tail -n 1 || true)"
  if [[ -n "$failed_safe" ]]; then
    line="${failed_safe%%:*}"
    if [[ "$line" =~ ^[0-9]+$ ]] && (( line > baseline_fail_state )); then
      echo "FAIL: run is FAILED_SAFE (approval too late) RUN_ID=${RUN_ID}" >&2
      exit 1
    fi
  fi

  # Fail-fast: new run created for same trigger_idem_key
  new_run_created="$(rg -n "\"trigger_idem_key\":\"${TRIGGER_IDEM_KEY}\"" "$LOG_MASTER" | rg '"msg":"response_run_created"' | tail -n 1 || true)"
  if [[ -n "$new_run_created" ]]; then
    line="${new_run_created%%:*}"
    if [[ "$line" =~ ^[0-9]+$ ]] && (( line > baseline_run_created )); then
      echo "FAIL: duplicate response_run_created for trigger_idem_key=${TRIGGER_IDEM_KEY}" >&2
      exit 1
    fi
  fi
  new_waiting="$(rg -n "\"trigger_idem_key\":\"${TRIGGER_IDEM_KEY}\"" "$LOG_MASTER" | rg '"msg":"response_run_waiting_approval"' | tail -n 1 || true)"
  if [[ -n "$new_waiting" ]]; then
    line="${new_waiting%%:*}"
    if [[ "$line" =~ ^[0-9]+$ ]] && (( line > baseline_waiting_2 )); then
      echo "FAIL: duplicate response_run_waiting_approval for trigger_idem_key=${TRIGGER_IDEM_KEY}" >&2
      exit 1
    fi
  fi

  # PASS A: response_trigger_duplicate for same trigger_idem_key
  trigger_dup_line="$(rg -n "\"trigger_idem_key\":\"${TRIGGER_IDEM_KEY}\"" "$LOG_MASTER" | rg '"msg":"response_trigger_duplicate"' | tail -n 1 || true)"
  if [[ -n "$trigger_dup_line" ]]; then
    line="${trigger_dup_line%%:*}"
    if [[ "$line" =~ ^[0-9]+$ ]] && (( line > baseline_trigger_dup )); then
      echo "$trigger_dup_line"
      echo "PASS: replay safe (master trigger duplicate) event_idem_key=${EVENT_ID} trigger_idem_key=${TRIGGER_IDEM_KEY} run_id=${RUN_ID}"
      exit 0
    fi
  fi

  sleep 1
  elapsed=$((elapsed + 1))
done

# PASS B: no additional run for same trigger_idem_key within timeout window
new_run_created_after="$(rg -n "\"trigger_idem_key\":\"${TRIGGER_IDEM_KEY}\"" "$LOG_MASTER" | rg '"msg":"response_run_created"' | awk -F: -v b="$baseline_run_created" '$1>b' | tail -n 1 || true)"
if [[ -z "$new_run_created_after" ]]; then
  echo "PASS: replay safe (no new run created within ${max_wait}s) event_idem_key=${EVENT_ID} trigger_idem_key=${TRIGGER_IDEM_KEY} run_id=${RUN_ID}"
  exit 0
fi

echo "FAIL: duplicate run detected for trigger_idem_key=${TRIGGER_IDEM_KEY}" >&2
exit 1
