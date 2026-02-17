#!/usr/bin/env bash
set -euo pipefail

LOG_MASTER="logs/master-roe.log"
DEMO_LOG="tmp/demo.log"

mkdir -p logs tmp

line_count() { [[ -f "$1" ]] && wc -l < "$1" | tr -d ' ' || echo 0; }
tail_from() { tail -n +"$(( $2 + 1 ))" "$1" 2>/dev/null || true; }

wait_match() {
  local file="$1" base="$2" fixed="$3" timeout="$4"
  local i=0
  while (( i < timeout )); do
    local line
    line="$(tail_from "$file" "$base" | rg -F "$fixed" | head -n 1 || true)"
    [[ -n "$line" ]] && { echo "$line"; return 0; }
    sleep 1; i=$((i+1))
  done
  return 1
}

debug_fail() {
  local run_id="$1"
  echo "Context: master (last 120 relevant):" >&2
  rg -F "\"run_id\":\"${run_id}\"" "$LOG_MASTER" | tail -n 120 >&2 || true
}

die() { echo "FAIL: $1"; [[ -n "${2:-}" ]] && debug_fail "$2"; exit 1; }

echo "=== M63 approval request published proof ==="

[[ -s "$LOG_MASTER" ]] || die "missing or empty $LOG_MASTER"
[[ -f "$DEMO_LOG" ]] || touch "$DEMO_LOG"

base_master="$(line_count "$LOG_MASTER")"
NOW="$(date +%s)"
OCT=$(( (NOW % 180) + 20 ))
echo "M63 invalid user from 10.0.0.${OCT} ts=${NOW}" >> "$DEMO_LOG"

run_line="$(tail_from "$LOG_MASTER" "$base_master" | rg -F "\"msg\":\"response_run_created\"" | rg -F "\"rule_id\":\"R-COLLECT-INVALID-USER\"" | rg -F "\"playbook_id\":\"PB-AGENT-PING-LOCALHOST\"" | head -n 1 || true)"
[[ -n "$run_line" ]] || run_line="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"response_run_created\"" 60 || true)"
RUN_ID="$(printf "%s\n" "$run_line" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"
[[ -n "$RUN_ID" ]] || die "unable to parse run_id"

approval_request_published="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"approval_request_published\",\"run_id\":\"${RUN_ID}\"" 60 || true)"
[[ -n "$approval_request_published" ]] || die "approval_request_published missing for run_id=${RUN_ID}" "$RUN_ID"
printf "%s\n" "$approval_request_published" | rg -F "\"subject\":\"rsiem.response.approval_requests\"" >/dev/null || die "approval_request_published missing expected subject for run_id=${RUN_ID}" "$RUN_ID"

approval_requested="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"approval_requested\",\"run_id\":\"${RUN_ID}\"" 60 || true)"
[[ -n "$approval_requested" ]] || die "approval_requested missing for run_id=${RUN_ID}" "$RUN_ID"

waiting_line="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"response_run_waiting_approval\",\"run_id\":\"${RUN_ID}\"" 60 || true)"
[[ -n "$waiting_line" ]] || die "response_run_waiting_approval missing for run_id=${RUN_ID}" "$RUN_ID"

echo "$run_line"
echo "$approval_request_published"
echo "$approval_requested"
echo "$waiting_line"
echo "PASS: M63 approval request published proof run_id=${RUN_ID}"
exit 0
