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

echo "=== M64 timeout respects config proof ==="

[[ -s "$LOG_MASTER" ]] || die "missing or empty $LOG_MASTER"
[[ -f "$DEMO_LOG" ]] || touch "$DEMO_LOG"

base_master="$(line_count "$LOG_MASTER")"
NOW="$(date +%s)"
OCT=$(( (NOW % 180) + 20 ))
echo "M64 invalid user from 10.0.0.${OCT} ts=${NOW}" >> "$DEMO_LOG"

run_line="$(tail_from "$LOG_MASTER" "$base_master" | rg -F "\"msg\":\"response_run_created\"" | rg -F "\"rule_id\":\"R-COLLECT-INVALID-USER\"" | rg -F "\"playbook_id\":\"PB-AGENT-PING-LOCALHOST\"" | head -n 1 || true)"
[[ -n "$run_line" ]] || run_line="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"response_run_created\"" 60 || true)"
RUN_ID="$(printf "%s\n" "$run_line" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"
[[ -n "$RUN_ID" ]] || die "unable to parse run_id"

waiting_line="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"response_run_waiting_approval\",\"run_id\":\"${RUN_ID}\"" 60 || true)"
[[ -n "$waiting_line" ]] || die "response_run_waiting_approval missing for run_id=${RUN_ID}" "$RUN_ID"
timeout_ms="$(printf "%s\n" "$waiting_line" | sed -n 's/.*"timeout_ms":\([0-9]\+\).*/\1/p')"
[[ -n "$timeout_ms" ]] || timeout_ms=300000

expected_s=$(( timeout_ms / 1000 ))
min_s=$(( expected_s - 5 ))
max_s=$(( expected_s + 30 ))
(( min_s < 0 )) && min_s=0
wait_s=$(( expected_s + 40 ))
(( wait_s < 20 )) && wait_s=20

start_s="$(date +%s)"
timed_out_line="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"approval_timed_out\",\"run_id\":\"${RUN_ID}\"" "$wait_s" || true)"
[[ -n "$timed_out_line" ]] || die "approval_timed_out missing within ${wait_s}s for run_id=${RUN_ID}" "$RUN_ID"
end_s="$(date +%s)"

elapsed_s=$(( end_s - start_s ))
if (( elapsed_s < min_s || elapsed_s > max_s )); then
  die "elapsed timeout ${elapsed_s}s out of bounds [${min_s}, ${max_s}] for timeout_ms=${timeout_ms}" "$RUN_ID"
fi

echo "$run_line"
echo "$waiting_line"
echo "$timed_out_line"
echo "Measured: elapsed_s=${elapsed_s} expected_s=${expected_s} bounds=[${min_s},${max_s}] timeout_ms=${timeout_ms}"
echo "PASS: M64 timeout respects config proof run_id=${RUN_ID} elapsed_s=${elapsed_s}"
exit 0
