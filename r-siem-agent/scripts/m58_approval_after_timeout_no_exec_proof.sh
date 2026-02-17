#!/usr/bin/env bash
set -euo pipefail

LOG_MASTER="logs/master-roe.log"
LOG_AGENT="logs/agent.log"
DEMO_LOG="tmp/demo.log"
APPROVAL_SUBJECT="rsiem.response.approvals"

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

worker_logs() {
  local out=()
  for f in logs/*.log; do
    [[ -f "$f" ]] || continue
    case "$f" in *worker*) out+=("$f");; esac
  done
  printf "%s\n" "${out[@]}" | awk 'NF' | awk '!s[$0]++'
}

publish_approval() {
  local run_id="$1" decision="$2" reason="$3"
  local payload
  payload="{\"run_id\":\"${run_id}\",\"decision\":\"${decision}\",\"actor\":\"khotso\",\"reason\":\"${reason}\",\"ts_unix_ms\":$(date +%s%3N)}"
  if command -v nats >/dev/null 2>&1; then
    nats pub "$APPROVAL_SUBJECT" "$payload" >/dev/null
  else
    go run -mod=vendor ./cmd/master-roe-approve -config configs/master.yaml -run_id "$run_id" -decision "$decision" -actor khotso -reason "$reason" >/dev/null
  fi
}

debug_fail() {
  local run_id="$1"
  echo "Context: master (last 120 relevant):" >&2
  rg -F "\"run_id\":\"${run_id}\"" "$LOG_MASTER" | tail -n 120 >&2 || true
  echo "Context: worker (last 120 relevant):" >&2
  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    echo "--- $f ---" >&2
    rg -F "\"run_id\":\"${run_id}\"" "$f" | tail -n 120 >&2 || true
  done < <(worker_logs)
  echo "Context: agent (last 80 relevant):" >&2
  rg -F "\"run_id\":\"${run_id}\"" "$LOG_AGENT" | tail -n 80 >&2 || true
}

die() { echo "FAIL: $1"; [[ -n "${2:-}" ]] && debug_fail "$2"; exit 1; }

echo "=== M58 approval after timeout no-exec proof ==="

[[ -s "$LOG_MASTER" ]] || die "missing or empty $LOG_MASTER"
[[ -s "$LOG_AGENT" ]] || die "missing or empty $LOG_AGENT"
[[ -f "$DEMO_LOG" ]] || touch "$DEMO_LOG"

base_master="$(line_count "$LOG_MASTER")"
base_agent="$(line_count "$LOG_AGENT")"

NOW="$(date +%s)"
OCT=$(( (NOW % 180) + 20 ))
echo "M58 invalid user from 10.0.0.${OCT} ts=${NOW}" >> "$DEMO_LOG"

run_line="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"response_run_created\",\"run_id\":\"" 60 | rg -F "\"rule_id\":\"R-COLLECT-INVALID-USER\"" | rg -F "\"playbook_id\":\"PB-AGENT-PING-LOCALHOST\"" | tail -n 1 || true)"
[[ -n "$run_line" ]] || run_line="$(tail_from "$LOG_MASTER" "$base_master" | rg -F "\"msg\":\"response_run_created\"" | rg -F "\"rule_id\":\"R-COLLECT-INVALID-USER\"" | rg -F "\"playbook_id\":\"PB-AGENT-PING-LOCALHOST\"" | head -n 1 || true)"
[[ -n "$run_line" ]] || die "timeout waiting for invalid-user run_created"
RUN_ID="$(printf "%s\n" "$run_line" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"
[[ -n "$RUN_ID" ]] || die "unable to parse run_id"

waiting_line="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"response_run_waiting_approval\",\"run_id\":\"${RUN_ID}\"" 60 || true)"
[[ -n "$waiting_line" ]] || die "waiting_approval not found for run_id=${RUN_ID}" "$RUN_ID"
timeout_ms="$(printf "%s\n" "$waiting_line" | sed -n 's/.*"timeout_ms":\([0-9]\+\).*/\1/p')"
[[ -n "$timeout_ms" ]] || timeout_ms=300000
wait_s=$(( timeout_ms / 1000 + 15 ))
(( wait_s < 15 )) && wait_s=15
echo "Detected timeout_ms=${timeout_ms}; waiting up to ${wait_s}s"

timed_out_line="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"approval_timed_out\",\"run_id\":\"${RUN_ID}\"" "$wait_s" || true)"
[[ -n "$timed_out_line" ]] || die "approval_timed_out not seen for run_id=${RUN_ID}" "$RUN_ID"

publish_approval "$RUN_ID" "approve" "m58 late approve"
sleep 2

step_pub_count="$({ tail_from "$LOG_MASTER" "$base_master" | rg -F "\"msg\":\"response_step_published\"" | rg -F "\"run_id\":\"${RUN_ID}\"" | wc -l | tr -d '[:space:]'; } || true)"
step_pub_count="${step_pub_count:-0}"; [[ "$step_pub_count" =~ ^[0-9]+$ ]] || step_pub_count=0
[[ "$step_pub_count" == "0" ]] || die "response_step_published count=${step_pub_count}, expected 0" "$RUN_ID"

worker_recv=0
while IFS= read -r f; do
  [[ -n "$f" ]] || continue
  c="$({ rg -F "\"msg\":\"step_received\"" "$f" | rg -F "\"run_id\":\"${RUN_ID}\"" | wc -l | tr -d '[:space:]'; } || true)"
  c="${c:-0}"; [[ "$c" =~ ^[0-9]+$ ]] || c=0
  worker_recv=$((worker_recv + c))
done < <(worker_logs)
[[ "$worker_recv" == "0" ]] || die "worker step_received count=${worker_recv}, expected 0" "$RUN_ID"

agent_exec="$({ tail_from "$LOG_AGENT" "$base_agent" | rg -F "\"msg\":\"agent_command_exec_start\"" | rg -F "\"run_id\":\"${RUN_ID}\"" | wc -l | tr -d '[:space:]'; } || true)"
agent_exec="${agent_exec:-0}"; [[ "$agent_exec" =~ ^[0-9]+$ ]] || agent_exec=0
[[ "$agent_exec" == "0" ]] || die "agent exec_start count=${agent_exec}, expected 0" "$RUN_ID"

echo "$run_line"
echo "$waiting_line"
echo "$timed_out_line"
echo "Counts: step_published=${step_pub_count} worker_step_received=${worker_recv} agent_exec_start=${agent_exec}"
echo "PASS: M58 approval after timeout no-exec proof run_id=${RUN_ID}"
exit 0
