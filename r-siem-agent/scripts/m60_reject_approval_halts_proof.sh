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
  local file="$1" base="$2" pattern="$3" timeout="$4"
  local i=0
  while (( i < timeout )); do
    local line
    line="$(tail_from "$file" "$base" | rg "$pattern" | head -n 1 || true)"
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

publish_reject() {
  local run_id="$1"
  local payload
  payload="{\"run_id\":\"${run_id}\",\"decision\":\"deny\",\"actor\":\"khotso\",\"reason\":\"m60 reject\",\"ts_unix_ms\":$(date +%s%3N)}"
  if command -v nats >/dev/null 2>&1; then
    nats pub "$APPROVAL_SUBJECT" "$payload" >/dev/null
  else
    go run -mod=vendor ./cmd/master-roe-approve -config configs/master.yaml -run_id "$run_id" -decision deny -actor khotso -reason "m60 reject" >/dev/null
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

echo "=== M60 reject approval halts proof ==="

[[ -s "$LOG_MASTER" ]] || die "missing or empty $LOG_MASTER"
[[ -s "$LOG_AGENT" ]] || die "missing or empty $LOG_AGENT"
[[ -f "$DEMO_LOG" ]] || touch "$DEMO_LOG"

base_master="$(line_count "$LOG_MASTER")"
base_agent="$(line_count "$LOG_AGENT")"

NOW="$(date +%s)"
OCT=$(( (NOW % 180) + 20 ))
echo "M60 invalid user from 10.0.0.${OCT} ts=${NOW}" >> "$DEMO_LOG"

run_line="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"response_run_created\".*\"rule_id\":\"R-COLLECT-INVALID-USER\".*\"playbook_id\":\"PB-AGENT-PING-LOCALHOST\"" 60 || true)"
[[ -n "$run_line" ]] || die "timeout waiting for invalid-user run_created"
RUN_ID="$(printf "%s\n" "$run_line" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"
[[ -n "$RUN_ID" ]] || die "unable to parse run_id"

waiting_line="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"response_run_waiting_approval\".*\"run_id\":\"${RUN_ID}\"" 60 || true)"
[[ -n "$waiting_line" ]] || die "waiting_approval not found for run_id=${RUN_ID}" "$RUN_ID"

publish_reject "$RUN_ID"

approval_received="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"approval_received\".*\"run_id\":\"${RUN_ID}\".*\"decision\":\"deny\"" 30 || true)"
[[ -n "$approval_received" ]] || die "approval_received(decision=reject) missing for run_id=${RUN_ID}" "$RUN_ID"

terminal_line="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"approval_denied\",\"run_id\":\"${RUN_ID}\"" 30 || true)"
if [[ -z "$terminal_line" ]]; then
  terminal_line="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"approval_not_needed\",\"run_id\":\"${RUN_ID}\",\"status\":\"FAILED_SAFE\"" 30 || true)"
fi
[[ -n "$terminal_line" ]] || die "no rejection terminal log found for run_id=${RUN_ID}" "$RUN_ID"

step_pub="$({ tail_from "$LOG_MASTER" "$base_master" | rg -F "\"msg\":\"response_step_published\"" | rg -F "\"run_id\":\"${RUN_ID}\"" | wc -l | tr -d '[:space:]'; } || true)"
step_pub="${step_pub:-0}"; [[ "$step_pub" =~ ^[0-9]+$ ]] || step_pub=0
[[ "$step_pub" == "0" ]] || die "response_step_published count=${step_pub}, expected 0" "$RUN_ID"

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
echo "$approval_received"
echo "$terminal_line"
echo "Counts: step_published=${step_pub} worker_step_received=${worker_recv} agent_exec_start=${agent_exec}"
echo "PASS: M60 reject approval halts proof run_id=${RUN_ID}"
exit 0
