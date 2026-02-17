#!/usr/bin/env bash
set -euo pipefail

LOG_MASTER="logs/master-roe.log"
LOG_AGENT="logs/agent.log"
DEMO_LOG="tmp/demo.log"

mkdir -p logs tmp

line_count() {
  local f="$1"
  [[ -f "$f" ]] || { echo 0; return; }
  wc -l < "$f" | tr -d ' '
}

tail_from() {
  local f="$1" base="$2"
  tail -n +"$((base + 1))" "$f" 2>/dev/null || true
}

wait_match() {
  local file="$1" base="$2" pattern="$3" timeout="$4"
  local i=0
  while (( i < timeout )); do
    local line
    line="$(tail_from "$file" "$base" | rg "$pattern" | head -n 1 || true)"
    if [[ -n "$line" ]]; then
      echo "$line"
      return 0
    fi
    sleep 1
    i=$((i + 1))
  done
  return 1
}

worker_logs() {
  local out=()
  [[ -f logs/roe-worker.log ]] && out+=("logs/roe-worker.log")
  [[ -f logs/worker-f.log ]] && out+=("logs/worker-f.log")
  [[ -f logs/worker-fast.live.log ]] && out+=("logs/worker-fast.live.log")
  [[ -f logs/worker-standard.live.log ]] && out+=("logs/worker-standard.live.log")
  for f in logs/*.log; do
    [[ -f "$f" ]] || continue
    case "$f" in
      *worker*) out+=("$f") ;;
    esac
  done
  printf "%s\n" "${out[@]}" | awk 'NF' | awk '!seen[$0]++'
}

debug_fail() {
  local run_id="$1"
  echo "Context: master (last 160 relevant):" >&2
  rg "\"run_id\":\"${run_id}\"|response_run_created|response_run_waiting_approval|approval_requested|approval_timed_out|approval_received|approval_not_needed|response_step_published" "$LOG_MASTER" | tail -n 160 >&2 || true
  echo "Context: worker logs (last 120 relevant):" >&2
  local f
  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    echo "--- $f ---" >&2
    rg "\"run_id\":\"${run_id}\"|step_received|step_succeeded|step_failed_" "$f" | tail -n 120 >&2 || true
  done < <(worker_logs)
  echo "Context: agent (last 80 relevant):" >&2
  rg "\"run_id\":\"${run_id}\"|agent_command_exec_(start|done|denied)" "$LOG_AGENT" | tail -n 80 >&2 || true
}

die() {
  local msg="$1"
  local run_id="${2:-}"
  echo "FAIL: $msg"
  [[ -n "$run_id" ]] && debug_fail "$run_id"
  exit 1
}

echo "=== M57 approval timeout no-steps proof ==="

[[ -s "$LOG_MASTER" ]] || die "missing or empty $LOG_MASTER"
[[ -s "$LOG_AGENT" ]] || die "missing or empty $LOG_AGENT"
[[ -f "$DEMO_LOG" ]] || touch "$DEMO_LOG"
worker_log_list="$(worker_logs)"

base_master="$(line_count "$LOG_MASTER")"
base_agent="$(line_count "$LOG_AGENT")"

NOW="$(date +%s)"
OCTET=$(( (NOW % 180) + 20 ))
echo "M57 invalid user from 10.0.0.${OCTET} ts=${NOW}" >> "$DEMO_LOG"

run_line="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"response_run_created\".*\"rule_id\":\"R-COLLECT-INVALID-USER\".*\"playbook_id\":\"PB-AGENT-PING-LOCALHOST\"" 60 || true)"
[[ -n "$run_line" ]] || die "timeout waiting for response_run_created for invalid-user run"
RUN_ID="$(printf "%s\n" "$run_line" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"
[[ -n "$RUN_ID" ]] || die "unable to parse run_id"

waiting_line="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"response_run_waiting_approval\".*\"run_id\":\"${RUN_ID}\"" 60 || true)"
[[ -n "$waiting_line" ]] || die "timeout waiting for response_run_waiting_approval for run_id=$RUN_ID" "$RUN_ID"

timeout_ms="$(printf "%s\n" "$waiting_line" | sed -n 's/.*"timeout_ms":\([0-9]\+\).*/\1/p')"
[[ -n "$timeout_ms" ]] || timeout_ms=300000
wait_s=$(( (timeout_ms / 1000) + 10 ))
(( wait_s >= 10 )) || wait_s=10

echo "Detected approval timeout_ms=${timeout_ms} (waiting up to ${wait_s}s for timeout event)"

timed_out_line="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"approval_timed_out\".*\"run_id\":\"${RUN_ID}\"" "$wait_s" || true)"
[[ -n "$timed_out_line" ]] || die "approval_timed_out not observed within ${wait_s}s for run_id=$RUN_ID" "$RUN_ID"

# Required count style: rg -n run_id | rg -n response_step_published | wc -l, normalized.
step_published_count="$(
  {
    rg -n -F "\"run_id\":\"${RUN_ID}\"" "$LOG_MASTER" \
      | rg -n -F "\"msg\":\"response_step_published\"" \
      | wc -l | tr -d '[:space:]'
  } || true
)"
step_published_count="${step_published_count:-0}"
if ! [[ "$step_published_count" =~ ^[0-9]+$ ]]; then
  step_published_count=0
fi
[[ "$step_published_count" == "0" ]] || die "unexpected response_step_published count=${step_published_count} for timed-out run" "$RUN_ID"

worker_step_received=0
while IFS= read -r f; do
  [[ -n "$f" ]] || continue
  c="$(
    {
      rg -F "\"msg\":\"step_received\"" "$f" \
        | rg -F "\"run_id\":\"${RUN_ID}\"" \
        | wc -l | tr -d '[:space:]'
    } || true
  )"
  c="${c:-0}"
  if ! [[ "$c" =~ ^[0-9]+$ ]]; then
    c=0
  fi
  worker_step_received=$((worker_step_received + c))
done <<< "$worker_log_list"
[[ "$worker_step_received" == "0" ]] || die "unexpected worker step_received count=${worker_step_received} for timed-out run" "$RUN_ID"

agent_exec_start_count="$(
  {
    tail_from "$LOG_AGENT" "$base_agent" \
      | rg -F "\"msg\":\"agent_command_exec_start\"" \
      | rg -F "\"run_id\":\"${RUN_ID}\"" \
      | wc -l | tr -d '[:space:]'
  } || true
)"
agent_exec_start_count="${agent_exec_start_count:-0}"
if ! [[ "$agent_exec_start_count" =~ ^[0-9]+$ ]]; then
  agent_exec_start_count=0
fi
[[ "$agent_exec_start_count" == "0" ]] || die "unexpected agent_command_exec_start count=${agent_exec_start_count} for timed-out run" "$RUN_ID"
echo "$timed_out_line"
echo "Counts: step_published=${step_published_count} worker_step_received=${worker_step_received} agent_exec_start=${agent_exec_start_count}"
echo "PASS: M57 approval timeout no-steps proof run_id=${RUN_ID} timeout_ms=${timeout_ms}"
exit 0
