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
  [[ -f logs/roe-worker-fast.log ]] && out+=("logs/roe-worker-fast.log")
  [[ -f logs/worker-fast.live.log ]] && out+=("logs/worker-fast.live.log")
  for f in logs/*.log; do
    [[ -f "$f" ]] || continue
    case "$f" in
      *roe-worker*|*worker-f*|*worker-fast*|*master-roe-worker*) out+=("$f") ;;
    esac
  done
  printf "%s\n" "${out[@]}" | awk 'NF' | awk '!seen[$0]++'
}

debug_fail() {
  local run_id="$1"
  echo "Context: master-roe (last 120 relevant):" >&2
  rg "\"run_id\":\"${run_id}\"|response_run_created|approval_received|response_step_published|approval_not_needed|approval_timed_out" "$LOG_MASTER" | tail -n 120 >&2 || true
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

echo "=== M55 FAST queue correctness proof ==="

[[ -s "$LOG_MASTER" ]] || die "missing or empty $LOG_MASTER"
[[ -s "$LOG_AGENT" ]] || die "missing or empty $LOG_AGENT"
[[ -f "$DEMO_LOG" ]] || touch "$DEMO_LOG"
worker_log_list="$(worker_logs)"
[[ -n "$worker_log_list" ]] || die "no worker logs found (checked logs/roe-worker.log, logs/worker-f.log, logs/*worker*.log)"

base_master="$(line_count "$LOG_MASTER")"
base_agent="$(line_count "$LOG_AGENT")"

NOW="$(date +%s)"
OCTET=$(( (NOW % 180) + 20 ))
echo "M41 invalid user from 10.0.0.${OCTET} ts=${NOW}" >> "$DEMO_LOG"

run_line="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"response_run_created\".*\"rule_id\":\"R-COLLECT-INVALID-USER\".*\"playbook_id\":\"PB-AGENT-PING-LOCALHOST\"" 60 || true)"
[[ -n "$run_line" ]] || die "timeout waiting for response_run_created for invalid-user run"

RUN_ID="$(printf "%s\n" "$run_line" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"
[[ -n "$RUN_ID" ]] || die "unable to parse run_id from run_created line"

go run -mod=vendor ./cmd/master-roe-approve -config configs/master.yaml -run_id "$RUN_ID" -decision approve -actor khotso -reason "m55 scripted proof" >/dev/null \
  || die "approval command failed for run_id=$RUN_ID" "$RUN_ID"

approval_received_line="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"approval_received\".*\"run_id\":\"${RUN_ID}\".*\"decision\":\"approve\"" 60 || true)"
[[ -n "$approval_received_line" ]] || die "approval_received(decision=approve) not found for run_id=$RUN_ID" "$RUN_ID"

step_pub_fast="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"response_step_published\".*\"run_id\":\"${RUN_ID}\".*\"step_subject\":\"rsiem.response.steps.fast\"" 60 || true)"
[[ -n "$step_pub_fast" ]] || die "no FAST response_step_published found for run_id=$RUN_ID" "$RUN_ID"

STEP_ID="$(printf "%s\n" "$step_pub_fast" | sed -n 's/.*"step_id":"\([^"]*\)".*/\1/p')"
[[ -n "$STEP_ID" ]] || die "unable to parse step_id for run_id=$RUN_ID" "$RUN_ID"

# Wait for FAST-lane worker evidence in any worker log.
i=0
fast_received=0
step_succeeded=0
while (( i < 60 )); do
  fast_received=0
  step_succeeded=0
  worker_fast_files=""
  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    c1="$(rg -c "\"msg\":\"step_received\".*\"run_id\":\"${RUN_ID}\".*\"lane\":\"FAST\"" "$f" || true)"
    c2="$(rg -c "\"msg\":\"step_succeeded\".*\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\"" "$f" || true)"
    fast_received=$((fast_received + c1))
    step_succeeded=$((step_succeeded + c2))
    if (( c1 > 0 || c2 > 0 )); then
      worker_fast_files="${worker_fast_files}${f} "
    fi
  done <<< "$worker_log_list"
  if (( fast_received >= 1 && step_succeeded >= 1 )); then
    break
  fi
  sleep 1
  i=$((i + 1))
done

(( fast_received >= 1 )) || die "no FAST step_received observed for run_id=$RUN_ID" "$RUN_ID"
(( step_succeeded >= 1 )) || die "no step_succeeded observed for run_id=$RUN_ID step_id=$STEP_ID" "$RUN_ID"

exec_start_count="$(rg -c "\"msg\":\"agent_command_exec_start\".*\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\".*\"command_id\":\"ping\"" "$LOG_AGENT" || true)"
exec_done_count="$(rg -c "\"msg\":\"agent_command_exec_done\".*\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\".*\"command_id\":\"ping\"" "$LOG_AGENT" || true)"
[[ "$exec_start_count" == "1" ]] || die "expected exec_start count=1, got $exec_start_count for run_id=$RUN_ID" "$RUN_ID"
[[ "$exec_done_count" == "1" ]] || die "expected exec_done count=1, got $exec_done_count for run_id=$RUN_ID" "$RUN_ID"

step_result_line="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"response_step_result_received\".*\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\".*\"status\":\"SUCCEEDED\"" 20 || true)"

echo "$run_line"
echo "$approval_received_line"
echo "$step_pub_fast"
if [[ -n "$step_result_line" ]]; then
  echo "$step_result_line"
fi
echo "Worker evidence logs: ${worker_fast_files:-none}"
echo "Counts: fast_step_received=${fast_received} step_succeeded=${step_succeeded} exec_start=${exec_start_count} exec_done=${exec_done_count}"
echo "PASS: M55 fast queue correctness proof run_id=${RUN_ID} step_id=${STEP_ID}"
exit 0
