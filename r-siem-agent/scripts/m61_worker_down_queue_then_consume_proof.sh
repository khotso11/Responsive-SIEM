#!/usr/bin/env bash
set -euo pipefail

LOG_MASTER="logs/master-roe.log"
LOG_AGENT="logs/agent.log"
DEMO_LOG="tmp/demo.log"

mkdir -p logs tmp .cache/go-build

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

all_worker_pids() {
  ps -eo pid=,args= | rg 'master-roe-worker' | awk '{print $1}' || true
}

stop_all_workers() {
  local pids
  pids="$(all_worker_pids)"
  [[ -n "$pids" ]] || return 0
  echo "$pids" | xargs -r kill || true
  sleep 1
}

debug_fail() {
  local run_id="$1"
  echo "Context: master (last 140 relevant):" >&2
  rg -F "\"run_id\":\"${run_id}\"" "$LOG_MASTER" | tail -n 140 >&2 || true
  echo "Context: worker (last 140 relevant):" >&2
  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    echo "--- $f ---" >&2
    rg -F "\"run_id\":\"${run_id}\"" "$f" | tail -n 140 >&2 || true
  done < <(worker_logs)
  echo "Context: agent (last 100 relevant):" >&2
  rg -F "\"run_id\":\"${run_id}\"" "$LOG_AGENT" | tail -n 100 >&2 || true
}

die() { echo "FAIL: $1"; [[ -n "${2:-}" ]] && debug_fail "$2"; exit 1; }

echo "=== M61 worker down queue then consume proof ==="

[[ -s "$LOG_MASTER" ]] || die "missing or empty $LOG_MASTER"
[[ -s "$LOG_AGENT" ]] || die "missing or empty $LOG_AGENT"
[[ -f "$DEMO_LOG" ]] || touch "$DEMO_LOG"

STARTED_WORKER_PID=""
cleanup_worker() {
  if [[ -n "${STARTED_WORKER_PID}" ]]; then
    if kill -0 "$STARTED_WORKER_PID" 2>/dev/null; then
      kill "$STARTED_WORKER_PID" 2>/dev/null || true
    fi
  fi
}
trap cleanup_worker EXIT

stop_all_workers

base_master="$(line_count "$LOG_MASTER")"
base_agent="$(line_count "$LOG_AGENT")"
worker_log_list="$(worker_logs)"
worker_files=()
worker_bases=()
while IFS= read -r f; do
  [[ -n "$f" ]] || continue
  worker_files+=("$f")
  worker_bases+=("$(line_count "$f")")
done <<< "$worker_log_list"

NOW="$(date +%s)"
OCT=$(( (NOW % 180) + 20 ))
echo "M61 invalid user from 10.0.0.${OCT} ts=${NOW}" >> "$DEMO_LOG"

run_line="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"response_run_created\".*\"rule_id\":\"R-COLLECT-INVALID-USER\".*\"playbook_id\":\"PB-AGENT-PING-LOCALHOST\"" 60 || true)"
[[ -n "$run_line" ]] || die "timeout waiting for invalid-user run_created"
RUN_ID="$(printf "%s\n" "$run_line" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"
[[ -n "$RUN_ID" ]] || die "unable to parse run_id"

waiting_line="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"response_run_waiting_approval\".*\"run_id\":\"${RUN_ID}\"" 60 || true)"
[[ -n "$waiting_line" ]] || die "waiting_approval not found for run_id=${RUN_ID}" "$RUN_ID"

if command -v nats >/dev/null 2>&1; then
  nats pub rsiem.response.approvals "{\"run_id\":\"$RUN_ID\",\"decision\":\"approve\",\"actor\":\"khotso\"}" >/dev/null \
    || die "approval command failed for run_id=${RUN_ID}" "$RUN_ID"
else
  env GOCACHE="$(pwd)/.cache/go-build" go run -mod=vendor ./cmd/master-roe-approve -config configs/master.yaml -run_id "$RUN_ID" -decision approve -actor khotso -reason "m61 queue proof" >/dev/null \
    || die "approval command failed for run_id=${RUN_ID}" "$RUN_ID"
fi

step_pub_line="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"response_step_published\".*\"run_id\":\"${RUN_ID}\"" 60 || true)"
[[ -n "$step_pub_line" ]] || die "no response_step_published after approval for run_id=${RUN_ID}" "$RUN_ID"
STEP_ID="$(printf "%s\n" "$step_pub_line" | sed -n 's/.*"step_id":"\([^"]*\)".*/\1/p')"
STEP_SUBJECT="$(printf "%s\n" "$step_pub_line" | sed -n 's/.*"step_subject":"\([^"]*\)".*/\1/p')"
[[ -n "$STEP_ID" && -n "$STEP_SUBJECT" ]] || die "unable to parse step_id/step_subject for run_id=${RUN_ID}" "$RUN_ID"

if [[ "$STEP_SUBJECT" == *".fast" ]]; then
  TARGET_LANE="FAST"
else
  TARGET_LANE="STANDARD"
fi

down_recv=0
for i in "${!worker_files[@]}"; do
  f="${worker_files[$i]}"
  b="${worker_bases[$i]}"
  c="$({ tail_from "$f" "$b" | rg -F "\"msg\":\"step_received\"" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"lane\":\"${TARGET_LANE}\"" | wc -l | tr -d '[:space:]'; } || true)"
  c="${c:-0}"; [[ "$c" =~ ^[0-9]+$ ]] || c=0
  down_recv=$((down_recv + c))
done
[[ "$down_recv" == "0" ]] || die "${TARGET_LANE} step_received observed before automated worker start (count=${down_recv})" "$RUN_ID"

if [[ "$TARGET_LANE" == "FAST" ]]; then
  WORKER_LOG="logs/worker-f.log"
else
  WORKER_LOG="logs/worker-s.log"
fi

env GOCACHE="$(pwd)/.cache/go-build" go run -mod=vendor ./cmd/master-roe-worker --config configs/master.yaml -lane "$TARGET_LANE" >> "$WORKER_LOG" 2>&1 &
STARTED_WORKER_PID="$!"
sleep 1
kill -0 "$STARTED_WORKER_PID" 2>/dev/null || die "failed to start ${TARGET_LANE} worker automatically" "$RUN_ID"

i=0
recv=0
succeeded=0
while (( i < 60 )); do
  recv=0; succeeded=0
  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    c1="$({ rg -F "\"msg\":\"step_received\"" "$f" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | rg -F "\"lane\":\"${TARGET_LANE}\"" | wc -l | tr -d '[:space:]'; } || true)"
    c2="$({ rg -F "\"msg\":\"step_succeeded\"" "$f" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | wc -l | tr -d '[:space:]'; } || true)"
    [[ "$c1" =~ ^[0-9]+$ ]] || c1=0
    [[ "$c2" =~ ^[0-9]+$ ]] || c2=0
    recv=$((recv + c1)); succeeded=$((succeeded + c2))
  done < <(worker_logs)
  (( recv >= 1 && succeeded >= 1 )) && break
  sleep 1; i=$((i+1))
done
(( recv >= 1 )) || die "no step_received on lane ${TARGET_LANE} after automated worker start" "$RUN_ID"
(( succeeded >= 1 )) || die "no step_succeeded on lane ${TARGET_LANE} after automated worker start" "$RUN_ID"

exec_start_line="$(wait_match "$LOG_AGENT" "$base_agent" "\"msg\":\"agent_command_exec_start\".*\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\"" 60 || true)"
[[ -n "$exec_start_line" ]] || die "no agent_command_exec_start after ${TARGET_LANE} worker consumption began" "$RUN_ID"

master_success_line="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"response_step_result_received\".*\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\".*\"status\":\"SUCCEEDED\"" 60 || true)"
[[ -n "$master_success_line" ]] || die "no response_step_result_received(status=SUCCEEDED) for run_id=${RUN_ID} step_id=${STEP_ID}" "$RUN_ID"

exec_start="$({ tail_from "$LOG_AGENT" "$base_agent" | rg -F "\"msg\":\"agent_command_exec_start\"" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | wc -l | tr -d '[:space:]'; } || true)"
worker_recv_total=0
while IFS= read -r f; do
  [[ -n "$f" ]] || continue
  c="$({ rg -F "\"msg\":\"step_received\"" "$f" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | rg -F "\"lane\":\"${TARGET_LANE}\"" | wc -l | tr -d '[:space:]'; } || true)"
  [[ "$c" =~ ^[0-9]+$ ]] || c=0
  worker_recv_total=$((worker_recv_total + c))
done < <(worker_logs)
master_success="$({ tail_from "$LOG_MASTER" "$base_master" | rg -F "\"msg\":\"response_step_result_received\"" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | rg -F "\"status\":\"SUCCEEDED\"" | sed -n 's/.*"js_seq":\([0-9]\+\).*/\1/p' | sort -u | wc -l | tr -d '[:space:]'; } || true)"
[[ "$exec_start" =~ ^[0-9]+$ ]] || exec_start=0
[[ "$master_success" =~ ^[0-9]+$ ]] || master_success=0
[[ "$worker_recv_total" =~ ^[0-9]+$ ]] || worker_recv_total=0
[[ "$exec_start" == "1" ]] || die "agent_command_exec_start count=${exec_start}, expected 1" "$RUN_ID"
[[ "$worker_recv_total" == "1" ]] || die "worker step_received count=${worker_recv_total}, expected 1" "$RUN_ID"
[[ "$master_success" == "1" ]] || die "master response_step_result_received(SUCCEEDED) unique-js_seq count=${master_success}, expected 1" "$RUN_ID"

echo "$run_line"
echo "$waiting_line"
echo "$step_pub_line"
echo "$exec_start_line"
echo "$master_success_line"
echo "Counts: while_down_step_received=${down_recv} after_start_step_received=${recv} after_start_step_succeeded=${succeeded} worker_step_received_total=${worker_recv_total} exec_start=${exec_start} master_step_result_success_unique=${master_success}"
echo "PASS: M61 worker down queue then consume proof run_id=${RUN_ID} step_id=${STEP_ID} lane=${TARGET_LANE}"
exit 0
