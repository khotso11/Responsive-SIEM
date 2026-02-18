#!/usr/bin/env bash
set -euo pipefail

# How to run:
# cd ~/projects/r-siem-agent
# bash -n scripts/m63_worker_and_agent_down_combined_recovery_proof.sh
# ./scripts/m63_worker_and_agent_down_combined_recovery_proof.sh ; echo "rc=$?"

LOG_MASTER="logs/master-roe.log"
LOG_AGENT="logs/agent.m63.log"
DEMO_LOG="tmp/demo.log"
PID_FILE="tmp/m63.agent.pid"

mkdir -p logs tmp
touch "$LOG_AGENT"

line_count() { [[ -f "$1" ]] && wc -l < "$1" | tr -d ' ' || echo 0; }
tail_from() { tail -n "+$(( $2 + 1 ))" "$1" 2>/dev/null || true; }

wait_match() {
  local file="$1" base="$2" pattern="$3" timeout="$4"
  local i=0
  while (( i < timeout )); do
    local line
    line="$(tail_from "$file" "$base" | rg "$pattern" | head -n 1 || true)"
    [[ -n "$line" ]] && { echo "$line"; return 0; }
    sleep 1
    i=$((i+1))
  done
  return 1
}

worker_logs() {
  local out=()
  for f in logs/*.log; do
    [[ -f "$f" ]] || continue
    case "$f" in
      *worker*) out+=("$f") ;;
    esac
  done
  printf "%s\n" "${out[@]}" | awk 'NF' | awk '!s[$0]++'
}

external_agent_pids() {
  pgrep -af 'cmd/agent' | awk '{print $1}' || true
}

start_agent() {
  if [[ -f "$PID_FILE" ]]; then
    local old_pid
    old_pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
      return 0
    fi
  fi
  go run -mod=vendor ./cmd/agent --config configs/agent.yaml >> "$LOG_AGENT" 2>&1 &
  local pid="$!"
  echo "$pid" > "$PID_FILE"
  sleep 1
  kill -0 "$pid" 2>/dev/null || return 1
}

stop_agent() {
  [[ -f "$PID_FILE" ]] || return 0
  local pid
  pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  [[ -n "$pid" ]] || { rm -f "$PID_FILE"; return 0; }
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    local i=0
    while (( i < 20 )); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.2
      i=$((i+1))
    done
    kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null || true
  fi
  rm -f "$PID_FILE"
}

debug_fail() {
  local run_id="${1:-}"
  echo "Context: master (last 140 relevant):" >&2
  if [[ -n "$run_id" ]]; then
    rg -F "\"run_id\":\"${run_id}\"" "$LOG_MASTER" | tail -n 140 >&2 || true
  else
    tail -n 140 "$LOG_MASTER" >&2 || true
  fi
  echo "Context: worker (last 140 relevant):" >&2
  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    echo "--- $f ---" >&2
    if [[ -n "$run_id" ]]; then
      rg -F "\"run_id\":\"${run_id}\"" "$f" | tail -n 140 >&2 || true
    else
      tail -n 140 "$f" >&2 || true
    fi
  done < <(worker_logs)
  echo "Context: agent (last 140 relevant):" >&2
  if [[ -n "$run_id" ]]; then
    rg -F "\"run_id\":\"${run_id}\"" "$LOG_AGENT" | tail -n 140 >&2 || true
  else
    tail -n 140 "$LOG_AGENT" >&2 || true
  fi
}

die() {
  echo "FAIL: $1"
  [[ -n "${2:-}" ]] && debug_fail "$2"
  exit 1
}

echo "=== M63 worker+agent down combined recovery proof ==="

command -v rg >/dev/null 2>&1 || die "missing required tool: rg"
command -v nats >/dev/null 2>&1 || die "missing required tool: nats"
[[ -s "$LOG_MASTER" ]] || die "missing or empty $LOG_MASTER"
[[ -f "$DEMO_LOG" ]] || touch "$DEMO_LOG"

cleanup() { stop_agent || true; }
trap cleanup EXIT

ext_agent_pids="$(external_agent_pids)"
[[ -z "$ext_agent_pids" ]] || die "Stop external agent because M63 manages its own agent instance."

# Ensure managed agent is down at approval time.
stop_agent

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
echo "M63 invalid user from 10.0.0.${OCT} ts=${NOW}" >> "$DEMO_LOG"

run_line="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"response_run_created\".*\"rule_id\":\"R-COLLECT-INVALID-USER\".*\"playbook_id\":\"PB-AGENT-PING-LOCALHOST\"" 60 || true)"
[[ -n "$run_line" ]] || die "timeout waiting for invalid-user run_created"
RUN_ID="$(printf "%s\n" "$run_line" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"
[[ -n "$RUN_ID" ]] || die "unable to parse run_id"

waiting_line="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"response_run_waiting_approval\".*\"run_id\":\"${RUN_ID}\"" 60 || true)"
[[ -n "$waiting_line" ]] || die "waiting_approval not found for run_id=${RUN_ID}" "$RUN_ID"

RUN_ID="$RUN_ID"
nats pub rsiem.response.approvals "{\"run_id\":\"$RUN_ID\",\"decision\":\"approve\",\"actor\":\"khotso\"}" >/dev/null \
  || die "approval command failed for run_id=${RUN_ID}" "$RUN_ID"

step_pub_line="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"response_step_published\".*\"run_id\":\"${RUN_ID}\"" 60 || true)"
[[ -n "$step_pub_line" ]] || die "no response_step_published after approval for run_id=${RUN_ID}" "$RUN_ID"
STEP_ID="$(printf "%s\n" "$step_pub_line" | sed -n 's/.*"step_id":"\([^"]*\)".*/\1/p')"
STEP_SUBJECT="$(printf "%s\n" "$step_pub_line" | sed -n 's/.*"step_subject":"\([^"]*\)".*/\1/p')"
[[ -n "$STEP_ID" && -n "$STEP_SUBJECT" ]] || die "unable to parse step_id/step_subject" "$RUN_ID"

if [[ "$STEP_SUBJECT" == *".fast" ]]; then
  TARGET_LANE="FAST"
elif [[ "$STEP_SUBJECT" == *".standard" ]]; then
  TARGET_LANE="STANDARD"
else
  die "unable to derive lane from step_subject=${STEP_SUBJECT}" "$RUN_ID"
fi

while_down_step_received=0
for idx in "${!worker_files[@]}"; do
  f="${worker_files[$idx]}"
  b="${worker_bases[$idx]}"
  c="$({ tail_from "$f" "$b" | rg -F "\"msg\":\"step_received\"" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | wc -l | tr -d '[:space:]'; } || true)"
  [[ "$c" =~ ^[0-9]+$ ]] || c=0
  while_down_step_received=$((while_down_step_received + c))
done
(( while_down_step_received == 0 )) || die "step_received observed while worker expected down (count=${while_down_step_received})" "$RUN_ID"

echo "ACTION: start ${TARGET_LANE} worker now in another terminal:"
if [[ "$TARGET_LANE" == "FAST" ]]; then
  echo "cd ~/projects/r-siem-agent && mkdir -p logs && go run -mod=vendor ./cmd/master-roe-worker --config configs/master.yaml -lane FAST | tee -a logs/worker-f.log"
else
  echo "cd ~/projects/r-siem-agent && mkdir -p logs && go run -mod=vendor ./cmd/master-roe-worker --config configs/master.yaml -lane STANDARD | tee -a logs/worker-s.log"
fi
read -r -p "Press Enter after worker is running..." _

recv_line=""
i=0
while (( i < 60 )); do
  down_success=0
  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    s="$({ rg -F "\"msg\":\"step_succeeded\"" "$f" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | wc -l | tr -d '[:space:]'; } || true)"
    [[ "$s" =~ ^[0-9]+$ ]] || s=0
    down_success=$((down_success + s))
  done < <(worker_logs)
  (( down_success == 0 )) || die "step_succeeded observed while agent still down before retry proof" "$RUN_ID"

  for idx in "${!worker_files[@]}"; do
    f="${worker_files[$idx]}"
    b="${worker_bases[$idx]}"
    line="$(tail_from "$f" "$b" | rg -F "\"msg\":\"step_received\"" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | rg -F "\"lane\":\"${TARGET_LANE}\"" | head -n 1 || true)"
    if [[ -n "$line" ]]; then
      recv_line="$line"
      break
    fi
  done
  [[ -n "$recv_line" ]] && break
  sleep 1
  i=$((i+1))
done
[[ -n "$recv_line" ]] || die "no step_received after starting ${TARGET_LANE} worker" "$RUN_ID"

attempt2_line=""
transient_count=0
transient_max_attempt=0
i=0
while (( i < 120 )); do
  down_success=0
  transient_count=0
  transient_max_attempt=0

  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    s="$({ rg -F "\"msg\":\"step_succeeded\"" "$f" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | wc -l | tr -d '[:space:]'; } || true)"
    [[ "$s" =~ ^[0-9]+$ ]] || s=0
    down_success=$((down_success + s))

    c="$({ rg -F "\"msg\":\"step_failed_transient\"" "$f" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | wc -l | tr -d '[:space:]'; } || true)"
    [[ "$c" =~ ^[0-9]+$ ]] || c=0
    transient_count=$((transient_count + c))

    m="$({ rg -F "\"msg\":\"step_failed_transient\"" "$f" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | sed -n 's/.*"attempt":\([0-9]\+\).*/\1/p' | sort -nr | head -n 1 | tr -d '[:space:]'; } || true)"
    [[ "$m" =~ ^[0-9]+$ ]] || m=0
    (( m > transient_max_attempt )) && transient_max_attempt="$m"
  done < <(worker_logs)

  (( down_success == 0 )) || die "step_succeeded observed while agent still down before retry proof" "$RUN_ID"

  for idx in "${!worker_files[@]}"; do
    f="${worker_files[$idx]}"
    b="${worker_bases[$idx]}"
    line="$(tail_from "$f" "$b" | rg -F "\"msg\":\"step_failed_transient\"" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | rg '"attempt":([2-9]|[1-9][0-9]+)' | head -n 1 || true)"
    if [[ -n "$line" ]]; then
      attempt2_line="$line"
      break
    fi
  done

  [[ -n "$attempt2_line" ]] && break
  sleep 1
  i=$((i+1))
done
[[ -n "$attempt2_line" ]] || die "transient retry proof missing: expected step_failed_transient attempt>=2 while agent down" "$RUN_ID"

base_agent_restart="$(line_count "$LOG_AGENT")"
start_agent || die "failed to start managed agent for recovery" "$RUN_ID"

worker_success_line=""
i=0
while (( i < 120 )); do
  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    line="$(rg -F "\"msg\":\"step_succeeded\"" "$f" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | head -n 1 || true)"
    if [[ -n "$line" ]]; then
      worker_success_line="$line"
      break
    fi
  done < <(worker_logs)
  [[ -n "$worker_success_line" ]] && break
  sleep 1
  i=$((i+1))
done
[[ -n "$worker_success_line" ]] || die "no worker step_succeeded after agent recovery" "$RUN_ID"

master_success_line="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"response_step_result_received\".*\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\".*\"status\":\"SUCCEEDED\"" 120 || true)"
[[ -n "$master_success_line" ]] || die "no master SUCCEEDED result after agent recovery" "$RUN_ID"

worker_step_succeeded_count=0
worker_step_received_total=0
while IFS= read -r f; do
  [[ -n "$f" ]] || continue
  c1="$({ rg -F "\"msg\":\"step_succeeded\"" "$f" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | wc -l | tr -d '[:space:]'; } || true)"
  c2="$({ rg -F "\"msg\":\"step_received\"" "$f" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | wc -l | tr -d '[:space:]'; } || true)"
  [[ "$c1" =~ ^[0-9]+$ ]] || c1=0
  [[ "$c2" =~ ^[0-9]+$ ]] || c2=0
  worker_step_succeeded_count=$((worker_step_succeeded_count + c1))
  worker_step_received_total=$((worker_step_received_total + c2))
done < <(worker_logs)

agent_exec_start="$({ tail_from "$LOG_AGENT" "$base_agent_restart" | rg -F "\"msg\":\"agent_command_exec_start\"" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | wc -l | tr -d '[:space:]'; } || true)"
[[ "$agent_exec_start" =~ ^[0-9]+$ ]] || agent_exec_start=0

master_success_unique_js_seq="$({ tail_from "$LOG_MASTER" "$base_master" | rg -F "\"msg\":\"response_step_result_received\"" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | rg -F "\"status\":\"SUCCEEDED\"" | sed -n 's/.*"js_seq":\([0-9]\+\).*/\1/p' | sort -u | wc -l | tr -d '[:space:]'; } || true)"
[[ "$master_success_unique_js_seq" =~ ^[0-9]+$ ]] || master_success_unique_js_seq=0

[[ "$worker_step_succeeded_count" == "1" ]] || die "worker step_succeeded count=${worker_step_succeeded_count}, expected 1" "$RUN_ID"
[[ "$agent_exec_start" == "1" ]] || die "agent_command_exec_start count=${agent_exec_start}, expected 1" "$RUN_ID"
[[ "$master_success_unique_js_seq" == "1" ]] || die "master SUCCEEDED unique js_seq count=${master_success_unique_js_seq}, expected 1" "$RUN_ID"

echo "$run_line"
echo "$waiting_line"
echo "$step_pub_line"
echo "$recv_line"
echo "$attempt2_line"
echo "$worker_success_line"
echo "$master_success_line"
echo "Counts: transient_failures=${transient_count} transient_max_attempt=${transient_max_attempt} worker_step_received_total=${worker_step_received_total} worker_step_succeeded=${worker_step_succeeded_count} agent_exec_start=${agent_exec_start} master_success_unique_js_seq=${master_success_unique_js_seq}"
echo "PASS: M63 worker+agent down combined recovery proof run_id=${RUN_ID} step_id=${STEP_ID} lane=${TARGET_LANE}"
exit 0
