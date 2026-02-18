#!/usr/bin/env bash
set -euo pipefail

LOG_MASTER="logs/master-roe.log"
LOG_WORKER="logs/worker.m69.log"
LOG_AGENT="logs/agent.log"
DEMO_LOG="tmp/demo.log"
PID_FILE=".cache/m69.worker.pid"

mkdir -p logs tmp .cache .cache/go-build

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

find_worker_lines() {
  local line pid cmd
  while IFS= read -r line; do
    line="${line#"${line%%[![:space:]]*}"}"
    [[ -n "$line" ]] || continue
    pid="${line%% *}"
    cmd="${line#* }"

    case "$cmd" in
      *" rg "*|*" grep "*|*" pgrep "*|*" awk "*|*" sed "*) continue ;;
      *"m69_worker_restart_around_result_commit_exactly_once.sh"*) continue ;;
      "bash "*|"sh "*) continue ;;
    esac

    if [[ "$cmd" =~ (^|[[:space:]])[^[:space:]]*cmd/master-roe-worker([[:space:]]|$) ]] || [[ "$cmd" =~ (^|[[:space:]])[^[:space:]]*/master-roe-worker([[:space:]]|$) ]] || [[ "$cmd" == *"master-roe-worker --config"* ]]; then
      printf "%s\t%s\n" "$pid" "$cmd"
    fi
  done < <(ps -eo pid=,args=)
}

external_worker_lines() {
  local managed_pid="${1:-}"
  if [[ -n "$managed_pid" ]]; then
    find_worker_lines | awk -F'\t' -v pid="$managed_pid" '$1 != pid { print }'
  else
    find_worker_lines
  fi
}

worker_pids() {
  find_worker_lines | awk -F'\t' '{print $1}'
}

start_worker() {
  env GOCACHE="$(pwd)/.cache/go-build" go run -mod=vendor ./cmd/master-roe-worker --config configs/master.yaml >> "$LOG_WORKER" 2>&1 &
  local pid="$!"
  echo "$pid" > "$PID_FILE"
  sleep 1
  kill -0 "$pid" 2>/dev/null || return 1
}

stop_worker() {
  local pid=""
  if [[ -f "$PID_FILE" ]]; then
    pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  fi

  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    local i=0
    while (( i < 20 )); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.1
      i=$((i+1))
    done
    kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null || true
  fi
  rm -f "$PID_FILE"

  # `go run` may leave compiled child worker alive; clear remaining worker pids for loop-safety.
  while IFS= read -r p; do
    [[ -n "$p" ]] || continue
    kill "$p" 2>/dev/null || true
  done < <(worker_pids)
  sleep 0.1
  while IFS= read -r p; do
    [[ -n "$p" ]] || continue
    kill -9 "$p" 2>/dev/null || true
  done < <(worker_pids)
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
  echo "--- $LOG_WORKER ---" >&2
  if [[ -n "$run_id" ]]; then
    rg -F "\"run_id\":\"${run_id}\"" "$LOG_WORKER" | tail -n 140 >&2 || true
  else
    tail -n 140 "$LOG_WORKER" >&2 || true
  fi

  if [[ -f "$LOG_AGENT" ]]; then
    echo "Context: agent (last 120 relevant):" >&2
    if [[ -n "$run_id" ]]; then
      rg -F "\"run_id\":\"${run_id}\"" "$LOG_AGENT" | tail -n 120 >&2 || true
    else
      tail -n 120 "$LOG_AGENT" >&2 || true
    fi
  fi
}

die() {
  echo "FAIL: $1"
  [[ -n "${2:-}" ]] && debug_fail "$2"
  exit 1
}

echo "=== M69 worker restart around result commit exactly once ==="

command -v rg >/dev/null 2>&1 || die "missing required tool: rg"
command -v nats >/dev/null 2>&1 || die "missing required tool: nats"

[[ -s "$LOG_MASTER" ]] || die "missing or empty $LOG_MASTER"
[[ -f "$DEMO_LOG" ]] || touch "$DEMO_LOG"
[[ -s "$LOG_AGENT" ]] || die "missing or empty $LOG_AGENT"
: > "$LOG_WORKER"

external_lines="$(external_worker_lines)"
if [[ -n "$external_lines" ]]; then
  echo "FAIL: Stop external master-roe-worker processes before running M69."
  exit 1
fi

cleanup() { stop_worker || true; }
trap cleanup EXIT INT TERM

start_worker || die "failed to start managed worker"

base_master="$(line_count "$LOG_MASTER")"
base_worker="$(line_count "$LOG_WORKER")"
base_agent="$(line_count "$LOG_AGENT")"

NOW="$(date +%s)"
OCT=$(( (NOW % 180) + 20 ))
echo "M69 invalid user from 10.0.0.${OCT} ts=${NOW}" >> "$DEMO_LOG"

run_line="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"response_run_created\".*\"rule_id\":\"R-COLLECT-INVALID-USER\".*\"playbook_id\":\"PB-AGENT-PING-LOCALHOST\"" 60 || true)"
[[ -n "$run_line" ]] || die "timeout waiting for invalid-user run_created"
RUN_ID="$(printf "%s\n" "$run_line" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"
[[ -n "$RUN_ID" ]] || die "unable to parse run_id"

RUN_ID="$RUN_ID"
nats pub rsiem.response.approvals "{\"run_id\":\"$RUN_ID\",\"decision\":\"approve\",\"actor\":\"khotso\"}" >/dev/null \
  || die "approval command failed for run_id=${RUN_ID}" "$RUN_ID"

step_pub_line="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"response_step_published\".*\"run_id\":\"${RUN_ID}\"" 60 || true)"
[[ -n "$step_pub_line" ]] || die "response_step_published missing for run_id=${RUN_ID}" "$RUN_ID"
STEP_ID="$(printf "%s\n" "$step_pub_line" | sed -n 's/.*"step_id":"\([^"]*\)".*/\1/p')"
STEP_SUBJECT="$(printf "%s\n" "$step_pub_line" | sed -n 's/.*"step_subject":"\([^"]*\)".*/\1/p')"
[[ -n "$STEP_ID" && -n "$STEP_SUBJECT" ]] || die "unable to parse step_id/step_subject" "$RUN_ID"

if [[ "$STEP_SUBJECT" == *".fast" ]]; then
  LANE="FAST"
elif [[ "$STEP_SUBJECT" == *".standard" ]]; then
  LANE="STANDARD"
else
  die "unable to derive lane from step_subject=${STEP_SUBJECT}" "$RUN_ID"
fi

boundary_line=""
for i in $(seq 1 120); do
  boundary_line="$(tail_from "$LOG_WORKER" "$base_worker" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | rg '"msg":"agent_command_reply"|"msg":"step_succeeded"' | head -n 1 || true)"
  [[ -n "$boundary_line" ]] && break
  sleep 1
done
[[ -n "$boundary_line" ]] || die "did not observe boundary marker (agent_command_reply or step_succeeded) for run_id=${RUN_ID} step_id=${STEP_ID}" "$RUN_ID"

stop_worker
start_worker || die "failed to restart worker around result-commit boundary" "$RUN_ID"

worker_success_line="$(wait_match "$LOG_WORKER" "$base_worker" "\"msg\":\"step_succeeded\".*\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\"" 120 || true)"
[[ -n "$worker_success_line" ]] || die "worker step_succeeded missing for run_id=${RUN_ID} step_id=${STEP_ID}" "$RUN_ID"

master_success_line="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"response_step_result_received\".*\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\".*\"status\":\"SUCCEEDED\"" 120 || true)"
[[ -n "$master_success_line" ]] || die "master SUCCEEDED result missing for run_id=${RUN_ID} step_id=${STEP_ID}" "$RUN_ID"

worker_step_received_total="$({ tail_from "$LOG_WORKER" "$base_worker" | rg -F "\"msg\":\"step_received\"" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | wc -l | tr -d '[:space:]'; } || true)"
worker_step_succeeded="$({ tail_from "$LOG_WORKER" "$base_worker" | rg -F "\"msg\":\"step_succeeded\"" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | wc -l | tr -d '[:space:]'; } || true)"
agent_exec_start="$({ tail_from "$LOG_AGENT" "$base_agent" | rg -F "\"msg\":\"agent_command_exec_start\"" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | wc -l | tr -d '[:space:]'; } || true)"
master_success_unique_js_seq="$({ tail_from "$LOG_MASTER" "$base_master" | rg -F "\"msg\":\"response_step_result_received\"" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | rg -F "\"status\":\"SUCCEEDED\"" | sed -n 's/.*"js_seq":\([0-9]\+\).*/\1/p' | sort -u | wc -l | tr -d '[:space:]'; } || true)"

result_applied_any_count="$({ tail_from "$LOG_MASTER" "$base_master" | rg -F "\"msg\":\"response_result_applied\"" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | wc -l | tr -d '[:space:]'; } || true)"
result_applied_succeeded_count="$({ tail_from "$LOG_MASTER" "$base_master" | rg -F "\"msg\":\"response_result_applied\"" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | rg -F "\"status\":\"SUCCEEDED\"" | wc -l | tr -d '[:space:]'; } || true)"

[[ "$worker_step_received_total" =~ ^[0-9]+$ ]] || worker_step_received_total=0
[[ "$worker_step_succeeded" =~ ^[0-9]+$ ]] || worker_step_succeeded=0
[[ "$agent_exec_start" =~ ^[0-9]+$ ]] || agent_exec_start=0
[[ "$master_success_unique_js_seq" =~ ^[0-9]+$ ]] || master_success_unique_js_seq=0
[[ "$result_applied_any_count" =~ ^[0-9]+$ ]] || result_applied_any_count=0
[[ "$result_applied_succeeded_count" =~ ^[0-9]+$ ]] || result_applied_succeeded_count=0

[[ "$worker_step_succeeded" == "1" ]] || die "worker_step_succeeded=${worker_step_succeeded}, expected 1" "$RUN_ID"
[[ "$agent_exec_start" == "1" ]] || die "agent_command_exec_start count=${agent_exec_start}, expected 1" "$RUN_ID"
[[ "$master_success_unique_js_seq" == "1" ]] || die "master_success_unique_js_seq=${master_success_unique_js_seq}, expected 1" "$RUN_ID"
if (( result_applied_any_count > 0 )); then
  [[ "$result_applied_succeeded_count" == "1" ]] || die "response_result_applied(SUCCEEDED) count=${result_applied_succeeded_count}, expected 1" "$RUN_ID"
fi

echo "$run_line"
echo "$step_pub_line"
echo "$master_success_line"
echo "Counts: worker_step_received_total=${worker_step_received_total} worker_step_succeeded=${worker_step_succeeded} agent_exec_start=${agent_exec_start} master_success_unique_js_seq=${master_success_unique_js_seq}"
echo "PASS: M69 worker restart around result commit exactly once run_id=${RUN_ID} step_id=${STEP_ID} lane=${LANE}"
exit 0
