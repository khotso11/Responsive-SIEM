#!/usr/bin/env bash
set -euo pipefail

LOG_MASTER="logs/master-roe.log"
LOG_AGENT="logs/agent.log"
LOG_WORKER="logs/worker.m66.log"
DEMO_LOG="tmp/demo.log"
PID_FILE=".cache/m66.worker.pid"

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

worker_process_lines() {
  local line pid cmd
  while IFS= read -r line; do
    line="${line#"${line%%[![:space:]]*}"}"
    [[ -n "$line" ]] || continue
    pid="${line%% *}"
    cmd="${line#* }"

    case "$cmd" in
      *" rg "*|*" grep "*|*" pgrep "*|*" awk "*|*" sed "*) continue ;;
      *"m66_worker_crash_after_step_succeeded_before_result_publish_proof.sh"*) continue ;;
      "bash "*|"sh "*) continue ;;
    esac

    if [[ "$cmd" == *"cmd/master-roe-worker"* ]] || [[ "$cmd" == *"master-roe-worker --config"* ]] || [[ "$cmd" == */master-roe-worker ]] || [[ "$cmd" == */master-roe-worker\ * ]]; then
      printf "%s\t%s\n" "$pid" "$cmd"
    fi
  done < <(ps -eo pid=,args=)
}

assert_no_external_workers() {
  local lines
  lines="$(worker_process_lines)"
  if [[ -n "$lines" ]]; then
    echo "Detected external worker processes:" >&2
    echo "$lines" | awk -F'\t' '{printf "  pid=%s cmd=%s\n", $1, $2}' >&2
    die "Stop external master-roe-worker processes before running M66. Hint: pkill -f cmd/master-roe-worker ; pkill -f '/master-roe-worker(\\s|$)'"
  fi
}

managed_pid() {
  [[ -f "$PID_FILE" ]] || return 1
  local pid
  pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  [[ -n "$pid" ]] || return 1
  kill -0 "$pid" 2>/dev/null || return 1
  echo "$pid"
}

start_worker() {
  local lane="$1"
  local delay_ms="${2:-0}"
  local pid

  if [[ "$delay_ms" =~ ^[1-9][0-9]*$ ]]; then
    env GOCACHE="$(pwd)/.cache/go-build" RSIEM_TEST_DELAY_RESULT_PUBLISH_MS="$delay_ms" \
      go run -mod=vendor ./cmd/master-roe-worker --config configs/master.yaml -lane "$lane" >> "$LOG_WORKER" 2>&1 &
  else
    env GOCACHE="$(pwd)/.cache/go-build" \
      go run -mod=vendor ./cmd/master-roe-worker --config configs/master.yaml -lane "$lane" >> "$LOG_WORKER" 2>&1 &
  fi
  pid="$!"
  echo "$pid" > "$PID_FILE"
  sleep 1
  kill -0 "$pid" 2>/dev/null || return 1
}

stop_worker() {
  [[ -f "$PID_FILE" ]] || return 0
  local pid
  pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  [[ -n "$pid" ]] || { rm -f "$PID_FILE"; return 0; }
  if kill -0 "$pid" 2>/dev/null; then
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
}

crash_worker() {
  local pid
  pid="$(managed_pid || true)"
  [[ -n "$pid" ]] || return 1
  kill -9 "$pid" 2>/dev/null || true
  rm -f "$PID_FILE"
  return 0
}

debug_fail() {
  local run_id="$1"
  echo "Context: master (last 140 relevant):" >&2
  rg -F "\"run_id\":\"${run_id}\"" "$LOG_MASTER" | tail -n 140 >&2 || true
  echo "Context: worker (last 140 relevant):" >&2
  echo "--- $LOG_WORKER ---" >&2
  rg -F "\"run_id\":\"${run_id}\"" "$LOG_WORKER" | tail -n 140 >&2 || true
  echo "Context: agent (last 140 relevant):" >&2
  rg -F "\"run_id\":\"${run_id}\"" "$LOG_AGENT" | tail -n 140 >&2 || true
}

die() {
  echo "FAIL: $1"
  [[ -n "${2:-}" ]] && debug_fail "$2"
  exit 1
}

echo "=== M66 worker crash after step_succeeded before result publish proof ==="

for tool in rg nats go ps awk sed pkill kill; do
  command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
done
[[ -s "$LOG_MASTER" ]] || die "missing or empty $LOG_MASTER"
[[ -s "$LOG_AGENT" ]] || die "missing or empty $LOG_AGENT"
[[ -f "$DEMO_LOG" ]] || touch "$DEMO_LOG"
: > "$LOG_WORKER"

assert_no_external_workers

cleanup() { stop_worker || true; }
trap cleanup EXIT INT TERM

base_master="$(line_count "$LOG_MASTER")"
base_agent="$(line_count "$LOG_AGENT")"
base_worker="$(line_count "$LOG_WORKER")"

NOW="$(date +%s)"
OCT=$(( (NOW % 180) + 20 ))
echo "M66 invalid user from 10.0.0.${OCT} ts=${NOW}" >> "$DEMO_LOG"

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

start_worker "$TARGET_LANE" 4000 || die "failed to start worker lane=${TARGET_LANE}" "$RUN_ID"

succeeded_line="$(wait_match "$LOG_WORKER" "$base_worker" "\"msg\":\"step_succeeded\".*\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\"" 120 || true)"
[[ -n "$succeeded_line" ]] || die "worker step_succeeded not observed before crash window run_id=${RUN_ID}" "$RUN_ID"

crash_worker || die "unable to crash managed worker after step_succeeded run_id=${RUN_ID}" "$RUN_ID"

master_success_pre="$({ tail_from "$LOG_MASTER" "$base_master" | rg -F "\"msg\":\"response_step_result_received\"" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | rg -F "\"status\":\"SUCCEEDED\"" | wc -l | tr -d '[:space:]'; } || true)"
[[ "$master_success_pre" =~ ^[0-9]+$ ]] || master_success_pre=0
[[ "$master_success_pre" == "0" ]] || die "master observed SUCCEEDED before worker restart (missed crash window); increase delay hook" "$RUN_ID"

start_worker "$TARGET_LANE" 0 || die "failed to restart worker lane=${TARGET_LANE}" "$RUN_ID"

master_success_line="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"response_step_result_received\".*\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\".*\"status\":\"SUCCEEDED\"" 120 || true)"
[[ -n "$master_success_line" ]] || die "no master SUCCEEDED result after worker restart run_id=${RUN_ID}" "$RUN_ID"

worker_step_received_total="$({ tail_from "$LOG_WORKER" "$base_worker" | rg -F "\"msg\":\"step_received\"" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | wc -l | tr -d '[:space:]'; } || true)"
worker_step_succeeded="$({ tail_from "$LOG_WORKER" "$base_worker" | rg -F "\"msg\":\"step_succeeded\"" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | wc -l | tr -d '[:space:]'; } || true)"
agent_exec_start="$({ tail_from "$LOG_AGENT" "$base_agent" | rg -F "\"msg\":\"agent_command_exec_start\"" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | wc -l | tr -d '[:space:]'; } || true)"
master_success_unique_js_seq="$({ tail_from "$LOG_MASTER" "$base_master" | rg -F "\"msg\":\"response_step_result_received\"" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | rg -F "\"status\":\"SUCCEEDED\"" | sed -n 's/.*"js_seq":\([0-9]\+\).*/\1/p' | sort -u | wc -l | tr -d '[:space:]'; } || true)"

[[ "$worker_step_received_total" =~ ^[0-9]+$ ]] || worker_step_received_total=0
[[ "$worker_step_succeeded" =~ ^[0-9]+$ ]] || worker_step_succeeded=0
[[ "$agent_exec_start" =~ ^[0-9]+$ ]] || agent_exec_start=0
[[ "$master_success_unique_js_seq" =~ ^[0-9]+$ ]] || master_success_unique_js_seq=0

[[ "$agent_exec_start" == "1" ]] || die "agent_command_exec_start count=${agent_exec_start}, expected 1" "$RUN_ID"
[[ "$master_success_unique_js_seq" == "1" ]] || die "master success unique js_seq count=${master_success_unique_js_seq}, expected 1" "$RUN_ID"

echo "$run_line"
echo "$waiting_line"
echo "$step_pub_line"
echo "$succeeded_line"
echo "$master_success_line"
echo "Counts: worker_step_received_total=${worker_step_received_total} worker_step_succeeded=${worker_step_succeeded} agent_exec_start=${agent_exec_start} master_success_unique_js_seq=${master_success_unique_js_seq}"
echo "PASS: M66 worker crash after step_succeeded before result publish proof run_id=${RUN_ID} step_id=${STEP_ID} lane=${TARGET_LANE}"
exit 0
