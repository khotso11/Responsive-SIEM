#!/usr/bin/env bash
set -euo pipefail

MASTER_LOG="logs/master.m67.log"
AGENT_LOG="logs/agent.log"
DEMO_LOG="tmp/demo.log"
PID_FILE=".cache/m67.master.pid"

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

worker_logs() {
  local out=()
  for f in logs/*worker*.log logs/worker-*.log; do
    [[ -f "$f" ]] || continue
    out+=("$f")
  done
  printf "%s\n" "${out[@]}" | awk 'NF' | awk '!s[$0]++'
}

find_master_pids() {
  local line pid cmd
  while IFS= read -r line; do
    line="${line#"${line%%[![:space:]]*}"}"
    [[ -n "$line" ]] || continue
    pid="${line%% *}"
    cmd="${line#* }"

    case "$cmd" in
      *" rg "*|*" grep "*|*" pgrep "*|*" awk "*|*" sed "*) continue ;;
      *"m67_master_restart_around_approval_boundary_no_missed_duplicated_publishes.sh"*) continue ;;
      "bash "*|"sh "*) continue ;;
    esac

    if [[ "$cmd" =~ (^|[[:space:]])[^[:space:]]*cmd/master-roe([[:space:]]|$) ]] || [[ "$cmd" =~ (^|[[:space:]])[^[:space:]]*/master-roe([[:space:]]|$) ]]; then
      echo "$pid"
    fi
  done < <(ps -eo pid=,args=)
}

find_worker_pids() {
  ps -eo pid=,args= | awk '
    {
      pid=$1
      $1=""
      sub(/^ +/, "", $0)
      cmd=$0
      if (cmd ~ /(^|[[:space:]])(rg|grep|pgrep|awk|sed)([[:space:]]|$)/) next
      if (cmd ~ /master-roe-worker/) print pid
    }
  '
}

find_agent_pids() {
  ps -eo pid=,args= | awk '
    {
      pid=$1
      $1=""
      sub(/^ +/, "", $0)
      cmd=$0
      if (cmd ~ /(^|[[:space:]])(rg|grep|pgrep|awk|sed)([[:space:]]|$)/) next
      if (cmd ~ /cmd\/agent/ || cmd ~ /(^|[[:space:]])[^[:space:]]*\/agent([[:space:]]|$)/) print pid
    }
  '
}

start_master() {
  env GOCACHE="$(pwd)/.cache/go-build" go run -mod=vendor ./cmd/master-roe --config configs/master.yaml >> "$MASTER_LOG" 2>&1 &
  local pid="$!"
  echo "$pid" > "$PID_FILE"
  sleep 1
  kill -0 "$pid" 2>/dev/null || return 1
}

stop_master() {
  [[ -f "$PID_FILE" ]] || return 0
  local pid
  pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  [[ -n "$pid" ]] || { rm -f "$PID_FILE"; return 0; }
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    local i=0
    while (( i < 30 )); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.1
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
    rg -F "\"run_id\":\"${run_id}\"" "$MASTER_LOG" | tail -n 140 >&2 || true
  else
    tail -n 140 "$MASTER_LOG" >&2 || true
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

  if [[ -f "$AGENT_LOG" ]]; then
    echo "Context: agent (last 120 relevant):" >&2
    if [[ -n "$run_id" ]]; then
      rg -F "\"run_id\":\"${run_id}\"" "$AGENT_LOG" | tail -n 120 >&2 || true
    else
      tail -n 120 "$AGENT_LOG" >&2 || true
    fi
  fi
}

die() {
  echo "FAIL: $1"
  [[ -n "${2:-}" ]] && debug_fail "$2"
  exit 1
}

echo "=== M67 master restart around approval boundary no missed duplicated publishes ==="

for t in rg nats go ps awk sed pkill kill; do
  command -v "$t" >/dev/null 2>&1 || die "missing required tool: $t"
done

[[ -f "$DEMO_LOG" ]] || touch "$DEMO_LOG"
[[ -f "$MASTER_LOG" ]] || touch "$MASTER_LOG"

ext_master_pids="$(find_master_pids | tr '\n' ' ' | xargs || true)"
[[ -z "$ext_master_pids" ]] || die "Stop external master-roe processes before running M67. M67 manages its own master instance."

if [[ -z "$(find_worker_pids | tr '\n' ' ' | xargs || true)" ]]; then
  echo "ACTION: start worker now:"
  echo "cd ~/projects/r-siem-agent && mkdir -p logs && go run -mod=vendor ./cmd/master-roe-worker --config configs/master.yaml | tee -a logs/worker-f.log"
  read -r -p "Press Enter after worker is running..." _
fi

if [[ -z "$(find_agent_pids | tr '\n' ' ' | xargs || true)" ]]; then
  echo "ACTION: start agent now:"
  echo "cd ~/projects/r-siem-agent && mkdir -p logs && go run ./cmd/agent -config configs/agent.yaml 2>&1 | tee logs/agent.log"
  read -r -p "Press Enter after agent is running..." _
fi

cleanup() { stop_master || true; }
trap cleanup EXIT INT TERM

start_master || die "failed to start managed master"

base_master="$(line_count "$MASTER_LOG")"
if [[ -f "$AGENT_LOG" ]]; then
  have_agent_log=1
  base_agent="$(line_count "$AGENT_LOG")"
else
  have_agent_log=0
  base_agent=0
fi

NOW="$(date +%s)"
OCT=$(( (NOW % 180) + 20 ))
echo "M67 invalid user from 10.0.0.${OCT} ts=${NOW}" >> "$DEMO_LOG"

waiting_line="$(wait_match "$MASTER_LOG" "$base_master" "\"msg\":\"response_run_waiting_approval\".*\"rule_id\":\"R-COLLECT-INVALID-USER\".*\"playbook_id\":\"PB-AGENT-PING-LOCALHOST\"" 60 || true)"
[[ -n "$waiting_line" ]] || die "timeout waiting for response_run_waiting_approval"
RUN_ID="$(printf "%s\n" "$waiting_line" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"
[[ -n "$RUN_ID" ]] || die "unable to parse run_id from waiting_approval line"

stop_master
start_master || die "failed to restart managed master" "$RUN_ID"
sleep 2

RUN_ID="$RUN_ID"
nats pub rsiem.response.approvals "{\"run_id\":\"$RUN_ID\",\"decision\":\"approve\",\"actor\":\"khotso\"}" >/dev/null \
  || die "approval command failed for run_id=${RUN_ID}" "$RUN_ID"

approval_received_line="$(wait_match "$MASTER_LOG" "$base_master" "\"msg\":\"approval_received\".*\"run_id\":\"${RUN_ID}\"" 60 || true)"
[[ -n "$approval_received_line" ]] || die "approval_received missing for run_id=${RUN_ID}" "$RUN_ID"

step_pub_line="$(wait_match "$MASTER_LOG" "$base_master" "\"msg\":\"response_step_published\".*\"run_id\":\"${RUN_ID}\"" 60 || true)"
[[ -n "$step_pub_line" ]] || die "response_step_published missing for run_id=${RUN_ID}" "$RUN_ID"
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

result_ok_line="$(wait_match "$MASTER_LOG" "$base_master" "\"msg\":\"response_step_result_received\".*\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\".*\"status\":\"SUCCEEDED\"" 120 || true)"
[[ -n "$result_ok_line" ]] || die "master SUCCEEDED result not observed for run_id=${RUN_ID}" "$RUN_ID"

approval_received_count="$({ tail_from "$MASTER_LOG" "$base_master" | rg -F "\"msg\":\"approval_received\"" | rg -F "\"run_id\":\"${RUN_ID}\"" | wc -l | tr -d '[:space:]'; } || true)"
approval_duplicate_count="$({ tail_from "$MASTER_LOG" "$base_master" | rg -F "\"msg\":\"approval_duplicate\"" | rg -F "\"run_id\":\"${RUN_ID}\"" | wc -l | tr -d '[:space:]'; } || true)"
step_published_count="$({ tail_from "$MASTER_LOG" "$base_master" | rg -F "\"msg\":\"response_step_published\"" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | wc -l | tr -d '[:space:]'; } || true)"
master_success_unique_js_seq="$({ tail_from "$MASTER_LOG" "$base_master" | rg -F "\"msg\":\"response_step_result_received\"" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | rg -F "\"status\":\"SUCCEEDED\"" | sed -n 's/.*"js_seq":\([0-9]\+\).*/\1/p' | sort -u | wc -l | tr -d '[:space:]'; } || true)"

worker_step_received_total=0
worker_step_succeeded=0
while IFS= read -r f; do
  [[ -n "$f" ]] || continue
  c1="$({ rg -F "\"msg\":\"step_received\"" "$f" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | wc -l | tr -d '[:space:]'; } || true)"
  c2="$({ rg -F "\"msg\":\"step_succeeded\"" "$f" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | wc -l | tr -d '[:space:]'; } || true)"
  [[ "$c1" =~ ^[0-9]+$ ]] || c1=0
  [[ "$c2" =~ ^[0-9]+$ ]] || c2=0
  worker_step_received_total=$((worker_step_received_total + c1))
  worker_step_succeeded=$((worker_step_succeeded + c2))
done < <(worker_logs)

agent_exec_start=0
if [[ "$have_agent_log" == "1" ]]; then
  agent_exec_start="$({ tail_from "$AGENT_LOG" "$base_agent" | rg -F "\"msg\":\"agent_command_exec_start\"" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | wc -l | tr -d '[:space:]'; } || true)"
fi

[[ "$approval_received_count" =~ ^[0-9]+$ ]] || approval_received_count=0
[[ "$approval_duplicate_count" =~ ^[0-9]+$ ]] || approval_duplicate_count=0
[[ "$step_published_count" =~ ^[0-9]+$ ]] || step_published_count=0
[[ "$master_success_unique_js_seq" =~ ^[0-9]+$ ]] || master_success_unique_js_seq=0
[[ "$agent_exec_start" =~ ^[0-9]+$ ]] || agent_exec_start=0

(( approval_received_count >= 1 )) || die "approval_received_count=${approval_received_count}, expected >=1" "$RUN_ID"
(( approval_duplicate_count <= 1 )) || die "approval_duplicate_count=${approval_duplicate_count}, expected <=1" "$RUN_ID"
[[ "$step_published_count" == "1" ]] || die "step_published_count=${step_published_count}, expected 1" "$RUN_ID"
[[ "$master_success_unique_js_seq" == "1" ]] || die "master_success_unique_js_seq=${master_success_unique_js_seq}, expected 1" "$RUN_ID"
if [[ "$have_agent_log" == "1" ]]; then
  [[ "$agent_exec_start" == "1" ]] || die "agent_exec_start=${agent_exec_start}, expected 1" "$RUN_ID"
fi

if (( worker_step_succeeded < 1 )); then
  die "worker_step_succeeded=${worker_step_succeeded}, expected >=1" "$RUN_ID"
fi

echo "$waiting_line"
echo "$approval_received_line"
echo "$step_pub_line"
echo "$result_ok_line"
echo "Counts: approval_received_count=${approval_received_count} approval_duplicate_count=${approval_duplicate_count} step_published_count=${step_published_count} worker_step_received_total=${worker_step_received_total} worker_step_succeeded=${worker_step_succeeded} agent_exec_start=${agent_exec_start} master_success_unique_js_seq=${master_success_unique_js_seq}"
echo "PASS: M67 master restart around approval boundary no missed duplicated publishes run_id=${RUN_ID} step_id=${STEP_ID} lane=${TARGET_LANE}"
exit 0
