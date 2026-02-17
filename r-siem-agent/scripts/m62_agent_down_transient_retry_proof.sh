#!/usr/bin/env bash
set -euo pipefail

LOG_MASTER="logs/master-roe.log"
LOG_AGENT="logs/agent.m62.log"
DEMO_LOG="tmp/demo.log"
PID_FILE="tmp/m62.agent.pid"

mkdir -p logs tmp .cache/go-build
touch "$LOG_AGENT"

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
  env GOCACHE="$(pwd)/.cache/go-build" go run -mod=vendor ./cmd/agent --config configs/agent.yaml >> "$LOG_AGENT" 2>&1 &
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
  local run_id="$1"
  echo "Context: master (last 140 relevant):" >&2
  rg -F "\"run_id\":\"${run_id}\"" "$LOG_MASTER" | tail -n 140 >&2 || true
  echo "Context: worker (last 140 relevant):" >&2
  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    echo "--- $f ---" >&2
    rg -F "\"run_id\":\"${run_id}\"" "$f" | tail -n 140 >&2 || true
  done < <(worker_logs)
  echo "Context: agent (last 120 relevant):" >&2
  rg -F "\"run_id\":\"${run_id}\"" "$LOG_AGENT" | tail -n 120 >&2 || true
}

die() { echo "FAIL: $1"; [[ -n "${2:-}" ]] && debug_fail "$2"; exit 1; }

echo "=== M62 agent down transient retry proof ==="

command -v rg >/dev/null 2>&1 || die "missing required tool: rg"
command -v nats >/dev/null 2>&1 || die "M62 requires nats CLI (install or add to PATH)"
[[ -s "$LOG_MASTER" ]] || die "missing or empty $LOG_MASTER"
[[ -f "$DEMO_LOG" ]] || touch "$DEMO_LOG"

cleanup() { stop_agent || true; }
trap cleanup EXIT

ext_agent_pids="$(external_agent_pids)"
[[ -z "$ext_agent_pids" ]] || die "Stop external agent (Terminal E). M62 manages its own agent instance."

start_agent || die "failed to start managed agent"
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
echo "M62 invalid user from 10.0.0.${OCT} ts=${NOW}" >> "$DEMO_LOG"

run_line="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"response_run_created\".*\"rule_id\":\"R-COLLECT-INVALID-USER\".*\"playbook_id\":\"PB-AGENT-PING-LOCALHOST\"" 60 || true)"
[[ -n "$run_line" ]] || die "timeout waiting for invalid-user run_created"
RUN_ID="$(printf "%s\n" "$run_line" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"
[[ -n "$RUN_ID" ]] || die "unable to parse run_id"

waiting_line="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"response_run_waiting_approval\".*\"run_id\":\"${RUN_ID}\"" 60 || true)"
[[ -n "$waiting_line" ]] || die "waiting_approval not found for run_id=${RUN_ID}" "$RUN_ID"

nats pub rsiem.response.approvals "{\"run_id\":\"$RUN_ID\",\"decision\":\"approve\",\"actor\":\"khotso\"}" >/dev/null \
  || die "approval command failed for run_id=${RUN_ID}" "$RUN_ID"

step_pub_line="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"response_step_published\".*\"run_id\":\"${RUN_ID}\"" 60 || true)"
[[ -n "$step_pub_line" ]] || die "no response_step_published for run_id=${RUN_ID}" "$RUN_ID"
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

recv_line=""
i=0
while (( i < 30 )); do
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
  sleep 1; i=$((i+1))
done

if [[ -z "$recv_line" ]]; then
  echo "ACTION: start ${TARGET_LANE} worker now in another terminal:"
  if [[ "$TARGET_LANE" == "FAST" ]]; then
    echo "cd ~/projects/r-siem-agent && mkdir -p logs && go run -mod=vendor ./cmd/master-roe-worker --config configs/master.yaml -lane FAST | tee -a logs/worker-f.log"
  else
    echo "cd ~/projects/r-siem-agent && mkdir -p logs && go run -mod=vendor ./cmd/master-roe-worker --config configs/master.yaml -lane STANDARD | tee -a logs/worker-s.log"
  fi
  read -r -p "Press Enter after worker is running..." _
  i=0
  while (( i < 60 )); do
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
    sleep 1; i=$((i+1))
  done
fi
[[ -n "$recv_line" ]] || die "no step_received for run_id=${RUN_ID} step_id=${STEP_ID} lane=${TARGET_LANE}" "$RUN_ID"

attempt1_line=""
i=0
while (( i < 60 )); do
  for idx in "${!worker_files[@]}"; do
    f="${worker_files[$idx]}"
    b="${worker_bases[$idx]}"
    line="$(tail_from "$f" "$b" | rg -F "\"msg\":\"step_failed_transient\"" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | rg -F "\"attempt\":1" | head -n 1 || true)"
    if [[ -n "$line" ]]; then
      attempt1_line="$line"
      break
    fi
  done
  [[ -n "$attempt1_line" ]] && break
  sleep 1; i=$((i+1))
done
[[ -n "$attempt1_line" ]] || die "step_failed_transient attempt=1 not observed while agent down run_id=${RUN_ID} step_id=${STEP_ID}" "$RUN_ID"

next_retry_ms="$(printf "%s\n" "$attempt1_line" | sed -n 's/.*"next_retry_at_unix_ms":\([0-9]\+\).*/\1/p')"
[[ "$next_retry_ms" =~ ^[0-9]+$ ]] || die "unable to parse next_retry_at_unix_ms from attempt=1 log run_id=${RUN_ID} step_id=${STEP_ID}" "$RUN_ID"
now_ms="$(date +%s%3N)"
sleep_ms=$(( next_retry_ms - now_ms + 300 ))
if (( sleep_ms > 0 )); then
  sleep "$(awk "BEGIN { printf \"%.3f\", ${sleep_ms}/1000 }")"
fi

down_success=0
while IFS= read -r f; do
  [[ -n "$f" ]] || continue
  c="$({ rg -F "\"msg\":\"step_succeeded\"" "$f" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | wc -l | tr -d '[:space:]'; } || true)"
  [[ "$c" =~ ^[0-9]+$ ]] || c=0
  down_success=$((down_success + c))
done < <(worker_logs)
(( down_success == 0 )) || die "step_succeeded observed while agent down before attempt=2 for run_id=${RUN_ID}" "$RUN_ID"

retry_proof_kind=""
retry_proof_line=""
i=0
while (( i < 15 )); do
  down_success=0
  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    c="$({ rg -F "\"msg\":\"step_succeeded\"" "$f" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | wc -l | tr -d '[:space:]'; } || true)"
    [[ "$c" =~ ^[0-9]+$ ]] || c=0
    down_success=$((down_success + c))
  done < <(worker_logs)
  (( down_success == 0 )) || die "step_succeeded observed while agent down before retry proof for run_id=${RUN_ID}" "$RUN_ID"

  # A) step_failed_transient attempt>=2
  for idx in "${!worker_files[@]}"; do
    f="${worker_files[$idx]}"
    b="${worker_bases[$idx]}"
    line="$(tail_from "$f" "$b" | rg -F "\"msg\":\"step_failed_transient\"" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | rg -e "\"attempt\":[2-9][0-9]*" | head -n 1 || true)"
    if [[ -n "$line" ]]; then
      retry_proof_kind="attempt_ge_2"
      retry_proof_line="$line"
      break
    fi
  done

  # B) second step_received (redelivery)
  if [[ -z "$retry_proof_kind" ]]; then
    recv_count=0
    for idx in "${!worker_files[@]}"; do
      f="${worker_files[$idx]}"
      b="${worker_bases[$idx]}"
      c="$({ tail_from "$f" "$b" | rg -F "\"msg\":\"step_received\"" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | wc -l | tr -d '[:space:]'; } || true)"
      [[ "$c" =~ ^[0-9]+$ ]] || c=0
      recv_count=$((recv_count + c))
    done
    if (( recv_count >= 2 )); then
      retry_proof_kind="redelivery_step_received"
      retry_proof_line="step_received count=${recv_count}"
    fi
  fi

  # C) worker_result_replay
  if [[ -z "$retry_proof_kind" ]]; then
    for idx in "${!worker_files[@]}"; do
      f="${worker_files[$idx]}"
      b="${worker_bases[$idx]}"
      line="$(tail_from "$f" "$b" | rg -F "\"msg\":\"worker_result_replay\"" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | head -n 1 || true)"
      if [[ -n "$line" ]]; then
        retry_proof_kind="worker_result_replay"
        retry_proof_line="$line"
        break
      fi
    done
  fi

  # D) master FAILED_TRANSIENT on >=2 distinct js_seq
  if [[ -z "$retry_proof_kind" ]]; then
    failed_transient_js_unique="$({ tail_from "$LOG_MASTER" "$base_master" | rg -F "\"msg\":\"response_step_result_received\"" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | rg -F "\"status\":\"FAILED_TRANSIENT\"" | sed -n 's/.*"js_seq":\([0-9]\+\).*/\1/p' | sort -u | wc -l | tr -d '[:space:]'; } || true)"
    [[ "$failed_transient_js_unique" =~ ^[0-9]+$ ]] || failed_transient_js_unique=0
    if (( failed_transient_js_unique >= 2 )); then
      retry_proof_kind="master_failed_transient_distinct_js_seq"
      retry_proof_line="master FAILED_TRANSIENT unique js_seq=${failed_transient_js_unique}"
    fi
  fi

  [[ -n "$retry_proof_kind" ]] && break
  sleep 1; i=$((i+1))
done
[[ -n "$retry_proof_kind" ]] || die "transient retries not proven for run_id=${RUN_ID} step_id=${STEP_ID}" "$RUN_ID"

transient_count=0
transient_max_attempt=0
while IFS= read -r f; do
  [[ -n "$f" ]] || continue
  c="$({ rg -F "\"msg\":\"step_failed_transient\"" "$f" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | wc -l | tr -d '[:space:]'; } || true)"
  [[ "$c" =~ ^[0-9]+$ ]] || c=0
  transient_count=$((transient_count + c))
  m="$({ rg -F "\"msg\":\"step_failed_transient\"" "$f" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | sed -n 's/.*"attempt":\([0-9]\+\).*/\1/p' | sort -nr | head -n 1 | tr -d '[:space:]'; } || true)"
  [[ "$m" =~ ^[0-9]+$ ]] || m=0
  (( m > transient_max_attempt )) && transient_max_attempt="$m"
done < <(worker_logs)

start_agent || die "failed to restart managed agent" "$RUN_ID"

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
  sleep 1; i=$((i+1))
done
[[ -n "$worker_success_line" ]] || die "no worker step_succeeded after agent restart run_id=${RUN_ID}" "$RUN_ID"

result_ok="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"response_step_result_received\".*\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\".*\"status\":\"SUCCEEDED\"" 120 || true)"
[[ -n "$result_ok" ]] || die "no SUCCEEDED step result after agent restart run_id=${RUN_ID}" "$RUN_ID"

exec_start="$({ tail_from "$LOG_AGENT" "$base_agent" | rg -F "\"msg\":\"agent_command_exec_start\"" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | wc -l | tr -d '[:space:]'; } || true)"
[[ "$exec_start" =~ ^[0-9]+$ ]] || exec_start=0
[[ "$exec_start" == "1" ]] || die "agent_command_exec_start count=${exec_start}, expected 1 for run_id=${RUN_ID}" "$RUN_ID"

worker_recv_total=0
while IFS= read -r f; do
  [[ -n "$f" ]] || continue
  c="$({ rg -F "\"msg\":\"step_received\"" "$f" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | wc -l | tr -d '[:space:]'; } || true)"
  [[ "$c" =~ ^[0-9]+$ ]] || c=0
  worker_recv_total=$((worker_recv_total + c))
done < <(worker_logs)
[[ "$worker_recv_total" == "1" ]] || die "worker step_received count=${worker_recv_total}, expected 1 for run_id=${RUN_ID}" "$RUN_ID"

master_success_unique="$({ tail_from "$LOG_MASTER" "$base_master" | rg -F "\"msg\":\"response_step_result_received\"" | rg -F "\"run_id\":\"${RUN_ID}\"" | rg -F "\"step_id\":\"${STEP_ID}\"" | rg -F "\"status\":\"SUCCEEDED\"" | sed -n 's/.*"js_seq":\([0-9]\+\).*/\1/p' | sort -u | wc -l | tr -d '[:space:]'; } || true)"
[[ "$master_success_unique" =~ ^[0-9]+$ ]] || master_success_unique=0
[[ "$master_success_unique" == "1" ]] || die "master success unique js_seq count=${master_success_unique}, expected 1 for run_id=${RUN_ID}" "$RUN_ID"

echo "$run_line"
echo "$waiting_line"
echo "$step_pub_line"
echo "$attempt1_line"
echo "$retry_proof_line"
echo "$worker_success_line"
echo "$result_ok"
echo "Counts: transient_failures=${transient_count} transient_max_attempt=${transient_max_attempt} retry_proof_kind=${retry_proof_kind} worker_step_received_total=${worker_recv_total} agent_exec_start=${exec_start} master_success_unique_js_seq=${master_success_unique}"
echo "PASS: M62 agent down transient retry proof run_id=${RUN_ID} step_id=${STEP_ID} lane=${TARGET_LANE}"
exit 0
