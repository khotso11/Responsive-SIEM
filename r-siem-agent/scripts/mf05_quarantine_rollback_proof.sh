#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

LOG_MASTER="logs/master-roe.log"
LOG_WORKER="logs/worker.log"
LOG_AGENT="logs/agent.log"
LOG_DETECTOR="logs/detector.log"
LOG_COLLECTOR="logs/collector.log"
EXPORT_STEPS="exports/roe_steps.jsonl"
EXPORT_RUNS="exports/roe_runs.jsonl"
DEMO_LOG="tmp/demo.log"

PLAYBOOK_ID="PB-QUARANTINE-ROLLBACK-DEMO"
RULE_ID="R-COLLECT-INVALID-USER"

STARTED_WORKER=0
STARTED_AGENT=0
RUN_ID_CTX=""
STEP1_ID_CTX=""
STEP2_ID_CTX=""
MASTER_PROC_RE='(cmd/master-roe([[:space:]]|$)|/master-roe([[:space:]]|$)).*(-{1,2}config([=[:space:]])?configs/master\.yaml)'
WORKER_PROC_RE='(cmd/master-roe-worker([[:space:]]|$)|/master-roe-worker([[:space:]]|$)).*(-{1,2}config([=[:space:]])?configs/master\.yaml)'
AGENT_PROC_RE='(cmd/agent([[:space:]]|$)|/agent([[:space:]]|$)).*(-{1,2}config([=[:space:]])?configs/agent\.yaml)'

line_count() { [[ -f "$1" ]] && wc -l < "$1" | tr -d '[:space:]' || echo 0; }

tail_from() {
  local file="$1" base="$2"
  tail -n "+$((base + 1))" "$file" 2>/dev/null || true
}

wait_match_rg() {
  local file="$1" base="$2" pattern="$3" timeout="${4:-60}"
  local i=0
  while (( i < timeout )); do
    local line
    line="$(tail_from "$file" "$base" | rg "$pattern" | head -n 1 || true)"
    if [[ -n "$line" ]]; then
      printf '%s\n' "$line"
      return 0
    fi
    sleep 1
    i=$((i + 1))
  done
  return 1
}

die() {
  local msg="$1"
  echo "FAIL: $msg" >&2
  debug_context >&2 || true
  exit 1
}

need_cmd() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1 || die "missing command: $cmd"
}

service_lines() {
  local pattern="$1"
  ps -eo pid=,args= | rg "$pattern" | rg -v 'rg |mf05_quarantine_rollback_proof' || true
}

service_count() {
  local pattern="$1"
  local c
  c="$(service_lines "$pattern" | wc -l | tr -d '[:space:]')"
  [[ "$c" =~ ^[0-9]+$ ]] || c=0
  echo "$c"
}

normalize_worker_single() {
  local c
  c="$(service_count "$WORKER_PROC_RE")"
  if (( c > 1 )); then
    pkill -f 'cmd/master-roe-worker|/master-roe-worker --config|/master-roe-worker -config' >/dev/null 2>&1 || true
    sleep 1.5
    c=0
  fi
  if (( c == 0 )); then
    nohup go run -mod=vendor ./cmd/master-roe-worker --config configs/master.yaml --lane BOTH >> "$LOG_WORKER" 2>&1 &
    STARTED_WORKER=1
    sleep 1
  fi
  local i=0
  while (( i < 180 )); do
    (( "$(service_count "$WORKER_PROC_RE")" >= 1 )) && return 0
    sleep 0.5
    i=$((i + 1))
  done
  die "unable to ensure worker process is running"
}

normalize_agent_single() {
  local c
  c="$(service_count "$AGENT_PROC_RE")"
  if (( c > 1 )); then
    pkill -f 'cmd/agent|/agent --config|/agent -config' >/dev/null 2>&1 || true
    sleep 1.5
    c=0
  fi
  if (( c == 0 )); then
    nohup go run -mod=vendor ./cmd/agent --config configs/agent.yaml >> "$LOG_AGENT" 2>&1 &
    STARTED_AGENT=1
    sleep 1
  fi
  local i=0
  while (( i < 180 )); do
    (( "$(service_count "$AGENT_PROC_RE")" >= 1 )) && return 0
    sleep 0.5
    i=$((i + 1))
  done
  die "unable to ensure agent process is running"
}

debug_context() {
  local run_filter='.'
  if [[ -n "$RUN_ID_CTX" ]]; then
    run_filter="\"run_id\":\"${RUN_ID_CTX}\""
  fi
  echo "Context: master (last 80 relevant):"
  rg "$run_filter" "$LOG_MASTER" | tail -n 80 || true
  echo "Context: worker (last 60 relevant):"
  rg "$run_filter" "$LOG_WORKER" | tail -n 60 || true
  echo "Context: agent (last 60 relevant):"
  rg "$run_filter" "$LOG_AGENT" | tail -n 60 || true
  echo "Context: exports steps (last 30 relevant):"
  rg "$run_filter" "$EXPORT_STEPS" | tail -n 30 || true
  echo "Context: exports runs (last 30 relevant):"
  rg "$run_filter" "$EXPORT_RUNS" | tail -n 30 || true
}

cleanup() {
  if (( STARTED_WORKER == 1 )); then
    pkill -f 'cmd/master-roe-worker|/master-roe-worker --config|/master-roe-worker -config' >/dev/null 2>&1 || true
  fi
  if (( STARTED_AGENT == 1 )); then
    pkill -f 'cmd/agent|/agent --config|/agent -config' >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "=== FR05 quarantine rollback proof ==="

need_cmd rg
need_cmd nats
need_cmd go
need_cmd pgrep
need_cmd pkill

mkdir -p logs tmp exports tmp/demo_quarantine tmp/quarantine
[[ -f "$DEMO_LOG" ]] || touch "$DEMO_LOG"

for f in "$LOG_MASTER" "$LOG_DETECTOR" "$LOG_COLLECTOR"; do
  [[ -s "$f" ]] || die "missing or empty $f. Run ./scripts/demo_up.sh first."
done

if ! pgrep -f 'cmd/master-roe|/master-roe --config|/master-roe -config' >/dev/null 2>&1; then
  die "master-roe is not running"
fi
if ! pgrep -f 'cmd/detector-v0|/detector-v0 --config|/detector-v0 -config' >/dev/null 2>&1; then
  die "detector-v0 is not running"
fi
if ! pgrep -f 'cmd/collector-tail|/collector-tail --config|/collector-tail -config' >/dev/null 2>&1; then
  die "collector-tail is not running"
fi

if (( "$(service_count "$MASTER_PROC_RE")" < 1 )); then
  die "master-roe process missing after precheck"
fi

normalize_agent_single
[[ -s "$LOG_AGENT" ]] || die "missing or empty $LOG_AGENT"
normalize_worker_single
[[ -s "$LOG_WORKER" ]] || die "missing or empty $LOG_WORKER"

base_master="$(line_count "$LOG_MASTER")"
base_worker="$(line_count "$LOG_WORKER")"
base_agent="$(line_count "$LOG_AGENT")"
base_steps="$(line_count "$EXPORT_STEPS")"
base_runs="$(line_count "$EXPORT_RUNS")"

nonce="$(date +%s)"
oct="$(( (nonce % 180) + 20 ))"
src_ip="10.0.0.${oct}"
file_name="file_${oct}.txt"
orig_path="tmp/demo_quarantine/${file_name}"
echo "fr05 quarantine rollback ${nonce}" > "$orig_path"
[[ -f "$orig_path" ]] || die "failed to create demo file: $orig_path"

now="$(date +%s)"
echo "FAILED login user=khotso src=${src_ip} ts=${now}" >> "$DEMO_LOG"

run_line="$(wait_match_rg "$LOG_MASTER" "$base_master" "\"msg\":\"response_run_created\".*\"rule_id\":\"${RULE_ID}\".*\"playbook_id\":\"${PLAYBOOK_ID}\"" 90 || true)"
[[ -n "$run_line" ]] || die "timeout waiting for run_created playbook_id=${PLAYBOOK_ID}"
run_id="$(printf '%s\n' "$run_line" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"
[[ -n "$run_id" ]] || die "failed to parse run_id"
RUN_ID_CTX="$run_id"

waiting_line="$(wait_match_rg "$LOG_MASTER" "$base_master" "\"msg\":\"response_run_waiting_approval\".*\"run_id\":\"${run_id}\"" 45 || true)"
[[ -n "$waiting_line" ]] || die "run not waiting approval run_id=${run_id}"

nats pub rsiem.response.approvals "{\"run_id\":\"${run_id}\",\"decision\":\"approve\",\"actor\":\"khotso\"}" >/dev/null || die "failed to publish approval"

step1_pub="$(wait_match_rg "$LOG_MASTER" "$base_master" "\"msg\":\"response_step_published\".*\"run_id\":\"${run_id}\".*\"step_index\":0.*\"action_type\":\"agent_command\"" 60 || true)"
[[ -n "$step1_pub" ]] || die "missing step1 published"
step1_id="$(printf '%s\n' "$step1_pub" | sed -n 's/.*"step_id":"\([^"]*\)".*/\1/p')"
[[ -n "$step1_id" ]] || die "failed to parse step1_id"
STEP1_ID_CTX="$step1_id"

step1_result="$(wait_match_rg "$LOG_MASTER" "$base_master" "\"msg\":\"response_step_result_received\".*\"run_id\":\"${run_id}\".*\"step_id\":\"${step1_id}\".*\"status\":\"SUCCEEDED\"" 90 || true)"
[[ -n "$step1_result" ]] || die "step1 did not succeed"

q_file="tmp/quarantine/${run_id}/${file_name}"

step2_pub="$(wait_match_rg "$LOG_MASTER" "$base_master" "\"msg\":\"response_step_published\".*\"run_id\":\"${run_id}\".*\"step_index\":1.*\"action_type\":\"agent_command\"" 60 || true)"
[[ -n "$step2_pub" ]] || die "missing step2 published"
step2_id="$(printf '%s\n' "$step2_pub" | sed -n 's/.*"step_id":"\([^"]*\)".*/\1/p')"
[[ -n "$step2_id" ]] || die "failed to parse step2_id"
STEP2_ID_CTX="$step2_id"

step2_result="$(wait_match_rg "$LOG_MASTER" "$base_master" "\"msg\":\"response_step_result_received\".*\"run_id\":\"${run_id}\".*\"step_id\":\"${step2_id}\".*\"status\":\"SUCCEEDED\"" 90 || true)"
[[ -n "$step2_result" ]] || die "step2 did not succeed"

run_succeeded="$(wait_match_rg "$LOG_MASTER" "$base_master" "\"msg\":\"response_run_updated\".*\"run_id\":\"${run_id}\".*\"status\":\"SUCCEEDED\"" 10 || true)"

[[ -f "$orig_path" ]] || die "restore proof failed: original path missing ${orig_path}"
[[ ! -f "$q_file" ]] || die "restore proof failed: quarantine file still present ${q_file}"

agent_move_count="$({ tail_from "$LOG_AGENT" "$base_agent" | rg '"msg":"agent_command_exec_start"' | rg -F '"run_id":"'"${run_id}"'"' | rg -F '"command_id":"quarantine_move"' | wc -l | tr -d '[:space:]'; } || true)"
agent_restore_count="$({ tail_from "$LOG_AGENT" "$base_agent" | rg '"msg":"agent_command_exec_start"' | rg -F '"run_id":"'"${run_id}"'"' | rg -F '"command_id":"quarantine_restore"' | wc -l | tr -d '[:space:]'; } || true)"
master_success_count="$({ tail_from "$LOG_MASTER" "$base_master" | rg '"msg":"response_step_result_received"' | rg -F '"run_id":"'"${run_id}"'"' | rg -F '"status":"SUCCEEDED"' | wc -l | tr -d '[:space:]'; } || true)"
master_success_unique_steps="$({ tail_from "$LOG_MASTER" "$base_master" | rg '"msg":"response_step_result_received"' | rg -F '"run_id":"'"${run_id}"'"' | rg -F '"status":"SUCCEEDED"' | sed -n 's/.*"step_id":"\([^"]*\)".*/\1/p' | sort -u | wc -l | tr -d '[:space:]'; } || true)"
master_failed_safe_count="$({ tail_from "$LOG_MASTER" "$base_master" | rg '"msg":"response_step_result_received"' | rg -F '"run_id":"'"${run_id}"'"' | rg -F '"status":"FAILED_SAFE"' | wc -l | tr -d '[:space:]'; } || true)"
master_failed_transient_count="$({ tail_from "$LOG_MASTER" "$base_master" | rg '"msg":"response_step_result_received"' | rg -F '"run_id":"'"${run_id}"'"' | rg -F '"status":"FAILED_TRANSIENT"' | wc -l | tr -d '[:space:]'; } || true)"
step_export_success_count="$({ tail_from "$EXPORT_STEPS" "$base_steps" | rg -F '"run_id":"'"${run_id}"'"' | rg -F '"status":"SUCCEEDED"' | wc -l | tr -d '[:space:]'; } || true)"
run_export_succeeded_count="$({ tail_from "$EXPORT_RUNS" "$base_runs" | rg -F '"msg":"response_run_updated"' | rg -F '"run_id":"'"${run_id}"'"' | rg -F '"status":"SUCCEEDED"' | wc -l | tr -d '[:space:]'; } || true)"
run_export_failed_count="$({ tail_from "$EXPORT_RUNS" "$base_runs" | rg -F '"msg":"response_run_updated"' | rg -F '"run_id":"'"${run_id}"'"' | rg '"status":"FAILED_(SAFE|TRANSIENT)"' | wc -l | tr -d '[:space:]'; } || true)"

run_kv_raw="$(nats kv get --raw RSIEM_RSP_RUNS "run.${run_id}" 2>/dev/null || true)"
run_kv_status="$(printf '%s\n' "$run_kv_raw" | sed -n 's/.*"status":"\([^"]*\)".*/\1/p' | tail -n 1)"

[[ "$agent_move_count" =~ ^[1-9][0-9]*$ ]] || die "agent quarantine_move exec_start count=${agent_move_count}, expected >=1"
[[ "$agent_restore_count" =~ ^[1-9][0-9]*$ ]] || die "agent quarantine_restore exec_start count=${agent_restore_count}, expected >=1"
[[ "$master_success_unique_steps" == "2" ]] || die "master SUCCEEDED unique step_id count=${master_success_unique_steps}, expected 2"
[[ "$master_failed_safe_count" == "0" ]] || die "master FAILED_SAFE result count=${master_failed_safe_count}, expected 0"
[[ "$master_failed_transient_count" == "0" ]] || die "master FAILED_TRANSIENT result count=${master_failed_transient_count}, expected 0"
[[ "$step_export_success_count" == "2" ]] || die "exported SUCCEEDED step count=${step_export_success_count}, expected 2"
[[ "$run_export_failed_count" == "0" ]] || die "run export shows FAILED status count=${run_export_failed_count}"
if [[ "$run_kv_status" == "FAILED_SAFE" || "$run_kv_status" == "FAILED_TRANSIENT" ]]; then
  die "run kv status is failed: ${run_kv_status}"
fi

run_succeeded_observed=0
if [[ -n "$run_succeeded" ]]; then
  run_succeeded_observed=1
elif [[ "$run_export_succeeded_count" =~ ^[1-9][0-9]*$ ]]; then
  run_succeeded_observed=1
elif [[ "$run_kv_status" == "SUCCEEDED" ]]; then
  run_succeeded_observed=1
fi
if [[ "$run_succeeded_observed" == "0" ]]; then
  echo "WARN: run-level SUCCEEDED not observed within timeout; step-level evidence succeeded (run_kv_status=${run_kv_status:-unknown})"
else
  echo "run_level_status=SUCCEEDED"
fi

echo "$run_line"
echo "$waiting_line"
echo "$step1_pub"
echo "$step1_result"
echo "$step2_pub"
echo "$step2_result"
[[ -n "$run_succeeded" ]] && echo "$run_succeeded"
echo "Counts: worker_lines_since_base=$(tail_from "$LOG_WORKER" "$base_worker" | wc -l | tr -d '[:space:]') agent_move_exec_start=${agent_move_count} agent_restore_exec_start=${agent_restore_count} master_success_results=${master_success_count} master_success_unique_steps=${master_success_unique_steps} master_failed_safe=${master_failed_safe_count} master_failed_transient=${master_failed_transient_count} export_steps_succeeded=${step_export_success_count} export_runs_succeeded=${run_export_succeeded_count} run_kv_status=${run_kv_status:-unknown}"
echo "PASS: FR05 quarantine rollback proof run_id=${run_id} step1_id=${step1_id} step2_id=${step2_id} lane=FAST"
