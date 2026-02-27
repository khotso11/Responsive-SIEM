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

RUN_ID_CTX=""

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

debug_context() {
  local run_filter='.'
  if [[ -n "$RUN_ID_CTX" ]]; then
    run_filter="\"run_id\":\"${RUN_ID_CTX}\""
  fi
  echo "Context: master (last 120 relevant):"
  rg "$run_filter" "$LOG_MASTER" | tail -n 120 || true
  echo "Context: worker (last 80 relevant):"
  rg "$run_filter" "$LOG_WORKER" | tail -n 80 || true
  echo "Context: agent (last 80 relevant):"
  rg "$run_filter" "$LOG_AGENT" | tail -n 80 || true
  echo "Context: exports steps (last 60 relevant):"
  rg "$run_filter" "$EXPORT_STEPS" | tail -n 60 || true
  echo "Context: exports runs (last 60 relevant):"
  rg "$run_filter" "$EXPORT_RUNS" | tail -n 60 || true
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

echo "=== FR05 quarantine partial failure proof ==="

need_cmd rg
need_cmd nats
need_cmd pgrep

mkdir -p logs tmp exports tmp/demo_quarantine tmp/quarantine
[[ -f "$DEMO_LOG" ]] || touch "$DEMO_LOG"

for f in "$LOG_MASTER" "$LOG_WORKER" "$LOG_AGENT" "$LOG_DETECTOR" "$LOG_COLLECTOR"; do
  [[ -s "$f" ]] || die "missing or empty $f. Run ./scripts/demo_up.sh first."
done

pgrep -f 'cmd/master-roe|/master-roe --config|/master-roe -config' >/dev/null 2>&1 || die "master-roe is not running"
pgrep -f 'cmd/master-roe-worker|/master-roe-worker --config|/master-roe-worker -config' >/dev/null 2>&1 || die "worker is not running"
pgrep -f 'cmd/agent|/agent --config|/agent -config' >/dev/null 2>&1 || die "agent is not running"
pgrep -f 'cmd/detector-v0|/detector-v0 --config|/detector-v0 -config' >/dev/null 2>&1 || die "detector-v0 is not running"
pgrep -f 'cmd/collector-tail|/collector-tail --config|/collector-tail -config' >/dev/null 2>&1 || die "collector-tail is not running"

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
echo "fr05 partial failure ${nonce}" > "$orig_path"
[[ -f "$orig_path" ]] || die "failed to create demo file: $orig_path"

now="$(date +%s)"
echo "FAILED login user=khotso src=${src_ip} ts=${now}" >> "$DEMO_LOG"

run_line="$(wait_match_rg "$LOG_MASTER" "$base_master" "\\\"msg\\\":\\\"response_run_created\\\".*\\\"rule_id\\\":\\\"${RULE_ID}\\\".*\\\"playbook_id\\\":\\\"${PLAYBOOK_ID}\\\"" 90 || true)"
[[ -n "$run_line" ]] || die "timeout waiting for run_created playbook_id=${PLAYBOOK_ID}"
run_id="$(printf '%s\n' "$run_line" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"
[[ -n "$run_id" ]] || die "failed to parse run_id"
RUN_ID_CTX="$run_id"

wait_line="$(wait_match_rg "$LOG_MASTER" "$base_master" "\\\"msg\\\":\\\"response_run_waiting_approval\\\".*\\\"run_id\\\":\\\"${run_id}\\\"" 45 || true)"
[[ -n "$wait_line" ]] || die "run not waiting approval run_id=${run_id}"

nats pub rsiem.response.approvals "{\"run_id\":\"${run_id}\",\"decision\":\"approve\",\"actor\":\"khotso\"}" >/dev/null || die "failed to publish approval"

step1_pub="$(wait_match_rg "$LOG_MASTER" "$base_master" "\\\"msg\\\":\\\"response_step_published\\\".*\\\"run_id\\\":\\\"${run_id}\\\".*\\\"step_index\\\":0" 60 || true)"
[[ -n "$step1_pub" ]] || die "missing step1 published"
step1_id="$(printf '%s\n' "$step1_pub" | sed -n 's/.*"step_id":"\([^"]*\)".*/\1/p')"
[[ -n "$step1_id" ]] || die "failed to parse step1_id"

step2_pub="$(wait_match_rg "$LOG_MASTER" "$base_master" "\\\"msg\\\":\\\"response_step_published\\\".*\\\"run_id\\\":\\\"${run_id}\\\".*\\\"step_index\\\":1" 60 || true)"
[[ -n "$step2_pub" ]] || die "missing step2 published"
step2_id="$(printf '%s\n' "$step2_pub" | sed -n 's/.*"step_id":"\([^"]*\)".*/\1/p')"
[[ -n "$step2_id" ]] || die "failed to parse step2_id"

step1_result="$(wait_match_rg "$LOG_MASTER" "$base_master" "\\\"msg\\\":\\\"response_step_result_received\\\".*\\\"run_id\\\":\\\"${run_id}\\\".*\\\"step_id\\\":\\\"${step1_id}\\\".*\\\"status\\\":\\\"SUCCEEDED\\\"" 90 || true)"
[[ -n "$step1_result" ]] || die "step1 did not succeed"

q_file="tmp/quarantine/${run_id}/${file_name}"
record_file="tmp/quarantine/${run_id}/.quarantine_record_${file_name}.json"
[[ -f "$q_file" ]] || die "quarantine file missing after step1: ${q_file}"
[[ -f "$record_file" ]] || die "quarantine record missing after step1: ${record_file}"

rm -f "$record_file"
[[ ! -f "$record_file" ]] || die "failed to remove quarantine record for deterministic failure"

step2_failed="$(wait_match_rg "$LOG_MASTER" "$base_master" "\\\"msg\\\":\\\"response_step_result_received\\\".*\\\"run_id\\\":\\\"${run_id}\\\".*\\\"step_id\\\":\\\"${step2_id}\\\".*\\\"status\\\":\\\"FAILED_SAFE\\\"" 90 || true)"
[[ -n "$step2_failed" ]] || die "step2 FAILED_SAFE not observed"

run_failed_line="$(wait_match_rg "$LOG_MASTER" "$base_master" "\\\"msg\\\":\\\"response_run_updated\\\".*\\\"run_id\\\":\\\"${run_id}\\\".*\\\"status\\\":\\\"FAILED_SAFE\\\"" 30 || true)"
[[ -n "$run_failed_line" ]] || die "run-level FAILED_SAFE not observed"

partial_log="$(wait_match_rg "$LOG_MASTER" "$base_master" "\\\"msg\\\":\\\"response_run_partial_completion\\\".*\\\"run_id\\\":\\\"${run_id}\\\"" 30 || true)"
[[ -n "$partial_log" ]] || die "partial completion operator log not observed"

agent_move_count="$({ tail_from "$LOG_AGENT" "$base_agent" | rg '"msg":"agent_command_exec_start"' | rg -F '"run_id":"'"${run_id}"'"' | rg -F '"command_id":"quarantine_move"' | wc -l | tr -d '[:space:]'; } || true)"
agent_restore_count="$({ tail_from "$LOG_AGENT" "$base_agent" | rg '"msg":"agent_command_exec_start"' | rg -F '"run_id":"'"${run_id}"'"' | rg -F '"command_id":"quarantine_restore"' | wc -l | tr -d '[:space:]'; } || true)"
step_export_succeeded="$({ tail_from "$EXPORT_STEPS" "$base_steps" | rg -F '"run_id":"'"${run_id}"'"' | rg -F '"status":"SUCCEEDED"' | wc -l | tr -d '[:space:]'; } || true)"
step_export_failed_safe="$({ tail_from "$EXPORT_STEPS" "$base_steps" | rg -F '"run_id":"'"${run_id}"'"' | rg -F '"status":"FAILED_SAFE"' | wc -l | tr -d '[:space:]'; } || true)"
run_export_failed_safe="$({ tail_from "$EXPORT_RUNS" "$base_runs" | rg -F '"msg":"response_run_updated"' | rg -F '"run_id":"'"${run_id}"'"' | rg -F '"status":"FAILED_SAFE"' | wc -l | tr -d '[:space:]'; } || true)"
run_kv_raw="$(nats kv get --raw RSIEM_RSP_RUNS "run.${run_id}" 2>/dev/null || true)"
run_kv_status="$(printf '%s\n' "$run_kv_raw" | sed -n 's/.*"status":"\([^"]*\)".*/\1/p' | tail -n 1)"

[[ "$agent_move_count" =~ ^[1-9][0-9]*$ ]] || die "agent quarantine_move exec_start count=${agent_move_count}, expected >=1"
[[ "$agent_restore_count" =~ ^[1-9][0-9]*$ ]] || die "agent quarantine_restore exec_start count=${agent_restore_count}, expected >=1"
[[ "$step_export_succeeded" =~ ^[1-9][0-9]*$ ]] || die "export SUCCEEDED step count=${step_export_succeeded}, expected >=1"
[[ "$step_export_failed_safe" =~ ^[1-9][0-9]*$ ]] || die "export FAILED_SAFE step count=${step_export_failed_safe}, expected >=1"
run_failed_safe_observed=0
if [[ -n "$run_failed_line" ]]; then
  run_failed_safe_observed=1
fi
if [[ "$run_export_failed_safe" =~ ^[1-9][0-9]*$ ]]; then
  run_failed_safe_observed=1
fi
[[ "$run_failed_safe_observed" == "1" ]] || die "FAILED_SAFE run-level evidence missing in both master log and exports"

[[ -f "$q_file" ]] || die "expected quarantine file to remain after restore failure"
[[ ! -f "$orig_path" ]] || die "expected original file to remain missing after restore failure"

echo "$run_line"
echo "$wait_line"
echo "$step1_pub"
echo "$step1_result"
echo "$step2_pub"
echo "$step2_failed"
echo "$run_failed_line"
echo "$partial_log"
echo "Counts: agent_move_exec_start=${agent_move_count} agent_restore_exec_start=${agent_restore_count} export_steps_succeeded=${step_export_succeeded} export_steps_failed_safe=${step_export_failed_safe} export_runs_failed_safe=${run_export_failed_safe} run_kv_status=${run_kv_status:-unknown}"
echo "PASS: FR05 quarantine partial failure proof run_id=${run_id} step1_id=${step1_id} step2_id=${step2_id} lane=FAST"
