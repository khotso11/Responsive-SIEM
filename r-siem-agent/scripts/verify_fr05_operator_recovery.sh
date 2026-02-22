#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

LOG_MASTER="logs/master-roe.log"
LOG_AGENT="logs/agent.log"
EXPORT_STEPS="exports/roe_steps.jsonl"
EXPORT_RUNS="exports/roe_runs.jsonl"
PLAYBOOK_ID="PB-QUARANTINE-ROLLBACK-DEMO"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "FAIL: missing command: $1" >&2
    exit 1
  }
}

json_escape() {
  local s="${1:-}"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/}"
  printf '%s' "$s"
}

json_or_null() {
  local s="${1:-}"
  if [[ -z "$s" ]]; then
    printf 'null'
  else
    printf '"%s"' "$(json_escape "$s")"
  fi
}

fail_with_context() {
  local msg="$1"
  echo "FAIL: ${msg}" >&2
  echo "Context: master tail" >&2
  tail -n 80 "$LOG_MASTER" >&2 || true
  echo "Context: agent tail" >&2
  tail -n 80 "$LOG_AGENT" >&2 || true
  exit 1
}

require_line() {
  local file="$1"
  local pattern="$2"
  local line
  line="$(rg "$pattern" "$file" | tail -n 1 || true)"
  if [[ -z "$line" ]]; then
    fail_with_context "missing evidence pattern in ${file}: ${pattern}"
  fi
  printf '%s\n' "$line"
}

extract_json_field() {
  local line="$1"
  local field="$2"
  printf '%s\n' "$line" | sed -n "s/.*\"${field}\":\"\([^\"]*\)\".*/\1/p" | tail -n 1
}

need_cmd rg
need_cmd sed
need_cmd date
need_cmd hostname

mkdir -p logs exports demo_artifacts
[[ -f "$LOG_MASTER" ]] || fail_with_context "missing ${LOG_MASTER}"
[[ -f "$LOG_AGENT" ]] || fail_with_context "missing ${LOG_AGENT}"
[[ -f "$EXPORT_STEPS" ]] || fail_with_context "missing ${EXPORT_STEPS}"
[[ -f "$EXPORT_RUNS" ]] || fail_with_context "missing ${EXPORT_RUNS}"

run_id="${RUN_ID:-}"
if [[ -z "$run_id" ]]; then
  run_id="$(rg '"msg":"response_run_created".*"playbook_id":"'"${PLAYBOOK_ID}"'"' "$LOG_MASTER" | tail -n 1 | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"
fi
[[ -n "$run_id" ]] || fail_with_context "unable to determine run_id"

expected_status="${EXPECTED_STATUS:-}"
if [[ -z "$expected_status" ]]; then
  expected_status="$(rg '"msg":"response_run_updated".*"run_id":"'"${run_id}"'"' "$LOG_MASTER" | tail -n 1 | sed -n 's/.*"status":"\([^"]*\)".*/\1/p')"
fi
[[ -n "$expected_status" ]] || fail_with_context "unable to determine expected_status for run_id=${run_id}"

case "$expected_status" in
  SUCCEEDED|FAILED_SAFE|FAILED_TRANSIENT) ;;
  *) fail_with_context "unsupported expected_status=${expected_status}" ;;
esac

pattern_run_created='"msg":"response_run_created".*"run_id":"'"${run_id}"'".*"playbook_id":"'"${PLAYBOOK_ID}"'"'
pattern_step_published='"msg":"response_step_published".*"run_id":"'"${run_id}"'"'
pattern_step_result_any='"msg":"response_step_result_received".*"run_id":"'"${run_id}"'"'
pattern_run_updated='"msg":"response_run_updated".*"run_id":"'"${run_id}"'".*"status":"'"${expected_status}"'"'
pattern_agent_move='"msg":"agent_command_exec_start".*"run_id":"'"${run_id}"'".*"command_id":"quarantine_move"'
pattern_agent_restore='"msg":"agent_command_exec_start".*"run_id":"'"${run_id}"'".*"command_id":"quarantine_restore"'
pattern_export_steps='"run_id":"'"${run_id}"'"'
pattern_export_runs='"run_id":"'"${run_id}"'".*"status":"'"${expected_status}"'"'
pattern_step_result_succeeded='"msg":"response_step_result_received".*"run_id":"'"${run_id}"'".*"status":"SUCCEEDED"'
pattern_step_result_failed_safe='"msg":"response_step_result_received".*"run_id":"'"${run_id}"'".*"status":"FAILED_SAFE"'
pattern_partial='"msg":"response_run_partial_completion".*"run_id":"'"${run_id}"'"'

run_created_line="$(require_line "$LOG_MASTER" "$pattern_run_created")"
step_published_line="$(require_line "$LOG_MASTER" "$pattern_step_published")"
step_result_any_line="$(require_line "$LOG_MASTER" "$pattern_step_result_any")"
run_updated_line="$(require_line "$LOG_MASTER" "$pattern_run_updated")"
agent_move_line="$(require_line "$LOG_AGENT" "$pattern_agent_move")"
agent_restore_line="$(require_line "$LOG_AGENT" "$pattern_agent_restore")"
export_steps_line="$(require_line "$EXPORT_STEPS" "$pattern_export_steps")"
export_runs_line="$(require_line "$EXPORT_RUNS" "$pattern_export_runs")"

step_result_succeeded_line=""
step_result_failed_safe_line=""
operator_line=""
operator_action=""
failed_safe_reason=""

step_result_succeeded_line="$(require_line "$LOG_MASTER" "$pattern_step_result_succeeded")"

if [[ "$expected_status" == "FAILED_SAFE" ]]; then
  step_result_failed_safe_line="$(require_line "$LOG_MASTER" "$pattern_step_result_failed_safe")"
  operator_line="$(require_line "$LOG_MASTER" "$pattern_partial")"
  operator_action="$(extract_json_field "$operator_line" "operator_action")"
  if [[ "$operator_action" != "manual_restore_check_recommended" ]]; then
    fail_with_context "operator_action expected manual_restore_check_recommended but got ${operator_action:-<empty>}"
  fi
  failed_safe_reason="$(extract_json_field "$run_updated_line" "failed_safe_reason")"
  if [[ -z "$failed_safe_reason" ]]; then
    failed_safe_reason="$(extract_json_field "$operator_line" "failed_safe_reason")"
  fi
  [[ -n "$failed_safe_reason" ]] || fail_with_context "failed_safe_reason missing for FAILED_SAFE run"
fi

artifact_dir="${FR05_ARTIFACT_DIR:-demo_artifacts/$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$artifact_dir"
proof_json="${FR05_OPERATOR_PROOF_JSON_PATH:-${artifact_dir}/fr05_operator_recovery_proof.json}"
mkdir -p "$(dirname "$proof_json")"

generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
host_name="$(hostname)"

cat > "$proof_json" <<EOF_JSON
{
  "timestamp": "$(json_escape "$generated_at")",
  "hostname": "$(json_escape "$host_name")",
  "run_id": "$(json_escape "$run_id")",
  "expected_status": "$(json_escape "$expected_status")",
  "operator_action": $(json_or_null "$operator_action"),
  "failed_safe_reason": $(json_or_null "$failed_safe_reason"),
  "log_paths": {
    "master": "$(json_escape "$LOG_MASTER")",
    "agent": "$(json_escape "$LOG_AGENT")",
    "steps_export": "$(json_escape "$EXPORT_STEPS")",
    "runs_export": "$(json_escape "$EXPORT_RUNS")"
  },
  "patterns": {
    "run_created": "$(json_escape "$pattern_run_created")",
    "step_published": "$(json_escape "$pattern_step_published")",
    "step_result_any": "$(json_escape "$pattern_step_result_any")",
    "run_updated": "$(json_escape "$pattern_run_updated")",
    "agent_move": "$(json_escape "$pattern_agent_move")",
    "agent_restore": "$(json_escape "$pattern_agent_restore")",
    "export_steps": "$(json_escape "$pattern_export_steps")",
    "export_runs": "$(json_escape "$pattern_export_runs")"
  },
  "evidence": {
    "run_created_line": "$(json_escape "$run_created_line")",
    "step_published_line": "$(json_escape "$step_published_line")",
    "step_result_any_line": "$(json_escape "$step_result_any_line")",
    "step_result_succeeded_line": "$(json_escape "$step_result_succeeded_line")",
    "step_result_failed_safe_line": $(json_or_null "$step_result_failed_safe_line"),
    "run_updated_line": "$(json_escape "$run_updated_line")",
    "operator_line": $(json_or_null "$operator_line"),
    "agent_move_line": "$(json_escape "$agent_move_line")",
    "agent_restore_line": "$(json_escape "$agent_restore_line")",
    "export_steps_line": "$(json_escape "$export_steps_line")",
    "export_runs_line": "$(json_escape "$export_runs_line")"
  }
}
EOF_JSON

echo "PASS: FR-05 operator recovery workflow proof completed"
echo "FR05_OPERATOR_PROOF_JSON=${proof_json}"
