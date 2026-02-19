#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p logs

echo "=== FR05 demo (safety + rollback + audit) ==="

./scripts/demo_up.sh

success_out="$(./scripts/demo_fr05_rollback.sh)"
printf '%s\n' "$success_out"
run_id_success="$(printf '%s\n' "$success_out" | sed -n 's/^RUN_ID="\([^"]*\)"/\1/p' | head -n 1)"
if [[ -z "$run_id_success" ]]; then
  echo "FAIL: unable to parse success RUN_ID from demo_fr05_rollback output" >&2
  exit 1
fi

# Re-ensure stack liveness before partial-failure proof to avoid false negatives
# from transiently stopped agent/worker after the success proof completes.
./scripts/demo_up.sh

fail_out="$(./scripts/mf05_quarantine_partial_failure_proof.sh)"
printf '%s\n' "$fail_out"
run_id_fail="$(printf '%s\n' "$fail_out" | sed -n 's/^PASS: FR05 quarantine partial failure proof run_id=\([^ ]*\).*/\1/p' | head -n 1)"
if [[ -z "$run_id_fail" ]]; then
  echo "FAIL: unable to parse failure RUN_ID from mf05_quarantine_partial_failure_proof output" >&2
  exit 1
fi

cat <<EOF2
=== SUPERVISOR PROOF COMMANDS ===
RUN_ID_OK="$run_id_success"
RUN_ID_FAIL="$run_id_fail"

rg '"msg":"response_run_created".*"run_id":"'"\$RUN_ID_OK"'".*"playbook_id":"PB-QUARANTINE-ROLLBACK-DEMO"' logs/master-roe.log
rg '"msg":"response_run_created".*"run_id":"'"\$RUN_ID_FAIL"'".*"playbook_id":"PB-QUARANTINE-ROLLBACK-DEMO"' logs/master-roe.log
rg '"msg":"agent_command_exec_start".*"run_id":"'"\$RUN_ID_OK"'".*"command_id":"quarantine_move"' logs/agent.log
rg '"msg":"agent_command_exec_start".*"run_id":"'"\$RUN_ID_OK"'".*"command_id":"quarantine_restore"' logs/agent.log
rg '"msg":"agent_command_exec_start".*"run_id":"'"\$RUN_ID_FAIL"'".*"command_id":"quarantine_move"' logs/agent.log
rg '"msg":"agent_command_exec_start".*"run_id":"'"\$RUN_ID_FAIL"'".*"command_id":"quarantine_restore"' logs/agent.log
rg '"msg":"response_run_updated".*"run_id":"'"\$RUN_ID_OK"'".*"status":"SUCCEEDED"' logs/master-roe.log
rg '"msg":"response_run_updated".*"run_id":"'"\$RUN_ID_FAIL"'".*"status":"FAILED_SAFE"' logs/master-roe.log
rg '"run_id":"'"\$RUN_ID_OK"'".*"status":"SUCCEEDED"' exports/roe_runs.jsonl
rg '"run_id":"'"\$RUN_ID_FAIL"'".*"status":"FAILED_SAFE"' exports/roe_runs.jsonl
EOF2

if [[ -x ./scripts/demo_capture.sh ]]; then
  artifact_out="$(RUN_ID="$run_id_fail" ./scripts/demo_capture.sh || true)"
  artifact_dir="$(printf '%s\n' "$artifact_out" | sed -n 's/^ARTIFACT_DIR=//p' | tail -n 1)"
  if [[ -n "$artifact_dir" ]]; then
    echo "ARTIFACT_DIR=${artifact_dir}"
  fi
fi

echo "PASS: FR05 completed (safety + rollback + audit) run_id_ok=${run_id_success} run_id_fail=${run_id_fail}"
