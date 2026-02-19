#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

./scripts/mf05_quarantine_rollback_proof.sh

RUN_ID="$(rg '"msg":"response_run_created".*"playbook_id":"PB-QUARANTINE-ROLLBACK-DEMO"' logs/master-roe.log | tail -n 1 | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"
if [[ -z "${RUN_ID}" ]]; then
  echo "FAIL: unable to resolve RUN_ID for PB-QUARANTINE-ROLLBACK-DEMO" >&2
  exit 1
fi

cat <<EOF
=== SUPERVISOR PROOF COMMANDS ===
RUN_ID="$RUN_ID"

rg '"msg":"response_run_created".*"run_id":"'"\$RUN_ID"'".*"playbook_id":"PB-QUARANTINE-ROLLBACK-DEMO"' logs/master-roe.log
rg '"msg":"response_step_published".*"run_id":"'"\$RUN_ID"'"' logs/master-roe.log
rg '"msg":"response_step_result_received".*"run_id":"'"\$RUN_ID"'".*"status":"SUCCEEDED"' logs/master-roe.log
rg '"msg":"response_run_updated".*"run_id":"'"\$RUN_ID"'".*"status":"SUCCEEDED"' logs/master-roe.log
rg '"msg":"agent_command_exec_start".*"run_id":"'"\$RUN_ID"'".*"command_id":"quarantine_move"' logs/agent.log
rg '"msg":"agent_command_exec_start".*"run_id":"'"\$RUN_ID"'".*"command_id":"quarantine_restore"' logs/agent.log
rg '"run_id":"'"\$RUN_ID"'".*"status":"SUCCEEDED"' exports/roe_steps.jsonl
rg '"run_id":"'"\$RUN_ID"'".*"status":"SUCCEEDED"' exports/roe_runs.jsonl
EOF
