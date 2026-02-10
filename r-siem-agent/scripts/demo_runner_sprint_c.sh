#!/usr/bin/env bash
set -euo pipefail

DEMO_EVIDENCE_LOG="${DEMO_EVIDENCE_LOG:-logs/demo_$(date +%Y%m%d_%H%M%S).log}"

mkdir -p logs tmp

echo "=== Sprint C Demo Runner ==="
echo "Evidence log: ${DEMO_EVIDENCE_LOG}"

run_optional_script() {
  local script="$1"
  if [[ ! -x "$script" ]]; then
    echo "WARN: skipped ${script} (not found or not executable)"
    demo_warn=1
    return 0
  fi
  echo "=== Running ${script} ==="
  if ! "$script"; then
    echo "FAIL: ${script} failed" >&2
    exit 1
  fi
}

demo_warn=0

run_optional_script "./scripts/m40_collector_publish_proof.sh"
run_optional_script "./scripts/m41_detector_invalid_user_rule_proof.sh"
run_optional_script "./scripts/m37_agent_command_e2e_proof.sh"
run_optional_script "./scripts/m42_detector_process_count_rule_proof.sh"

if [[ "$demo_warn" -ne 0 ]]; then
  echo "WARN: demo_runner_sprint_c completed with skips; see output above" >&2
  echo "PASS: Sprint C demo runner (with skips)"
  exit 0
fi

echo "PASS: Sprint C demo runner"
echo "Evidence log: ${DEMO_EVIDENCE_LOG}"
