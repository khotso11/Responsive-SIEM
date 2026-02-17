#!/usr/bin/env bash
set -euo pipefail

DEMO_EVIDENCE_LOG="${DEMO_EVIDENCE_LOG:-logs/demo_$(date +%Y%m%d_%H%M%S).log}"

mkdir -p logs tmp

echo "=== Sprint C Demo Runner ==="
echo "Evidence log: ${DEMO_EVIDENCE_LOG}"

preflight_failed=0
missing_logs=()

check_log() {
  local file="$1"
  if [[ ! -s "$file" ]]; then
    missing_logs+=("$file")
    preflight_failed=1
  fi
}

check_log "logs/collector-tail.log"
check_log "logs/detector-v0.log"
check_log "logs/master-roe.log"
check_log "logs/roe-worker.log"
check_log "logs/agent.log"

if [[ "$preflight_failed" -ne 0 ]]; then
  echo "FAIL: preflight check failed; required logs are missing or empty:"
  for file in "${missing_logs[@]}"; do
    echo "  - ${file}"
  done
  echo "Start these terminals/services, then rerun:"
  echo "  - Terminal H (collector-tail): go run -mod=vendor ./cmd/collector-tail -config configs/collector.yaml | tee logs/collector-tail.log"
  echo "  - Terminal I (detector-v0): go run -mod=vendor ./cmd/detector-v0 -config configs/detector.yaml | tee logs/detector-v0.log"
  echo "  - Terminal E (master-roe): go run -mod=vendor ./cmd/master-roe --config configs/master.yaml | tee logs/master-roe.log"
  echo "  - Terminal F (roe-worker): go run -mod=vendor ./cmd/master-roe-worker --config configs/master.yaml | tee logs/roe-worker.log"
  echo "  - Terminal G (agent): go run -mod=vendor ./cmd/agent --config configs/agent.yaml | tee logs/agent.log"
  exit 2
fi

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
