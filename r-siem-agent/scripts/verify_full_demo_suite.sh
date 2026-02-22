#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v rg >/dev/null 2>&1; then
  echo "FAIL: missing required command: rg" >&2
  exit 1
fi

timestamp="$(date +%Y%m%d_%H%M%S)"
LOG_PATH="/tmp/verify_full_demo_suite_${timestamp}.out"
touch "$LOG_PATH"

run_script() {
  local script_path="$1"
  local step_log
  step_log="$(mktemp /tmp/verify_full_demo_suite_step.XXXXXX)"
  echo "=== RUN: ${script_path} ===" | tee -a "$LOG_PATH"
  if ! "${script_path}" >"$step_log" 2>&1; then
    cat "$step_log" | tee -a "$LOG_PATH"
    rm -f "$step_log"
    return 1
  fi
  cat "$step_log" | tee -a "$LOG_PATH"
  rm -f "$step_log"
}

extract_artifact() {
  local key="$1"
  rg "^${key}=" "$LOG_PATH" | tail -n 1 | sed -n "s/^${key}=//p" || true
}

run_script ./scripts/test_minimal_patch.sh
run_script ./scripts/verify_fr02_full.sh
run_script ./scripts/verify_fr05_full.sh
run_script ./scripts/verify_new_playbooks.sh

fr02_rotation_json="$(extract_artifact FR02_ROTATION_PROOF_JSON)"
fr02_revocation_json="$(extract_artifact FR02_REVOCATION_PROOF_JSON)"
fr05_success_json="$(extract_artifact FR05_SUCCESS_PROOF_JSON)"
fr05_failed_safe_json="$(extract_artifact FR05_FAILED_SAFE_PROOF_JSON)"
new_playbooks_json="$(extract_artifact NEW_PLAYBOOKS_PROOF_JSON)"

check_artifact_exists() {
  local key="$1"
  local path="$2"
  if [[ -n "$path" && ! -f "$path" ]]; then
    echo "FAIL: ${key} path does not exist: ${path}" >&2
    exit 1
  fi
}

check_artifact_exists FR02_ROTATION_PROOF_JSON "$fr02_rotation_json"
check_artifact_exists FR02_REVOCATION_PROOF_JSON "$fr02_revocation_json"
check_artifact_exists FR05_SUCCESS_PROOF_JSON "$fr05_success_json"
check_artifact_exists FR05_FAILED_SAFE_PROOF_JSON "$fr05_failed_safe_json"
check_artifact_exists NEW_PLAYBOOKS_PROOF_JSON "$new_playbooks_json"

echo "PASS: full demo suite completed"
echo "FULL_DEMO_SUITE_LOG=${LOG_PATH}"
[[ -n "$fr02_rotation_json" ]] && echo "FR02_ROTATION_PROOF_JSON=${fr02_rotation_json}"
[[ -n "$fr02_revocation_json" ]] && echo "FR02_REVOCATION_PROOF_JSON=${fr02_revocation_json}"
[[ -n "$fr05_success_json" ]] && echo "FR05_SUCCESS_PROOF_JSON=${fr05_success_json}"
[[ -n "$fr05_failed_safe_json" ]] && echo "FR05_FAILED_SAFE_PROOF_JSON=${fr05_failed_safe_json}"
[[ -n "$new_playbooks_json" ]] && echo "NEW_PLAYBOOKS_PROOF_JSON=${new_playbooks_json}"
