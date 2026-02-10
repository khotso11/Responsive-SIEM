#!/usr/bin/env bash
set -euo pipefail

LOG_MASTER="logs/master-roe.log"

DEMO_EVIDENCE_LOG="${DEMO_EVIDENCE_LOG:-logs/demo_$(date +%Y%m%d_%H%M%S).log}"

mkdir -p logs tmp

echo "=== Sprint C Demo Runner ==="
echo "Evidence log: ${DEMO_EVIDENCE_LOG}"

run_optional_script() {
  local script="$1"
  if [[ ! -x "$script" ]]; then
    echo "SKIP: ${script} not found or not executable"
    demo_warn=1
    return 0
  fi
  echo "=== Running ${script} ==="
  "$script"
}

last_line_num() {
  local pattern="$1"
  local file="$2"
  local last
  last="$(rg -n "$pattern" "$file" | tail -n 1 || true)"
  if [[ -z "$last" ]]; then
    echo 0
    return
  fi
  echo "${last%%:*}"
}

wait_new_run_id() {
  local pattern="$1"
  local file="$2"
  local baseline="$3"
  local max_wait="$4"
  local last line
  local elapsed=0
  while (( elapsed < max_wait )); do
    last="$(rg -n "$pattern" "$file" | tail -n 1 || true)"
    if [[ -n "$last" ]]; then
      line="${last%%:*}"
      if [[ "$line" =~ ^[0-9]+$ ]] && (( line > baseline )); then
        printf "%s\n" "$last" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p'
        return 0
      fi
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  return 1
}

demo_warn=0

run_optional_script "./scripts/m40_collector_publish_proof.sh"
run_optional_script "./scripts/m41_detector_invalid_user_rule_proof.sh"

RUN_ID=""
M37_OUTPUT=""
if [[ -x "./scripts/m37_agent_command_e2e_proof.sh" ]]; then
  echo "=== Running ./scripts/m37_agent_command_e2e_proof.sh ==="
  M37_OUTPUT_FILE="$(mktemp)"
  if ! ./scripts/m37_agent_command_e2e_proof.sh |& tee "$M37_OUTPUT_FILE"; then
    echo "FAIL: m37_agent_command_e2e_proof.sh failed" >&2
    exit 1
  fi
  RUN_ID="$(sed -n 's/^run_id: //p' "$M37_OUTPUT_FILE" | tail -n 1)"
  rm -f "$M37_OUTPUT_FILE"
fi

if [[ ! -s "$LOG_MASTER" ]]; then
  echo "WARN: ${LOG_MASTER} missing; cannot derive run_id for approval" >&2
  demo_warn=1
elif [[ -z "$RUN_ID" ]]; then
  baseline_run_created="$(last_line_num '"msg":"response_run_created"' "$LOG_MASTER")"
  RUN_ID="$(wait_new_run_id '"msg":"response_run_created".*"rule_id":"R-COLLECT-INVALID-USER".*"playbook_id":"PB-AGENT-PING-LOCALHOST"' "$LOG_MASTER" "$baseline_run_created" 15 || true)"
fi

if [[ -n "$RUN_ID" ]]; then
  echo "run_id: ${RUN_ID}"
  if command -v nats >/dev/null 2>&1; then
    echo "=== Publishing approval for ${RUN_ID} ==="
    nats pub rsiem.response.approvals "{\"run_id\":\"${RUN_ID}\",\"decision\":\"approve\",\"actor\":\"khotso\"}"
  else
    echo "SKIP: nats CLI not found; approval not published"
    demo_warn=1
  fi
else
  echo "SKIP: no run_id found for M37-style approval"
  demo_warn=1
fi

if ! run_optional_script "./scripts/m42_detector_process_count_rule_proof.sh"; then
  echo "FAIL: M42 proof failed" >&2
  exit 1
fi

if [[ "$demo_warn" -ne 0 ]]; then
  echo "WARN: demo_runner_sprint_c completed with warnings; see output above" >&2
  echo "PASS: Sprint C demo runner (with warnings)"
  exit 0
fi

echo "PASS: Sprint C demo runner"
echo "Evidence log: ${DEMO_EVIDENCE_LOG}"
