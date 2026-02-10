#!/usr/bin/env bash
set -euo pipefail

LOG_MASTER="logs/master-roe.log"
LOG_AGENT="logs/agent.log"

require_log() {
  local file="$1"
  local label="$2"
  if [[ ! -s "$file" ]]; then
    echo "Missing or empty $file. Start Terminal $label first." >&2
    exit 2
  fi
}

require_log "$LOG_MASTER" "E (master-roe)"
require_log "$LOG_AGENT" "G (agent)"

LOG_WORKER="logs/roe-worker.log"
if [[ ! -s "$LOG_WORKER" ]]; then
  echo "WARN: worker log missing; validating via master-roe only." >&2
  LOG_WORKER=""
fi

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

wait_new_line() {
  local pattern="$1"
  local file="$2"
  local baseline="$3"
  local max_wait="$4"
  local last line elapsed=0
  while (( elapsed < max_wait )); do
    last="$(rg -n "$pattern" "$file" | tail -n 1 || true)"
    if [[ -n "$last" ]]; then
      line="${last%%:*}"
      if [[ "$line" =~ ^[0-9]+$ ]] && (( line > baseline )); then
        echo "$last"
        return 0
      fi
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  return 1
}

echo "=== M38 agent allowlist denied proof ==="

ALERT_KEY="A-M38-DENY-$(date +%s)"
RULE_ID="R-COUNT-PROCESS-HOST"
SEVERITY="high"
GROUP_KEY="10.0.0.77"

baseline_run_created="$(last_line_num '"msg":"response_run_created"' "$LOG_MASTER")"

if ! go run -mod=vendor ./cmd/master-roe-pubtrigger -config configs/master.yaml -alert-key "$ALERT_KEY" -rule-id "$RULE_ID" -severity "$SEVERITY" -group-key "$GROUP_KEY" -lane STANDARD; then
  echo "Missing NATS? Start Terminal A (NATS) and retry." >&2
  exit 2
fi

run_created_line="$(wait_new_line '"msg":"response_run_created"' "$LOG_MASTER" "$baseline_run_created" 20 || true)"
if [[ -z "$run_created_line" ]]; then
  echo "FAIL: timeout waiting for response_run_created" >&2
  exit 1
fi
RUN_ID="$(printf "%s\n" "$run_created_line" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"
if [[ -z "$RUN_ID" ]]; then
  echo "FAIL: unable to extract run_id" >&2
  exit 1
fi

echo "$run_created_line"
echo "run_id: ${RUN_ID}"

start_line="${run_created_line%%:*}"
if [[ -z "$start_line" || ! "$start_line" =~ ^[0-9]+$ ]]; then
  echo "FAIL: unable to extract start line for run_id slice" >&2
  exit 1
fi
end_line=$((start_line + 300))
slice="$(sed -n "${start_line},${end_line}p" "$LOG_MASTER")"

step_published_lines="$(printf "%s\n" "$slice" | rg "\"run_id\":\"${RUN_ID}\"" | rg '"msg":"response_step_published"' || true)"
agent_step_line="$(printf "%s\n" "$step_published_lines" | rg '"action_type":"agent_command"' | head -n 1 || true)"
if [[ -z "$agent_step_line" ]]; then
  echo "FAIL: response_step_published did not show action_type=agent_command" >&2
  echo "Context: response_step_published lines for run_id in slice:" >&2
  printf "%s\n" "$step_published_lines" >&2 || true
  exit 1
fi

AGENT_STEP_ID="$(printf "%s\n" "$agent_step_line" | sed -n 's/.*"step_id":"\([^"]*\)".*/\1/p')"
if [[ -z "$AGENT_STEP_ID" ]]; then
  echo "FAIL: unable to extract agent step_id" >&2
  exit 1
fi

agent_denied_line="$(rg "\"run_id\":\"${RUN_ID}\"" "$LOG_AGENT" | rg "\"step_id\":\"${AGENT_STEP_ID}\"" | rg '"msg":"agent_command_exec_denied"' | rg '"reason":"missing_command"|"reason":"not_allowlisted"' | tail -n 1 || true)"
if [[ -z "$agent_denied_line" ]]; then
  echo "FAIL: agent_command_exec_denied not found for run_id=${RUN_ID} step_id=${AGENT_STEP_ID}" >&2
  echo "Context: recent agent log lines for run_id:" >&2
  rg "\"run_id\":\"${RUN_ID}\"" "$LOG_AGENT" | tail -n 80 >&2 || true
  exit 1
fi

step_failed_line="$(printf "%s\n" "$slice" | rg "\"run_id\":\"${RUN_ID}\"" | rg "\"step_id\":\"${AGENT_STEP_ID}\"" | rg '"msg":"response_step_result_received"' | rg '"status":"FAILED_SAFE"' | head -n 1 || true)"
if [[ -z "$step_failed_line" ]]; then
  echo "FAIL: response_step_result_received FAILED_SAFE not found for agent step" >&2
  echo "Context: response_step_result_received lines for run_id in slice:" >&2
  printf "%s\n" "$slice" | rg "\"run_id\":\"${RUN_ID}\"" | rg '"msg":"response_step_result_received"' >&2 || true
  exit 1
fi

echo "agent_step_id: ${AGENT_STEP_ID}"
echo "$agent_denied_line"
echo "$step_failed_line"

echo "PASS: M38 agent allowlist denied proof"
