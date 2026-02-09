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

wait_new_line_for_run() {
  local pattern="$1"
  local file="$2"
  local baseline="$3"
  local run_id="$4"
  local max_wait="$5"
  local last line elapsed=0
  while (( elapsed < max_wait )); do
    last="$(rg -n "\"run_id\":\"${run_id}\"" "$file" | rg "$pattern" | tail -n 1 || true)"
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

fail_if_timeout_or_failed_safe() {
  local run_id="$1"
  local baseline="$2"
  local timed_out failed_safe line
  timed_out="$(rg -n "\"run_id\":\"${run_id}\"" "$LOG_MASTER" | rg '"msg":"approval_timed_out"' | tail -n 1 || true)"
  if [[ -n "$timed_out" ]]; then
    line="${timed_out%%:*}"
    if [[ "$line" =~ ^[0-9]+$ ]] && (( line > baseline )); then
      echo "FAIL: approval_timed_out for RUN_ID=${run_id}" >&2
      exit 1
    fi
  fi

  failed_safe="$(rg -n "\"run_id\":\"${run_id}\"" "$LOG_MASTER" | rg '"msg":"approval_not_needed"' | rg '"status":"FAILED_SAFE"' | tail -n 1 || true)"
  if [[ -n "$failed_safe" ]]; then
    line="${failed_safe%%:*}"
    if [[ "$line" =~ ^[0-9]+$ ]] && (( line > baseline )); then
      echo "FAIL: run is FAILED_SAFE (approval too late) RUN_ID=${run_id}" >&2
      exit 1
    fi
  fi
}

fail_if_agent_denied() {
  local run_id="$1"
  local baseline="$2"
  local denied line
  denied="$(rg -n "\"run_id\":\"${run_id}\"" "$LOG_AGENT" | rg '"msg":"agent_command_exec_denied"' | tail -n 1 || true)"
  if [[ -n "$denied" ]]; then
    line="${denied%%:*}"
    if [[ "$line" =~ ^[0-9]+$ ]] && (( line > baseline )); then
      echo "FAIL: agent_command_exec_denied for RUN_ID=${run_id}" >&2
      exit 1
    fi
  fi
}

fail_if_step_failed_safe() {
  local run_id="$1"
  local baseline="$2"
  local failed line
  failed="$(rg -n "\"run_id\":\"${run_id}\"" "$LOG_MASTER" | rg '"msg":"response_step_result_received"' | rg '"status":"FAILED_SAFE"' | tail -n 1 || true)"
  if [[ -n "$failed" ]]; then
    line="${failed%%:*}"
    if [[ "$line" =~ ^[0-9]+$ ]] && (( line > baseline )); then
      echo "FAIL: response_step_result_received FAILED_SAFE for RUN_ID=${run_id}" >&2
      exit 1
    fi
  fi
}

echo "=== M37 agent_command end-to-end proof ==="

EVENT_ID="evt.m37.$(date +%s)"
LINE="M37 invalid user from 10.0.0.77 ts=$(date +%s)"
TRIGGER_IDEM_KEY="trig.alert.A-COLLECT-INVALID-USER-${EVENT_ID}"

baseline_run_created="$(last_line_num '"msg":"response_run_created"' "$LOG_MASTER")"
baseline_approval_req="$(last_line_num '"msg":"approval_request_published"' "$LOG_MASTER")"
baseline_waiting="$(last_line_num '"msg":"response_run_waiting_approval"' "$LOG_MASTER")"
baseline_step_result="$(last_line_num '"msg":"response_step_result_received"' "$LOG_MASTER")"
baseline_fail_state="$(last_line_num '"msg":"approval_timed_out"|"msg":"approval_not_needed"' "$LOG_MASTER")"

baseline_step_received=0
if [[ -n "$LOG_WORKER" ]]; then
  baseline_step_received="$(last_line_num '"msg":"step_received"' "$LOG_WORKER")"
fi
baseline_agent_start="$(last_line_num '"msg":"agent_command_exec_start"' "$LOG_AGENT")"
baseline_agent_done="$(last_line_num '"msg":"agent_command_exec_done"' "$LOG_AGENT")"
baseline_agent_denied="$(last_line_num '"msg":"agent_command_exec_denied"' "$LOG_AGENT")"


if ! go run -mod=vendor ./cmd/master-pubevent -config configs/master.yaml -event_idem_key "$EVENT_ID" -line "$LINE"; then
  echo "Missing NATS? Start Terminal A (NATS) and retry." >&2
  exit 2
fi

run_created_line="$(wait_new_line '"msg":"response_run_created"' "$LOG_MASTER" "$baseline_run_created" 20 || true)"
if [[ -z "$run_created_line" ]]; then
  echo "FAIL: timeout waiting for response_run_created" >&2
  exit 1
fi

approval_req_line="$(wait_new_line '"msg":"approval_request_published"' "$LOG_MASTER" "$baseline_approval_req" 20 || true)"
if [[ -z "$approval_req_line" ]]; then
  echo "FAIL: timeout waiting for approval_request_published" >&2
  exit 1
fi

waiting_line="$(wait_new_line '"msg":"response_run_waiting_approval"' "$LOG_MASTER" "$baseline_waiting" 20 || true)"
if [[ -z "$waiting_line" ]]; then
  echo "FAIL: timeout waiting for response_run_waiting_approval" >&2
  exit 1
fi

RUN_ID="$(printf "%s\n" "$waiting_line" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"
if [[ -z "$RUN_ID" ]]; then
  echo "FAIL: unable to extract run_id" >&2
  exit 1
fi


echo "$run_created_line"
echo "$approval_req_line"
echo "$waiting_line"
echo "event_idem_key: ${EVENT_ID}"
echo "trigger_idem_key: ${TRIGGER_IDEM_KEY}"
echo "run_id: ${RUN_ID}"

# Approve
if ! go run -mod=vendor ./cmd/master-roe-approve -config configs/master.yaml -run_id "$RUN_ID" -decision approve -actor khotso -reason "lab approval"; then
  echo "FAIL: approval publish failed" >&2
  exit 1
fi

# Wait for worker step_received (agent_command) or master response_step_published (agent_command)
step_received_line=""
step_published_line=""
max_wait=30
elapsed=0
while (( elapsed < max_wait )); do
  fail_if_timeout_or_failed_safe "$RUN_ID" "$baseline_fail_state"
  fail_if_agent_denied "$RUN_ID" "$baseline_agent_denied"
  if [[ -n "$LOG_WORKER" ]]; then
    step_received_line="$(wait_new_line_for_run '"msg":"step_received"' "$LOG_WORKER" "$baseline_step_received" "$RUN_ID" 1 || true)"
    if [[ -n "$step_received_line" ]]; then
      break
    fi
  fi
  step_published_line="$(wait_new_line_for_run '"msg":"response_step_published"' "$LOG_MASTER" "$baseline_step_result" "$RUN_ID" 1 || true)"
  if [[ -n "$step_published_line" ]]; then
    if printf "%s" "$step_published_line" | rg -q '"action_type":"agent_command"'; then
      break
    fi
  fi
  sleep 1
  elapsed=$((elapsed + 1))
done
if [[ -z "$step_received_line" && -z "$step_published_line" ]]; then
  echo "FAIL: timeout waiting for agent_command step (step_received or response_step_published)" >&2
  exit 1
fi

STEP_ID=""
if [[ -n "$step_received_line" ]]; then
  if ! printf "%s" "$step_received_line" | rg -q '"action_type":"agent_command"'; then
    echo "FAIL: step_received did not show action_type=agent_command" >&2
    echo "$step_received_line" >&2
    exit 1
  fi
  STEP_ID="$(printf "%s\n" "$step_received_line" | sed -n 's/.*"step_id":"\([^"]*\)".*/\1/p')"
else
  STEP_ID="$(printf "%s\n" "$step_published_line" | sed -n 's/.*"step_id":"\([^"]*\)".*/\1/p')"
fi
if [[ -z "$STEP_ID" ]]; then
  echo "FAIL: unable to extract step_id from step_received" >&2
  exit 1
fi
echo "step_id: ${STEP_ID}"

# Wait for response_step_result_received SUCCEEDED
step_result_line=""
elapsed=0
while (( elapsed < max_wait )); do
  fail_if_timeout_or_failed_safe "$RUN_ID" "$baseline_fail_state"
  fail_if_step_failed_safe "$RUN_ID" "$baseline_step_result"
  step_result_line="$(rg -n "\"run_id\":\"${RUN_ID}\"" "$LOG_MASTER" | rg '"msg":"response_step_result_received"' | rg '"status":"SUCCEEDED"' | tail -n 1 || true)"
  if [[ -n "$step_result_line" ]]; then
    line="${step_result_line%%:*}"
    if [[ "$line" =~ ^[0-9]+$ ]] && (( line > baseline_step_result )); then
      break
    fi
  fi
  sleep 1
  elapsed=$((elapsed + 1))
done
if [[ -z "$step_result_line" ]]; then
  echo "FAIL: timeout waiting for response_step_result_received SUCCEEDED" >&2
  exit 1
fi

# Wait for agent exec start/done
agent_start_line=""
agent_done_line=""
elapsed=0
while (( elapsed < max_wait )); do
  fail_if_timeout_or_failed_safe "$RUN_ID" "$baseline_fail_state"
  fail_if_agent_denied "$RUN_ID" "$baseline_agent_denied"
  agent_start_line="$(rg -n "\"run_id\":\"${RUN_ID}\"" "$LOG_AGENT" | rg '"msg":"agent_command_exec_start"' | rg '"command_id":"ping"' | tail -n 1 || true)"
  if [[ -n "$agent_start_line" ]]; then
    line="${agent_start_line%%:*}"
    if [[ "$line" =~ ^[0-9]+$ ]] && (( line > baseline_agent_start )); then
      break
    fi
  fi
  sleep 1
  elapsed=$((elapsed + 1))
done
if [[ -z "$agent_start_line" ]]; then
  echo "FAIL: timeout waiting for agent_command_exec_start" >&2
  exit 1
fi

elapsed=0
while (( elapsed < max_wait )); do
  fail_if_timeout_or_failed_safe "$RUN_ID" "$baseline_fail_state"
  fail_if_agent_denied "$RUN_ID" "$baseline_agent_denied"
agent_done_line="$(rg -n "\"run_id\":\"${RUN_ID}\"" "$LOG_AGENT" | rg '"msg":"agent_command_exec_done"' | rg '"command_id":"ping"' | rg '"exit_code":0' | tail -n 1 || true)"
  if [[ -n "$agent_done_line" ]]; then
    line="${agent_done_line%%:*}"
    if [[ "$line" =~ ^[0-9]+$ ]] && (( line > baseline_agent_done )); then
      break
    fi
  fi
  sleep 1
  elapsed=$((elapsed + 1))
done
if [[ -z "$agent_done_line" ]]; then
  echo "FAIL: timeout waiting for agent_command_exec_done" >&2
  exit 1
fi

COMMAND_ID="$(printf "%s\n" "$agent_start_line" | sed -n 's/.*"command_id":"\\([^"]*\\)".*/\\1/p')"
if [[ -z "$COMMAND_ID" ]]; then
  COMMAND_ID="ping"
fi


echo "$step_received_line"
echo "$step_result_line"
echo "$agent_start_line"
echo "$agent_done_line"

echo "command_id: ${COMMAND_ID}"
echo "PASS: M37 agent_command end-to-end"
