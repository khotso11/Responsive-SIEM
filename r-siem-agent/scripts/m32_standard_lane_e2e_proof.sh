#!/usr/bin/env bash
set -euo pipefail

LOG_MASTER="logs/master-roe.log"
LOG_WORKER="logs/roe-worker.log"
LOG_AGENT="logs/agent.log"
CONFIG_MASTER="configs/master.yaml"

if [[ ! -f "$LOG_MASTER" ]]; then
  echo "Missing $LOG_MASTER. Start Terminal E (master-roe) first." >&2
  exit 1
fi
if [[ ! -f "$LOG_WORKER" ]]; then
  echo "Missing $LOG_WORKER. Start Terminal F (roe-worker) first." >&2
  exit 1
fi
if [[ ! -f "$LOG_AGENT" ]]; then
  echo "Missing $LOG_AGENT. Start Terminal G (agent) first." >&2
  exit 1
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
  local last line
  while true; do
    last="$(rg -n "$pattern" "$file" | tail -n 1 || true)"
    if [[ -n "$last" ]]; then
      line="${last%%:*}"
      if [[ "$line" =~ ^[0-9]+$ ]] && (( line > baseline )); then
        echo "$last"
        return
      fi
    fi
    sleep 1
  done
}

wait_new_line_for_run() {
  local pattern="$1"
  local file="$2"
  local baseline="$3"
  local run_id="$4"
  local last line
  while true; do
    fail_if_timed_out
    fail_if_failed_safe
    last="$(rg -n "\"run_id\":\"${run_id}\"" "$file" | rg "$pattern" | tail -n 1 || true)"
    if [[ -n "$last" ]]; then
      line="${last%%:*}"
      if [[ "$line" =~ ^[0-9]+$ ]] && (( line > baseline )); then
        echo "$last"
        return
      fi
    fi
    sleep 1
  done
}

echo "=== M32 STANDARD lane end-to-end ==="

baseline_trigger="$(last_line_num '"msg":"response_trigger_received"' "$LOG_MASTER")"
baseline_waiting="$(last_line_num '"msg":"response_run_waiting_approval"' "$LOG_MASTER")"

ALERT_KEY="A-M32-STD-$(date +%s)"
RULE_ID="R-SEQ-PROCESS-TO-NET"
SEVERITY="high"
GROUP_KEY="10.0.0.77"


go run -mod=vendor ./cmd/master-roe-pubtrigger -config "$CONFIG_MASTER" -alert-key "$ALERT_KEY" -rule-id "$RULE_ID" -severity "$SEVERITY" -group-key "$GROUP_KEY" -lane STANDARD

trigger_line="$(wait_new_line '"msg":"response_trigger_received"' "$LOG_MASTER" "$baseline_trigger")"
if ! printf "%s" "$trigger_line" | rg -q '"lane":"STANDARD"'; then
  echo "ERROR: response_trigger_received did not show STANDARD lane" >&2
  echo "$trigger_line" >&2
  exit 1
fi

echo "$trigger_line"

waiting_line="$(wait_new_line '"msg":"response_run_waiting_approval"' "$LOG_MASTER" "$baseline_waiting")"
RUN_ID="$(printf "%s\n" "$waiting_line" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"

echo "$waiting_line"
echo "RUN_ID: ${RUN_ID}"

# Fail-fast guard baselines (only consider NEW lines after this point)
baseline_approval_events="$(last_line_num '"msg":"approval_timed_out"|"msg":"approval_not_needed"' "$LOG_MASTER")"

fail_if_timed_out() {
  local match
  match="$(rg -n "\"run_id\":\"${RUN_ID}\"" "$LOG_MASTER" | rg '"msg":"approval_timed_out"' | tail -n 1 || true)"
  if [[ -n "$match" ]]; then
    local line="${match%%:*}"
    if [[ "$line" =~ ^[0-9]+$ ]] && (( line > baseline_approval_events )); then
      echo "FAIL: approval_timed_out for RUN_ID=${RUN_ID}"
      exit 1
    fi
  fi
}

fail_if_failed_safe() {
  local match
  match="$(rg -n "\"run_id\":\"${RUN_ID}\"" "$LOG_MASTER" | rg '"msg":"approval_not_needed"' | rg '"status":"FAILED_SAFE"' | tail -n 1 || true)"
  if [[ -n "$match" ]]; then
    local line="${match%%:*}"
    if [[ "$line" =~ ^[0-9]+$ ]] && (( line > baseline_approval_events )); then
      echo "FAIL: run is FAILED_SAFE (approval too late) RUN_ID=${RUN_ID}"
      exit 1
    fi
  fi
}

# Approve
if command -v nats >/dev/null 2>&1; then
  subject="$(awk '/subject_approvals:/{print $2; exit}' "$CONFIG_MASTER")"
  if [[ -z "${subject}" ]]; then
    subject="rsiem.response.approvals"
  fi
  payload=$(printf '{"run_id":"%s","decision":"approve","actor":"khotso","reason":"lab approval","ts_unix_ms":%s}' "$RUN_ID" "$(date +%s%3N)")
  nats pub "$subject" "$payload"
else
  subject="$(awk '/subject_approvals:/{print $2; exit}' "$CONFIG_MASTER")"
  if [[ -z "${subject}" ]]; then
    subject="rsiem.response.approvals"
  fi
  payload=$(printf '{"run_id":"%s","decision":"approve","actor":"khotso","reason":"lab approval","ts_unix_ms":%s}' "$RUN_ID" "$(date +%s%3N)")
  echo "Run manually (Terminal D) then press Enter:"
  echo "nats pub $subject '$payload'"
  read -r -p "Press Enter to continue" _
fi

baseline_step_received="$(rg -n "\"run_id\":\"${RUN_ID}\"" "$LOG_WORKER" | rg '"msg":"step_received"' | tail -n 1 | cut -d: -f1 || true)"
if [[ -z "${baseline_step_received}" ]]; then
  baseline_step_received=0
fi
baseline_step_succeeded="$(rg -n "\"run_id\":\"${RUN_ID}\"" "$LOG_WORKER" | rg '"msg":"step_succeeded"' | tail -n 1 | cut -d: -f1 || true)"
if [[ -z "${baseline_step_succeeded}" ]]; then
  baseline_step_succeeded=0
fi
baseline_agent="$(rg -n "\"run_id\":\"${RUN_ID}\"" "$LOG_AGENT" | rg '"msg":"agent_command_exec_start"' | tail -n 1 | cut -d: -f1 || true)"
if [[ -z "${baseline_agent}" ]]; then
  baseline_agent=0
fi

step_received_line="$(wait_new_line_for_run '"msg":"step_received"' "$LOG_WORKER" "$baseline_step_received" "$RUN_ID")"
step_succeeded_line="$(wait_new_line_for_run '"msg":"step_succeeded"' "$LOG_WORKER" "$baseline_step_succeeded" "$RUN_ID")"

agent_line="$(wait_new_line_for_run '"msg":"agent_command_exec_start"' "$LOG_AGENT" "$baseline_agent" "$RUN_ID")"

agent_count="$(rg "\"run_id\":\"${RUN_ID}\"" "$LOG_AGENT" | rg -c '"msg":"agent_command_exec_start"')"
if [[ "$agent_count" != "1" ]]; then
  echo "ERROR: expected exactly 1 agent_command_exec_start, got ${agent_count}" >&2
  exit 1
fi

echo "$step_received_line"
echo "$step_succeeded_line"
echo "$agent_line"

echo "PASS: M32 STANDARD lane end-to-end"
