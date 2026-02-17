#!/usr/bin/env bash
set -euo pipefail

LOG_COLLECTOR="logs/collector-tail.log"
LOG_DETECTOR="logs/detector-v0.log"
LOG_MASTER="logs/master-roe.log"
LOG_WORKER="logs/roe-worker.log"
LOG_AGENT="logs/agent.log"
DEMO_LOG="tmp/demo.log"

require_log() {
  local file="$1"
  local label="$2"
  if [[ ! -s "$file" ]]; then
    echo "FAIL: missing or empty ${file}. Start Terminal ${label} first." >&2
    exit 2
  fi
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

wait_in_slice() {
  local pattern="$1"
  local file="$2"
  local start_line="$3"
  local span="$4"
  local max_wait="$5"
  local elapsed=0
  while (( elapsed < max_wait )); do
    if (( start_line < 1 )); then
      start_line=1
    fi
    local end_line=$((start_line + span))
    local slice
    slice="$(sed -n "${start_line},${end_line}p" "$file" | nl -ba -v "$start_line" -s ":")"
    local match
    match="$(printf "%s\n" "$slice" | rg "$pattern" | head -n 1 || true)"
    if [[ -n "$match" ]]; then
      echo "$match"
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  return 1
}

last_after_line() {
  local pattern="$1"
  local file="$2"
  local baseline="$3"
  local matches
  matches="$(rg -n "$pattern" "$file" | awk -F: -v b="$baseline" '$1 > b' || true)"
  local last
  last="$(printf "%s\n" "$matches" | tail -n 1 || true)"
  if [[ -z "$last" || "$last" == ":" ]]; then
    return 1
  fi
  echo "$last"
  return 0
}

extract_export_command_id() {
  local run_id="$1"
  local step_id="$2"
  local export_line=""
  local command_id=""
  local export_file
  for export_file in exports/roe_steps_latest.jsonl exports/roe_steps.jsonl; do
    if [[ ! -s "$export_file" ]]; then
      continue
    fi
    export_line="$(rg "\"run_id\":\"${run_id}\"" "$export_file" | rg "\"step_id\":\"${step_id}\"" | rg "\"action_type\":\"agent_command\"" | tail -n 1 || true)"
    if [[ -n "$export_line" ]]; then
      command_id="$(printf "%s\n" "$export_line" | sed -n 's/.*"command_id":"\([^"]*\)".*/\1/p')"
      if [[ -z "$command_id" ]]; then
        command_id="$(printf "%s\n" "$export_line" | sed -n 's/.*"message":"agent_command: \([^ ]*\).*/\1/p')"
      fi
      echo "${command_id}|${export_line}"
      return 0
    fi
  done
  echo "|"
  return 1
}

wait_export_parse() {
  local run_id="$1"
  local step_id="$2"
  local max_wait="$3"
  local elapsed=0
  local parse=""
  while (( elapsed < max_wait )); do
    parse="$(extract_export_command_id "$run_id" "$step_id" || true)"
    if [[ -n "${parse#*|}" ]]; then
      echo "$parse"
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  echo "$parse"
  return 1
}

debug_recent() {
  local pattern="$1"
  local file="$2"
  echo "Context: last 10 relevant lines from ${file}:" >&2
  rg "$pattern" "$file" | tail -n 10 >&2 || true
}

echo "=== M43 process_count playbook e2e proof ==="

require_log "$LOG_COLLECTOR" "H (collector-tail)"
require_log "$LOG_DETECTOR" "I (detector-v0)"
require_log "$LOG_MASTER" "E (master-roe)"
require_log "$LOG_WORKER" "F (roe-worker)"
require_log "$LOG_AGENT" "G (agent)"

mkdir -p tmp

baseline_trigger="$(last_line_num '"msg":"trigger_published"' "$LOG_DETECTOR")"
baseline_run_created="$(last_line_num '"msg":"response_run_created"' "$LOG_MASTER")"
baseline_step_published="$(last_line_num '"msg":"response_step_published"' "$LOG_MASTER")"
baseline_step_received="$(last_line_num '"msg":"step_received"' "$LOG_WORKER")"
baseline_step_succeeded="$(last_line_num '"msg":"step_succeeded"' "$LOG_WORKER")"
baseline_step_failed="$(last_line_num '"msg":"step_failed_safe"|"msg":"step_failed_transient"' "$LOG_WORKER")"
baseline_agent_start="$(last_line_num '"msg":"agent_command_exec_start"' "$LOG_AGENT")"
baseline_agent_done="$(last_line_num '"msg":"agent_command_exec_done"' "$LOG_AGENT")"
baseline_agent_denied="$(last_line_num '"msg":"agent_command_exec_denied"' "$LOG_AGENT")"

NOW="$(date +%s)"
HOST_ID="m43-${NOW}"
echo "M42 process count host=${HOST_ID} ts=${NOW} process_count=3" >> "$DEMO_LOG"

trigger_line="$(wait_in_slice '"msg":"trigger_published".*"alert_key":"A-COUNT-PROCESS-HOST-' "$LOG_DETECTOR" "$((baseline_trigger + 1))" 700 30 || true)"
if [[ -z "$trigger_line" ]]; then
  echo "FAIL: timeout waiting for trigger_published A-COUNT-PROCESS-HOST" >&2
  debug_recent '"msg":"trigger_published"|"msg":"rule_matched"' "$LOG_DETECTOR"
  exit 1
fi
ALERT_KEY="$(printf "%s\n" "$trigger_line" | sed -n 's/.*"alert_key":"\([^"]*\)".*/\1/p')"
if [[ -z "$ALERT_KEY" ]]; then
  echo "FAIL: unable to extract alert_key from trigger_published" >&2
  echo "$trigger_line" >&2
  exit 1
fi

run_created_line="$(wait_in_slice '"msg":"response_run_created".*"rule_id":"R-COUNT-PROCESS-HOST".*"playbook_id":"PB-COUNT-PROCESS-HOST"' "$LOG_MASTER" "$((baseline_run_created + 1))" 900 30 || true)"
if [[ -z "$run_created_line" ]]; then
  echo "FAIL: timeout waiting for response_run_created R-COUNT-PROCESS-HOST/PB-COUNT-PROCESS-HOST" >&2
  debug_recent '"msg":"response_run_created".*"rule_id":"R-COUNT-PROCESS-HOST"' "$LOG_MASTER"
  exit 1
fi
RUN_ID="$(printf "%s\n" "$run_created_line" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"
if [[ -z "$RUN_ID" ]]; then
  echo "FAIL: unable to extract run_id" >&2
  echo "$run_created_line" >&2
  exit 1
fi

step_published_line="$(wait_in_slice "\"msg\":\"response_step_published\".*\"run_id\":\"${RUN_ID}\".*\"action_type\":\"agent_command\"" "$LOG_MASTER" "$((baseline_step_published + 1))" 1200 30 || true)"
if [[ -z "$step_published_line" ]]; then
  echo "FAIL: timeout waiting for response_step_published agent_command run_id=${RUN_ID}" >&2
  debug_recent "\"msg\":\"response_step_published\".*\"run_id\":\"${RUN_ID}\"" "$LOG_MASTER"
  exit 1
fi
STEP_ID="$(printf "%s\n" "$step_published_line" | sed -n 's/.*"step_id":"\([^"]*\)".*/\1/p')"
if [[ -z "$STEP_ID" ]]; then
  echo "FAIL: unable to extract step_id from response_step_published" >&2
  echo "$step_published_line" >&2
  exit 1
fi

step_received_line="$(wait_in_slice "\"msg\":\"step_received\".*\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\".*\"action_type\":\"agent_command\"" "$LOG_WORKER" "$((baseline_step_received + 1))" 1200 30 || true)"
if [[ -z "$step_received_line" ]]; then
  echo "FAIL: timeout waiting for worker step_received run_id=${RUN_ID} step_id=${STEP_ID}" >&2
  debug_recent "\"msg\":\"step_received\".*\"run_id\":\"${RUN_ID}\"" "$LOG_WORKER"
  exit 1
fi

step_succeeded_line=""
step_failed_line=""
elapsed=0
while (( elapsed < 60 )); do
  step_succeeded_line="$(last_after_line "\"msg\":\"step_succeeded\".*\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\"" "$LOG_WORKER" "$baseline_step_succeeded" || true)"
  if [[ -n "$step_succeeded_line" ]]; then
    break
  fi
  step_failed_line="$(last_after_line "\"msg\":\"step_failed_safe\"|\"msg\":\"step_failed_transient\"" "$LOG_WORKER" "$baseline_step_failed" | rg "\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\"" || true)"
  if [[ -z "$step_failed_line" ]]; then
    step_failed_line="$(last_after_line "\"msg\":\"step_failed_safe\".*\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\"|\"msg\":\"step_failed_transient\".*\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\"" "$LOG_WORKER" "$baseline_step_failed" || true)"
  fi
  if [[ -n "$step_failed_line" ]]; then
    break
  fi
  sleep 1
  elapsed=$((elapsed + 1))
done
if [[ -z "$step_succeeded_line" && -z "$step_failed_line" ]]; then
  echo "FAIL: timeout waiting for worker terminal result (step_succeeded or step_failed_*) run_id=${RUN_ID} step_id=${STEP_ID}" >&2
  debug_recent "\"msg\":\"step_succeeded\"|\"msg\":\"step_failed_safe\"|\"msg\":\"step_failed_transient\"" "$LOG_WORKER"
  debug_recent "\"msg\":\"response_step_result_received\".*\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\"" "$LOG_MASTER"
  exit 1
fi
if [[ -n "$step_failed_line" ]]; then
  export_parse="$(wait_export_parse "$RUN_ID" "$STEP_ID" 8 || true)"
  export_command_id="${export_parse%%|*}"
  export_line="${export_parse#*|}"
  echo "FAIL: worker reported terminal failure for agent_command step run_id=${RUN_ID} step_id=${STEP_ID}" >&2
  echo "$step_failed_line" >&2
  debug_recent "\"msg\":\"response_step_result_received\".*\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\"" "$LOG_MASTER"
  debug_recent "\"msg\":\"agent_command_exec_denied\".*\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\"" "$LOG_AGENT"
  if [[ -n "$export_line" ]]; then
    echo "Context: export step line: ${export_line}" >&2
  fi
  if [[ -n "$export_command_id" ]]; then
    echo "Context: export command_id=${export_command_id}" >&2
  fi
  exit 1
fi

export_parse="$(wait_export_parse "$RUN_ID" "$STEP_ID" 8 || true)"
EXPORT_COMMAND_ID="${export_parse%%|*}"
EXPORT_LINE="${export_parse#*|}"
if [[ -z "$EXPORT_LINE" ]]; then
  echo "FAIL: unable to find exported agent_command step result for run_id=${RUN_ID} step_id=${STEP_ID}" >&2
  debug_recent "\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\".*\"action_type\":\"agent_command\"" "exports/roe_steps.jsonl"
  exit 1
fi
if [[ -z "$EXPORT_COMMAND_ID" ]]; then
  echo "FAIL: unable to extract command_id from exported step line for run_id=${RUN_ID} step_id=${STEP_ID}" >&2
  echo "$EXPORT_LINE" >&2
  exit 1
fi
if [[ "$EXPORT_COMMAND_ID" != "ping" ]]; then
  echo "FAIL: exported command_id mismatch (expected ping, got ${EXPORT_COMMAND_ID})" >&2
  echo "$EXPORT_LINE" >&2
  exit 1
fi

agent_start_line="$(wait_in_slice "\"msg\":\"agent_command_exec_start\".*\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\".*\"command_id\":\"ping\"" "$LOG_AGENT" "$((baseline_agent_start + 1))" 1200 30 || true)"
if [[ -z "$agent_start_line" ]]; then
  echo "FAIL: timeout waiting for agent_command_exec_start command_id=ping run_id=${RUN_ID} step_id=${STEP_ID}" >&2
  debug_recent "\"msg\":\"agent_command_exec_denied\".*\"run_id\":\"${RUN_ID}\"" "$LOG_AGENT"
  debug_recent "\"msg\":\"agent_command_exec_start\".*\"run_id\":\"${RUN_ID}\"" "$LOG_AGENT"
  exit 1
fi

agent_done_line="$(wait_in_slice "\"msg\":\"agent_command_exec_done\".*\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\".*\"command_id\":\"ping\"" "$LOG_AGENT" "$((baseline_agent_done + 1))" 1200 30 || true)"
if [[ -z "$agent_done_line" ]]; then
  echo "FAIL: timeout waiting for agent_command_exec_done command_id=ping run_id=${RUN_ID} step_id=${STEP_ID}" >&2
  debug_recent "\"msg\":\"agent_command_exec_done\".*\"run_id\":\"${RUN_ID}\"" "$LOG_AGENT"
  exit 1
fi

agent_start_count="$(rg "\"msg\":\"agent_command_exec_start\".*\"run_id\":\"${RUN_ID}\".*\"step_id\":\"${STEP_ID}\".*\"command_id\":\"ping\"" "$LOG_AGENT" | wc -l | tr -d ' ')"
if [[ "$agent_start_count" != "1" ]]; then
  echo "FAIL: expected exactly one agent_command_exec_start for run_id=${RUN_ID} step_id=${STEP_ID}, got ${agent_start_count}" >&2
  debug_recent "\"msg\":\"agent_command_exec_denied\".*\"run_id\":\"${RUN_ID}\"" "$LOG_AGENT"
  debug_recent "\"msg\":\"agent_command_exec_start\".*\"run_id\":\"${RUN_ID}\"" "$LOG_AGENT"
  exit 1
fi

echo "$trigger_line"
echo "$run_created_line"
echo "$step_published_line"
echo "$step_received_line"
echo "$step_succeeded_line"
echo "$agent_start_line"
echo "$agent_done_line"
echo "export_step_line: ${EXPORT_LINE}"
echo "PASS: M43 process_count playbook e2e proof alert_key=${ALERT_KEY} run_id=${RUN_ID} step_id=${STEP_ID} command_id=${EXPORT_COMMAND_ID}"
