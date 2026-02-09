#!/usr/bin/env bash
set -euo pipefail

LOG_MASTER="logs/master-roe.log"
LOG_WORKER="logs/roe-worker.log"
LOG_AGENT="logs/agent.log"
DEMO_LOG="tmp/demo.log"

if [[ ! -f "$LOG_MASTER" ]]; then
  echo "Missing $LOG_MASTER. Start Terminal E (master-roe) first." >&2
  exit 1
fi

mkdir -p logs tmp

baseline_line="$(rg -n '"msg":"response_run_waiting_approval"' "$LOG_MASTER" | tail -n 1 | cut -d: -f1 || true)"
if [[ -z "${baseline_line}" ]]; then
  baseline_line=0
fi

echo "M25 invalid user from 10.0.0.77 ts=$(date +%s)" >> "$DEMO_LOG"

echo "Waiting for new response_run_waiting_approval after line ${baseline_line}..."
while true; do
  last_match="$(rg -n '"msg":"response_run_waiting_approval"' "$LOG_MASTER" | tail -n 1 || true)"
  if [[ -z "${last_match}" ]]; then
    sleep 1
    continue
  fi

  cur_line="${last_match%%:*}"
  if [[ ! "${cur_line}" =~ ^[0-9]+$ ]]; then
    sleep 1
    continue
  fi

  if (( cur_line > baseline_line )); then
    RUN_ID="$(printf "%s\n" "$last_match" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"
    if [[ -n "${RUN_ID}" ]]; then
      break
    fi
  fi

  sleep 1
done

echo "RUN_ID: ${RUN_ID}"

read -r -p "Stop worker (Terminal F) now (Ctrl+C), press Enter" _

go run -mod=vendor ./cmd/master-roe-approve -config configs/master.yaml -run_id "$RUN_ID" -decision approve -actor khotso -reason "lab approval"

read -r -p "Start worker (Terminal F) now (re-run command), press Enter" _

echo "Waiting for first worker terminal success..."
while true; do
  if rg "\"run_id\":\"${RUN_ID}\"" "$LOG_WORKER" | rg -q "step_succeeded|step_duplicate_succeeded|worker_result_replay"; then
    break
  fi
  sleep 1
done

baseline_exec_start="$(rg "\"run_id\":\"${RUN_ID}\"" "$LOG_AGENT" 2>/dev/null | rg -c "agent_command_exec_start" || true)"
if [[ -z "${baseline_exec_start}" ]]; then
  baseline_exec_start=0
fi

echo "agent_command_exec_start count BEFORE replay: ${baseline_exec_start}"

read -r -p "Induce replay: stop worker (Ctrl+C) and start it again, then press Enter" _

sleep 3

echo "\nWorker evidence (${LOG_WORKER}):"
rg "\"run_id\":\"${RUN_ID}\"" "$LOG_WORKER" | rg "step_received|step_succeeded|worker_result_replay|step_duplicate_succeeded"

echo "\nAgent evidence (${LOG_AGENT}):"
rg "\"run_id\":\"${RUN_ID}\"" "$LOG_AGENT" | rg "agent_command_exec_start|agent_command_exec_done"

after_exec_start="$(rg "\"run_id\":\"${RUN_ID}\"" "$LOG_AGENT" 2>/dev/null | rg -c "agent_command_exec_start" || true)"
if [[ -z "${after_exec_start}" ]]; then
  after_exec_start=0
fi

echo "agent_command_exec_start count AFTER replay: ${after_exec_start}"

if [[ "${after_exec_start}" != "${baseline_exec_start}" ]]; then
  echo "ERROR: agent_command_exec_start count changed (expected no double exec)." >&2
  exit 1
fi
