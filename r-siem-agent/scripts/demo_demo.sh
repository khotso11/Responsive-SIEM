#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

LOG_MASTER="logs/master-roe.log"
LOG_WORKER="logs/worker.log"
LOG_AGENT="logs/agent.log"
LOG_DETECTOR="logs/detector.log"
LOG_COLLECTOR="logs/collector.log"
DEMO_LOG="tmp/demo.log"

die() {
  local msg="$1"
  echo "FAIL: $msg" >&2
  exit 1
}

line_count() {
  local f="$1"
  if [[ -f "$f" ]]; then
    wc -l < "$f" | tr -d '[:space:]'
  else
    echo 0
  fi
}

tail_from() {
  local f="$1" base="$2"
  local start=$((base + 1))
  if [[ ! -f "$f" ]]; then
    return 0
  fi
  sed -n "${start},\$p" "$f"
}

wait_match() {
  local f="$1" base="$2" pattern="$3" timeout="${4:-30}"
  local i=0
  while (( i < timeout )); do
    local line
    line="$(tail_from "$f" "$base" | rg -F "$pattern" | head -n 1 || true)"
    if [[ -n "$line" ]]; then
      printf '%s\n' "$line"
      return 0
    fi
    sleep 1
    i=$((i + 1))
  done
  return 1
}

wait_match_rg() {
  local f="$1" base="$2" pattern="$3" timeout="${4:-30}"
  local i=0
  while (( i < timeout )); do
    local line
    line="$(tail_from "$f" "$base" | rg "$pattern" | head -n 1 || true)"
    if [[ -n "$line" ]]; then
      printf '%s\n' "$line"
      return 0
    fi
    sleep 1
    i=$((i + 1))
  done
  return 1
}

need_cmd() {
  local cmd="$1"
  local hint="${2:-}"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    [[ -n "$hint" ]] && die "$hint"
    die "missing command: $cmd"
  fi
}

mkdir -p logs tmp

need_cmd rg "demo_demo requires rg (install ripgrep and rerun)."
need_cmd nats "demo_demo requires nats CLI (install or add to PATH)."
need_cmd sed
need_cmd tail
need_cmd date

[[ -s "$LOG_MASTER" ]] || die "missing or empty $LOG_MASTER. Run ./scripts/demo_up.sh first."
[[ -s "$LOG_WORKER" ]] || die "missing or empty $LOG_WORKER. Run ./scripts/demo_up.sh first."
[[ -s "$LOG_AGENT" ]] || die "missing or empty $LOG_AGENT. Run ./scripts/demo_up.sh first."
[[ -s "$LOG_DETECTOR" ]] || die "missing or empty $LOG_DETECTOR. Run ./scripts/demo_up.sh first."
[[ -s "$LOG_COLLECTOR" ]] || die "missing or empty $LOG_COLLECTOR. Run ./scripts/demo_up.sh first."
[[ -f "$DEMO_LOG" ]] || touch "$DEMO_LOG"

base_master="$(line_count "$LOG_MASTER")"
base_worker="$(line_count "$LOG_WORKER")"
base_agent="$(line_count "$LOG_AGENT")"
base_detector="$(line_count "$LOG_DETECTOR")"
base_collector="$(line_count "$LOG_COLLECTOR")"

NOW="$(date +%s)"
OCT=$(( (NOW % 180) + 20 ))
SRC_IP="10.0.0.${OCT}"
echo "FAILED login user=khotso src=${SRC_IP} ts=${NOW}" >> "$DEMO_LOG"

collector_line="$(wait_match_rg "$LOG_COLLECTOR" "$base_collector" "\"msg\":\"collector_event_published\".*\"src_ip\":\"${SRC_IP}\".*\"user\":\"khotso\"" 20 || true)"
[[ -n "$collector_line" ]] || die "collector_event_published not observed within 20s"

detector_line="$(wait_match_rg "$LOG_DETECTOR" "$base_detector" "\"msg\":\"detector_rule_matched\".*\"src_ip\":\"${SRC_IP}\".*\"user\":\"khotso\"" 30 || true)"
[[ -n "$detector_line" ]] || die "detector_rule_matched not observed for src_ip=${SRC_IP} user=khotso"

run_line="$(tail_from "$LOG_MASTER" "$base_master" | rg -F "\"msg\":\"response_run_created\"" | rg -F "\"rule_id\":\"R-COLLECT-INVALID-USER\"" | rg -F "\"playbook_id\":\"PB-AGENT-PING-LOCALHOST\"" | head -n 1 || true)"
if [[ -z "$run_line" ]]; then
  run_line="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"response_run_created\"" 20 || true)"
fi
if [[ -z "$run_line" ]]; then
  echo "Context: master (last 120 relevant):" >&2
  tail_from "$LOG_MASTER" "$base_master" | rg -F "\"rule_id\":\"R-COLLECT-INVALID-USER\"" | rg -F "\"playbook_id\":\"PB-AGENT-PING-LOCALHOST\"" | tail -n 120 >&2 || true
  die "response_run_created not observed within 20s"
fi
printf '%s\n' "$run_line" | rg -F "\"rule_id\":\"R-COLLECT-INVALID-USER\"" >/dev/null || die "response_run_created rule_id mismatch"
printf '%s\n' "$run_line" | rg -F "\"playbook_id\":\"PB-AGENT-PING-LOCALHOST\"" >/dev/null || die "response_run_created playbook mismatch"
RUN_ID="$(printf '%s\n' "$run_line" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"
[[ -n "$RUN_ID" ]] || die "unable to parse run_id"
echo "RUN_ID=$RUN_ID"

APPROVAL_CMD="nats pub rsiem.response.approvals \"{\\\"run_id\\\":\\\"$RUN_ID\\\",\\\"decision\\\":\\\"approve\\\",\\\"actor\\\":\\\"khotso\\\"}\""
echo "Running: $APPROVAL_CMD"
nats pub rsiem.response.approvals "{\"run_id\":\"$RUN_ID\",\"decision\":\"approve\",\"actor\":\"khotso\"}" >/dev/null

step_line="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"response_step_published\",\"run_id\":\"${RUN_ID}\"" 30 || true)"
[[ -n "$step_line" ]] || die "response_step_published not observed for run_id=$RUN_ID"
STEP_ID="$(printf '%s\n' "$step_line" | sed -n 's/.*"step_id":"\([^"]*\)".*/\1/p')"
[[ -n "$STEP_ID" ]] || die "unable to parse step_id"

worker_line="$(wait_match "$LOG_WORKER" "$base_worker" "\"msg\":\"step_received\",\"run_id\":\"${RUN_ID}\",\"step_id\":\"${STEP_ID}\"" 30 || true)"
[[ -n "$worker_line" ]] || die "step_received not observed for run_id=$RUN_ID step_id=$STEP_ID"

agent_line="$(wait_match "$LOG_AGENT" "$base_agent" "\"msg\":\"agent_command_exec_start\",\"run_id\":\"${RUN_ID}\",\"step_id\":\"${STEP_ID}\"" 30 || true)"
[[ -n "$agent_line" ]] || die "agent_command_exec_start not observed for run_id=$RUN_ID step_id=$STEP_ID"

success_line="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"response_step_result_received\",\"run_id\":\"${RUN_ID}\",\"step_id\":\"${STEP_ID}\",\"status\":\"SUCCEEDED\"" 60 || true)"
[[ -n "$success_line" ]] || die "response_step_result_received status=SUCCEEDED not observed for run_id=$RUN_ID step_id=$STEP_ID"

cat <<EOF
=== SUPERVISOR PROOF COMMANDS ===
RUN_ID="$RUN_ID"
STEP_ID="$STEP_ID"
SRC_IP="$SRC_IP"

rg '"msg":"collector_event_published".*"src_ip":"'"\$SRC_IP"'".*"user":"khotso"' logs/collector.log
rg '"msg":"detector_rule_matched".*"src_ip":"'"\$SRC_IP"'".*"user":"khotso"' logs/detector.log
rg '"msg":"response_run_created".*"run_id":"'"\$RUN_ID"'"' logs/master-roe.log
rg '"msg":"response_step_published".*"run_id":"'"\$RUN_ID"'".*"step_id":"'"\$STEP_ID"'"' logs/master-roe.log
rg '"msg":"step_received".*"run_id":"'"\$RUN_ID"'".*"step_id":"'"\$STEP_ID"'"' logs/worker.log
rg '"msg":"agent_command_exec_start".*"run_id":"'"\$RUN_ID"'".*"step_id":"'"\$STEP_ID"'"' logs/agent.log
rg '"msg":"response_step_result_received".*"run_id":"'"\$RUN_ID"'".*"step_id":"'"\$STEP_ID"'".*"status":"SUCCEEDED"' logs/master-roe.log
EOF

echo "PASS: demo vertical slice succeeded run_id=${RUN_ID} step_id=${STEP_ID} src_ip=${SRC_IP}"
