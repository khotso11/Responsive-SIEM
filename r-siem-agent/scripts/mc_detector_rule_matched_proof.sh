#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

LOG_COLLECTOR="logs/collector.log"
LOG_DETECTOR="logs/detector.log"
LOG_MASTER="logs/master-roe.log"
DEMO_LOG="tmp/demo.log"

die() {
  echo "FAIL: $1" >&2
  echo "Context: collector (last 80):" >&2
  [[ -f "$LOG_COLLECTOR" ]] && tail -n 80 "$LOG_COLLECTOR" >&2 || true
  echo "Context: detector (last 80):" >&2
  [[ -f "$LOG_DETECTOR" ]] && tail -n 80 "$LOG_DETECTOR" >&2 || true
  echo "Context: master (last 80):" >&2
  [[ -f "$LOG_MASTER" ]] && tail -n 80 "$LOG_MASTER" >&2 || true
  exit 1
}

command -v rg >/dev/null 2>&1 || die "mc proof requires rg"
mkdir -p logs tmp
[[ -f "$DEMO_LOG" ]] || touch "$DEMO_LOG"
[[ -s "$LOG_COLLECTOR" ]] || die "missing or empty $LOG_COLLECTOR (run ./scripts/demo_up.sh first)"
[[ -s "$LOG_DETECTOR" ]] || die "missing or empty $LOG_DETECTOR (run ./scripts/demo_up.sh first)"
[[ -s "$LOG_MASTER" ]] || die "missing or empty $LOG_MASTER (run ./scripts/demo_up.sh first)"

NOW="$(date +%s)"
echo "FAILED login user=khotso src=10.0.0.8 ts=${NOW}" >> "$DEMO_LOG"
sleep 2

collector_line="$(rg '"msg":"collector_event_published".*"src_ip":"10.0.0.8".*"user":"khotso"' "$LOG_COLLECTOR" | tail -n 1 || true)"
detector_line="$(rg '"msg":"detector_rule_matched".*"rule_id":"R-COLLECT-INVALID-USER".*"event_type":"auth_failed".*"src_ip":"10.0.0.8".*"user":"khotso"' "$LOG_DETECTOR" | tail -n 1 || true)"
master_line="$(rg '"msg":"response_run_created".*"rule_id":"R-COLLECT-INVALID-USER".*"playbook_id":"PB-AGENT-PING-LOCALHOST"' "$LOG_MASTER" | tail -n 1 || true)"

[[ -n "$collector_line" ]] || die "collector_event_published line not found"
[[ -n "$detector_line" ]] || die "detector_rule_matched line not found"
[[ -n "$master_line" ]] || die "response_run_created line not found"

echo "$collector_line"
echo "$detector_line"
echo "$master_line"
echo "PASS: MC detector rule matched proof"
exit 0
