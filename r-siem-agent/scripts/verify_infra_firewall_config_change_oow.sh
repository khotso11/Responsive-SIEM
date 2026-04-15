#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

LOG_COLLECTOR="logs/collector-syslog.log"
LOG_DETECTOR="logs/detector.log"
LOG_MASTER="logs/master-roe.log"
EXPORT_RUNS="exports/roe_runs.jsonl"
RULE_ID="R-INFRA-FIREWALL-CONFIG-CHANGE-OOW"
PLAYBOOK_ID="PB-INFRA-FIREWALL-CONFIG-CHANGE-OOW-NOTIFY"
EXPECTED_CONFIDENCE=86

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "FAIL: missing command: $1" >&2
    exit 1
  }
}

line_count() {
  local file="$1"
  [[ -f "$file" ]] || { echo 0; return; }
  wc -l < "$file" | tr -d '[:space:]'
}

tail_from() {
  local file="$1"
  local base="$2"
  tail -n "+$((base + 1))" "$file" 2>/dev/null || true
}

wait_match_rg() {
  local file="$1"
  local base="$2"
  local pattern="$3"
  local timeout="${4:-30}"
  local i=0
  while (( i < timeout * 5 )); do
    local line
    line="$(tail_from "$file" "$base" | rg "$pattern" | head -n 1 || true)"
    if [[ -n "$line" ]]; then
      printf '%s\n' "$line"
      return 0
    fi
    sleep 0.2
    i=$((i + 1))
  done
  return 1
}

fail_with_context() {
  local msg="$1"
  echo "FAIL: ${msg}" >&2
  tail -n 80 "$LOG_COLLECTOR" >&2 || true
  tail -n 80 "$LOG_DETECTOR" >&2 || true
  tail -n 80 "$LOG_MASTER" >&2 || true
  exit 1
}

need_cmd go
need_cmd rg

TS="$(date -u +%Y%m%d_%H%M%S)"
ART_DIR="demo_artifacts/${TS}"
mkdir -p "$ART_DIR" logs .pids .cache/go-build tmp exports
PROOF_JSON="${ART_DIR}/infra_firewall_config_change_oow_proof.json"

collector_pid=""
cleanup() {
  if [[ -n "$collector_pid" ]] && kill -0 "$collector_pid" 2>/dev/null; then
    kill "$collector_pid" >/dev/null 2>&1 || true
    wait "$collector_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT

./scripts/demo_down.sh >/dev/null 2>&1 || true
pkill -f '/collector-syslog --config' >/dev/null 2>&1 || true
pkill -f '/detector-v0 --config' >/dev/null 2>&1 || true
pkill -f '/master-roe --config' >/dev/null 2>&1 || true
pkill -f '/master-roe-worker --config' >/dev/null 2>&1 || true
pkill -f '/agent --config' >/dev/null 2>&1 || true
pkill -f '/collector-tail --config' >/dev/null 2>&1 || true
sleep 1
./scripts/demo_up.sh >/dev/null

: > "$LOG_COLLECTOR"
GOCACHE="$ROOT_DIR/.cache/go-build" go run -mod=vendor ./cmd/collector-syslog --config configs/collector-syslog.yaml >> "$LOG_COLLECTOR" 2>&1 &
collector_pid=$!
sleep 1
if ! kill -0 "$collector_pid" 2>/dev/null; then
  echo "FAIL: collector-syslog failed to start" >&2
  tail -n 80 "$LOG_COLLECTOR" >&2 || true
  exit 1
fi

published_before="$(rg -c '"msg":"collector_event_published".*"collector":"syslog"' "$LOG_COLLECTOR" || true)"
published_before="${published_before:-0}"
base_detector="$(line_count "$LOG_DETECTOR")"
base_master="$(line_count "$LOG_MASTER")"
base_runs="$(line_count "$EXPORT_RUNS")"

host_tag="edge-fw-change-$(date +%H%M%S)"
ts_ms="$(date +%s%3N)"
msg="<13>Apr 07 22:30:00 ${host_tag} firewall configuration committed acl updated by admin change_window=outside ts=${ts_ms}"
printf '%s\n' "$msg" > /dev/udp/127.0.0.1/5140

published_after="$published_before"
for _ in $(seq 1 20); do
  published_after="$(rg -c '"msg":"collector_event_published".*"collector":"syslog"' "$LOG_COLLECTOR" || true)"
  published_after="${published_after:-0}"
  if (( published_after - published_before >= 1 )); then
    break
  fi
  sleep 0.5
done
published_delta=$(( published_after - published_before ))
if (( published_delta < 1 )); then
  fail_with_context "syslog collector published ${published_delta}, expected >= 1"
fi

detector_line="$(wait_match_rg "$LOG_DETECTOR" "$base_detector" "\\\"msg\\\":\\\"detector_rule_matched\\\".*\\\"rule_id\\\":\\\"${RULE_ID}\\\"" 30 || true)"
[[ -n "$detector_line" ]] || fail_with_context "missing detector_rule_matched for ${RULE_ID}"
alert_line="$(wait_match_rg "$LOG_DETECTOR" "$base_detector" "\\\"msg\\\":\\\"detector_alert_published\\\".*\\\"rule_id\\\":\\\"${RULE_ID}\\\"" 30 || true)"
[[ -n "$alert_line" ]] || fail_with_context "missing detector_alert_published for ${RULE_ID}"
run_created_line="$(wait_match_rg "$LOG_MASTER" "$base_master" "\\\"msg\\\":\\\"response_run_created\\\".*\\\"rule_id\\\":\\\"${RULE_ID}\\\".*\\\"playbook_id\\\":\\\"${PLAYBOOK_ID}\\\"" 40 || true)"
[[ -n "$run_created_line" ]] || fail_with_context "missing response_run_created for ${PLAYBOOK_ID}"
run_id="$(printf '%s\n' "$run_created_line" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p' | head -n 1)"
[[ -n "$run_id" ]] || fail_with_context "failed to parse run_id"
approval_line="$(wait_match_rg "$LOG_MASTER" "$base_master" "\\\"msg\\\":\\\"approval_policy_evaluated\\\".*\\\"run_id\\\":\\\"${run_id}\\\".*\\\"confidence_score\\\":${EXPECTED_CONFIDENCE}.*\\\"approval_required\\\":false" 40 || true)"
[[ -n "$approval_line" ]] || fail_with_context "missing approval policy line for ${run_id}"
run_updated_line="$(wait_match_rg "$LOG_MASTER" "$base_master" "\\\"msg\\\":\\\"response_run_updated\\\".*\\\"run_id\\\":\\\"${run_id}\\\".*\\\"status\\\":\\\"SUCCEEDED\\\"" 40 || true)"
[[ -n "$run_updated_line" ]] || fail_with_context "missing terminal response_run_updated for ${run_id}"
export_line="$(tail_from "$EXPORT_RUNS" "$base_runs" | rg "\"run_id\":\"${run_id}\".*\"status\":\"SUCCEEDED\"" | tail -n 1 || true)"
[[ -n "$export_line" ]] || fail_with_context "missing export run line for ${run_id}"

printf '%s\n' "$detector_line" > "${ART_DIR}/detector_rule_matched.log"
printf '%s\n' "$alert_line" > "${ART_DIR}/detector_alert_published.log"
printf '%s\n' "$run_created_line" > "${ART_DIR}/response_run_created.log"
printf '%s\n' "$approval_line" > "${ART_DIR}/approval_policy_evaluated.log"
printf '%s\n' "$run_updated_line" > "${ART_DIR}/response_run_updated.log"
printf '%s\n' "$export_line" > "${ART_DIR}/roe_runs_export.log"

cat > "$PROOF_JSON" <<JSON
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "rule_id": "${RULE_ID}",
  "playbook_id": "${PLAYBOOK_ID}",
  "source_host": "${host_tag}",
  "count_sent": 1,
  "count_published": ${published_delta},
  "run_id": "${run_id}",
  "confidence_score": ${EXPECTED_CONFIDENCE},
  "evidence": {
    "detector_rule_matched": "${ART_DIR}/detector_rule_matched.log",
    "detector_alert_published": "${ART_DIR}/detector_alert_published.log",
    "response_run_created": "${ART_DIR}/response_run_created.log",
    "approval_policy_evaluated": "${ART_DIR}/approval_policy_evaluated.log",
    "response_run_updated": "${ART_DIR}/response_run_updated.log",
    "roe_runs_export": "${ART_DIR}/roe_runs_export.log"
  },
  "pass": true
}
JSON

echo "PASS: infrastructure firewall config change outside window verified"
echo "INFRA_FIREWALL_CONFIG_CHANGE_OOW_PROOF_JSON=${PROOF_JSON}"
