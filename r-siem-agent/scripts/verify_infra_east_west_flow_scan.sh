#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

LOG_COLLECTOR="logs/collector-netflowv5.log"
LOG_DETECTOR="logs/detector.log"
LOG_MASTER="logs/master-roe.log"
EXPORT_RUNS="exports/roe_runs.jsonl"
RULE_ID="R-INFRA-EAST-WEST-FLOW-SCAN"
PLAYBOOK_ID="PB-INFRA-EAST-WEST-FLOW-SCAN-NOTIFY"
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
PROOF_JSON="${ART_DIR}/infra_east_west_flow_scan_proof.json"

collector_pid=""
cleanup() {
  if [[ -n "$collector_pid" ]] && kill -0 "$collector_pid" 2>/dev/null; then
    kill "$collector_pid" >/dev/null 2>&1 || true
    wait "$collector_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT

./scripts/demo_down.sh >/dev/null 2>&1 || true
pkill -f '/collector-netflowv5 --config' >/dev/null 2>&1 || true
pkill -f '/detector-v0 --config' >/dev/null 2>&1 || true
pkill -f '/master-roe --config' >/dev/null 2>&1 || true
pkill -f '/master-roe-worker --config' >/dev/null 2>&1 || true
pkill -f '/agent --config' >/dev/null 2>&1 || true
pkill -f '/collector-tail --config' >/dev/null 2>&1 || true
sleep 1
./scripts/demo_up.sh >/dev/null

: > "$LOG_COLLECTOR"
GOCACHE="$ROOT_DIR/.cache/go-build" go run -mod=vendor ./cmd/collector-netflowv5 --config configs/collector-netflowv5.yaml >> "$LOG_COLLECTOR" 2>&1 &
collector_pid=$!
sleep 1
if ! kill -0 "$collector_pid" 2>/dev/null; then
  echo "FAIL: collector-netflowv5 failed to start" >&2
  tail -n 80 "$LOG_COLLECTOR" >&2 || true
  exit 1
fi

published_before="$(rg -c '"msg":"collector_event_published".*"collector":"netflow_v5"' "$LOG_COLLECTOR" || true)"
published_before="${published_before:-0}"
base_detector="$(line_count "$LOG_DETECTOR")"
base_master="$(line_count "$LOG_MASTER")"
base_runs="$(line_count "$EXPORT_RUNS")"

gen_file="$(mktemp -t infra_eastwest_netflow.XXXX.go)"
cat > "$gen_file" <<'GO'
package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"time"
)

const (
	headerLen = 24
	recordLen = 48
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <addr>\n", os.Args[0])
		os.Exit(2)
	}
	conn, err := net.Dial("udp", os.Args[1])
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	buf := make([]byte, headerLen+6*recordLen)
	sysUptime := uint32(700000)
	binary.BigEndian.PutUint16(buf[0:2], 5)
	binary.BigEndian.PutUint16(buf[2:4], 6)
	binary.BigEndian.PutUint32(buf[4:8], sysUptime)
	binary.BigEndian.PutUint32(buf[8:12], uint32(time.Now().Unix()))
	binary.BigEndian.PutUint32(buf[12:16], 1000000)
	binary.BigEndian.PutUint32(buf[16:20], 1)

	off := headerLen
	for i := 0; i < 6; i++ {
		src := net.IPv4(10, 44, 1, 10).To4()
		dst := net.IPv4(10, 44, 2, byte(10+i)).To4()
		copy(buf[off:off+4], src)
		copy(buf[off+4:off+8], dst)
		binary.BigEndian.PutUint32(buf[off+16:off+20], uint32(80+i))
		binary.BigEndian.PutUint32(buf[off+20:off+24], uint32(2048+i*32))
		binary.BigEndian.PutUint32(buf[off+24:off+28], sysUptime-1000)
		binary.BigEndian.PutUint32(buf[off+28:off+32], sysUptime-100)
		binary.BigEndian.PutUint16(buf[off+32:off+34], uint16(40000+i))
		binary.BigEndian.PutUint16(buf[off+34:off+36], 445)
		buf[off+38] = 6
		off += recordLen
	}
	if _, err := conn.Write(buf); err != nil {
		panic(err)
	}
}
GO
GOCACHE="$ROOT_DIR/.cache/go-build" go run "$gen_file" 127.0.0.1:2055
rm -f "$gen_file"

published_after="$published_before"
for _ in $(seq 1 40); do
  published_after="$(rg -c '"msg":"collector_event_published".*"collector":"netflow_v5"' "$LOG_COLLECTOR" || true)"
  published_after="${published_after:-0}"
  if (( published_after - published_before >= 6 )); then
    break
  fi
  sleep 0.5
done
published_delta=$(( published_after - published_before ))
if (( published_delta < 6 )); then
  fail_with_context "netflow collector published ${published_delta}, expected >= 6"
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
  "records_sent": 6,
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

echo "PASS: infrastructure east-west flow scan verified"
echo "INFRA_EAST_WEST_FLOW_SCAN_PROOF_JSON=${PROOF_JSON}"
