#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

fail() {
  echo "FAIL: $1" >&2
  local file="${2:-}"
  if [[ -n "$file" && -f "$file" ]]; then
    echo "Context: tail -n 80 ${file}" >&2
    tail -n 80 "$file" >&2 || true
  fi
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

pick_port() {
  local port
  for port in $(seq 18100 18110); do
    if ! ss -ltn | awk '{print $4}' | rg -q "(^|:)${port}$"; then
      echo "$port"
      return 0
    fi
  done
  return 1
}

require_cmd go
require_cmd curl
require_cmd rg
require_cmd ss
require_cmd python3

timestamp="$(date +%Y%m%d_%H%M%S)"
artifacts_dir="demo_artifacts/${timestamp}/honeypot_burst"
mkdir -p "${artifacts_dir}"

honeypot_bin="${artifacts_dir}/honeypot"
honeypot_cfg="${artifacts_dir}/honeypot.yaml"
honeypot_log="${artifacts_dir}/honeypot.log"
proof_json="${artifacts_dir}/proof.json"
HONEYPOT_PID=""

cleanup() {
  if [[ -n "${HONEYPOT_PID}" ]] && kill -0 "${HONEYPOT_PID}" >/dev/null 2>&1; then
    kill "${HONEYPOT_PID}" >/dev/null 2>&1 || true
    wait "${HONEYPOT_PID}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

./scripts/demo_down.sh >/dev/null 2>&1 || true
./scripts/demo_up.sh >/dev/null

[[ -f logs/detector.log ]] || fail "logs/detector.log not found after demo_up"
[[ -f logs/master-roe.log ]] || fail "logs/master-roe.log not found after demo_up"
base_detector_lines="$(wc -l < logs/detector.log | tr -d '[:space:]')"
base_master_lines="$(wc -l < logs/master-roe.log | tr -d '[:space:]')"

port="$(pick_port || true)"
[[ -n "${port}" ]] || fail "no free deterministic localhost port in range 18100-18110"

env GOCACHE="$ROOT_DIR/.cache/go-build" go build -mod=vendor -o "${honeypot_bin}" ./cmd/honeypot

cat > "${honeypot_cfg}" <<EOF_HONEYPOT
log_level: info
node_id: honeypot-local
host: honeypot-local
response_target_agent_id: $(hostname)
jetstream:
  url: nats://127.0.0.1:4222
  stream: RSIEM_EVENTS
  subject: rsiem.events.raw
  spool_path: ${artifacts_dir}/honeypot.spool.jsonl
  spool_fsync: false
  retry_interval_ms: 1000
limits:
  read_timeout_ms: 2500
  write_timeout_ms: 2500
  max_payload_bytes: 2048
  max_concurrent: 16
services:
  - id: decoy-admin-http
    enabled: true
    protocol: http
    listen: 127.0.0.1:${port}
    http_title: Restricted Administration Portal
    realm: Operations Console
EOF_HONEYPOT

"${honeypot_bin}" -config "${honeypot_cfg}" >"${honeypot_log}" 2>&1 &
HONEYPOT_PID="$!"
sleep 1
kill -0 "${HONEYPOT_PID}" >/dev/null 2>&1 || fail "honeypot failed to start" "${honeypot_log}"

for _ in $(seq 1 20); do
  if rg -n "honeypot_service_listening.*decoy-admin-http" "${honeypot_log}" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done
rg -n "honeypot_service_listening.*decoy-admin-http" "${honeypot_log}" >/dev/null 2>&1 || fail "honeypot listen evidence not found" "${honeypot_log}"

src_ip="10.66.12.251"
for idx in 1 2 3; do
  curl -sS -o /dev/null \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -H "X-RSIEM-Source-IP: ${src_ip}" \
    --data "username=honeypot-admin&password=wrong-${idx}" \
    "http://127.0.0.1:${port}/admin/login?probe=burst-${idx}" || fail "curl probe ${idx} failed" "${honeypot_log}"
  sleep 0.3
done

detector_line=""
for _ in $(seq 1 40); do
  detector_line="$(tail -n "+$((base_detector_lines + 1))" logs/detector.log 2>/dev/null | rg "\"msg\":\"detector_rule_matched\".*\"rule_id\":\"R-DECEPTION-HONEYPOT-PROBE-BURST-SRCIP\"" | tail -n 1 || true)"
  if [[ -n "${detector_line}" ]]; then
    break
  fi
  sleep 0.25
done
[[ -n "${detector_line}" ]] || fail "honeypot burst escalation evidence not found" "logs/detector.log"

run_line=""
for _ in $(seq 1 40); do
  run_line="$(tail -n "+$((base_master_lines + 1))" logs/master-roe.log 2>/dev/null | rg "\"msg\":\"response_run_created\".*\"rule_id\":\"R-DECEPTION-HONEYPOT-PROBE-BURST-SRCIP\".*\"playbook_id\":\"PB-DECEPTION-HONEYPOT-SOURCE-CONTAIN\"" | tail -n 1 || true)"
  if [[ -n "${run_line}" ]]; then
    break
  fi
  sleep 0.25
done
[[ -n "${run_line}" ]] || fail "honeypot burst response run evidence not found" "logs/master-roe.log"

cat > "${proof_json}" <<EOF_PROOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "source_ip": "${src_ip}",
  "rule_id": "R-DECEPTION-HONEYPOT-PROBE-BURST-SRCIP",
  "playbook_id": "PB-DECEPTION-HONEYPOT-SOURCE-CONTAIN",
  "detector_evidence_line": $(printf '%s' "${detector_line}" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'),
  "run_evidence_line": $(printf '%s' "${run_line}" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'),
  "pass": true
}
EOF_PROOF

echo "PASS: honeypot repeated-source escalation completed"
echo "HONEYPOT_BURST_PROOF_JSON=${proof_json}"
