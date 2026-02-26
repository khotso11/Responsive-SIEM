#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "FAIL: missing command: $1" >&2
    exit 1
  }
}

need_cmd rg
need_cmd jq

SYSLOG_OUT="/tmp/verify_fr01_syslog.out"
NETFLOW_OUT="/tmp/verify_fr01_netflowv5.out"

./scripts/verify_fr01_syslog.sh | tee "$SYSLOG_OUT"
syslog_json="$(rg '^FR01_SYSLOG_PROOF_JSON=' "$SYSLOG_OUT" | tail -n 1 | sed -n 's/^FR01_SYSLOG_PROOF_JSON=//p')"
if [[ -z "$syslog_json" || ! -f "$syslog_json" ]]; then
  echo "FAIL: missing syslog proof json" >&2
  exit 1
fi

./scripts/verify_fr01_netflowv5.sh | tee "$NETFLOW_OUT"
netflow_json="$(rg '^FR01_NETFLOWV5_PROOF_JSON=' "$NETFLOW_OUT" | tail -n 1 | sed -n 's/^FR01_NETFLOWV5_PROOF_JSON=//p')"
if [[ -z "$netflow_json" || ! -f "$netflow_json" ]]; then
  echo "FAIL: missing netflowv5 proof json" >&2
  exit 1
fi

syslog_pass="$(jq -r '.pass // false' "$syslog_json" 2>/dev/null || echo false)"
netflow_pass="$(jq -r '.pass // false' "$netflow_json" 2>/dev/null || echo false)"
syslog_bind="$(jq -r '.bind // ""' "$syslog_json" 2>/dev/null || echo "")"
netflow_bind="$(jq -r '.bind // ""' "$netflow_json" 2>/dev/null || echo "")"

if [[ "$syslog_pass" != "true" && "$syslog_pass" != "false" ]]; then
  syslog_pass=false
fi
if [[ "$netflow_pass" != "true" && "$netflow_pass" != "false" ]]; then
  netflow_pass=false
fi

wrapper_pass=false
if [[ "$syslog_pass" == "true" && "$netflow_pass" == "true" ]]; then
  wrapper_pass=true
fi

TS="$(date -u +%Y%m%d_%H%M%S)"
RFC3339="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ART_DIR="demo_artifacts/${TS}"
mkdir -p "$ART_DIR"
PROOF_JSON="${ART_DIR}/fr01_streaming_phase1_proof.json"

cat > "$PROOF_JSON" <<JSON
{
  "timestamp": "${RFC3339}",
  "phase": "fr01_streaming_phase1",
  "components": {
    "syslog": { "proof_json": "${syslog_json}", "pass": ${syslog_pass}, "bind": "${syslog_bind}" },
    "netflowv5": { "proof_json": "${netflow_json}", "pass": ${netflow_pass}, "bind": "${netflow_bind}" }
  },
  "pass": ${wrapper_pass}
}
JSON

if [[ "$wrapper_pass" != "true" ]]; then
  echo "FAIL: FR-01 streaming phase1 component proof indicates failure" >&2
  exit 1
fi

echo "PASS: FR-01 streaming phase1 completed"
echo "FR01_STREAMING_PHASE1_PROOF_JSON=${PROOF_JSON}"
