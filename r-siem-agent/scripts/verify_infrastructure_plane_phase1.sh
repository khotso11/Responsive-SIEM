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
need_cmd tee

SYSLOG_OUT="/tmp/verify_infrastructure_syslog.out"
NETFLOW_OUT="/tmp/verify_infrastructure_netflowv5.out"
SNMP_OUT="/tmp/verify_infrastructure_snmptrap.out"

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

./scripts/verify_fr01_snmptrap.sh | tee "$SNMP_OUT"
snmp_json="$(rg '^FR01_SNMPTRAP_PROOF_JSON=' "$SNMP_OUT" | tail -n 1 | sed -n 's/^FR01_SNMPTRAP_PROOF_JSON=//p')"
if [[ -z "$snmp_json" || ! -f "$snmp_json" ]]; then
  echo "FAIL: missing snmptrap proof json" >&2
  exit 1
fi

syslog_pass="$(jq -r '.pass // false' "$syslog_json" 2>/dev/null || echo false)"
netflow_pass="$(jq -r '.pass // false' "$netflow_json" 2>/dev/null || echo false)"
snmp_pass="$(jq -r '.pass // false' "$snmp_json" 2>/dev/null || echo false)"

if [[ "$syslog_pass" != "true" && "$syslog_pass" != "false" ]]; then
  syslog_pass=false
fi
if [[ "$netflow_pass" != "true" && "$netflow_pass" != "false" ]]; then
  netflow_pass=false
fi
if [[ "$snmp_pass" != "true" && "$snmp_pass" != "false" ]]; then
  snmp_pass=false
fi

wrapper_pass=false
if [[ "$syslog_pass" == "true" && "$netflow_pass" == "true" && "$snmp_pass" == "true" ]]; then
  wrapper_pass=true
fi

TS="$(date -u +%Y%m%d_%H%M%S)"
RFC3339="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ART_DIR="demo_artifacts/${TS}"
mkdir -p "$ART_DIR"
PROOF_JSON="${ART_DIR}/infrastructure_plane_phase1_proof.json"

cat > "$PROOF_JSON" <<JSON
{
  "timestamp": "${RFC3339}",
  "phase": "infrastructure_plane_phase1",
  "collectors": {
    "syslog": { "proof_json": "${syslog_json}", "pass": ${syslog_pass} },
    "netflow_v5": { "proof_json": "${netflow_json}", "pass": ${netflow_pass} },
    "snmp_trap": { "proof_json": "${snmp_json}", "pass": ${snmp_pass} }
  },
  "lab_spec": "configs/labs/emulated_infrastructure_lab.yaml",
  "deployment_doc": "docs/deploy/emulated_infrastructure_lab.md",
  "pass": ${wrapper_pass}
}
JSON

if [[ "$wrapper_pass" != "true" ]]; then
  echo "FAIL: infrastructure plane phase1 component proof indicates failure" >&2
  exit 1
fi

echo "PASS: infrastructure plane phase1 completed"
echo "INFRASTRUCTURE_PLANE_PHASE1_PROOF_JSON=${PROOF_JSON}"
