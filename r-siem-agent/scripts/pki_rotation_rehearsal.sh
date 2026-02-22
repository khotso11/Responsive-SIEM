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

cert_fp_or_empty() {
  local cert_path="$1"
  if [[ ! -f "$cert_path" ]]; then
    echo ""
    return 0
  fi
  openssl x509 -in "$cert_path" -noout -fingerprint -sha256 \
    | sed 's/^.*=//' \
    | tr -d ':' \
    | tr 'A-F' 'a-f'
}

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

json_or_null() {
  local value="${1:-}"
  if [[ -z "$value" ]]; then
    printf 'null'
  else
    printf '"%s"' "$(json_escape "$value")"
  fi
}

promote_next_to_current() {
  local component_dir="$1"
  local next_dir="${component_dir}/next"
  local stage_dir="${component_dir}/.current.new.$$"
  local current_dir="${component_dir}/current"
  local old_dir="${component_dir}/.current.old.$$"
  if [[ ! -d "$next_dir" ]]; then
    echo "FAIL: missing next slot: ${next_dir}" >&2
    exit 1
  fi
  rm -rf "$stage_dir"
  cp -a "$next_dir" "$stage_dir"
  rm -rf "$old_dir"
  if [[ -d "$current_dir" ]]; then
    mv "$current_dir" "$old_dir"
  fi
  mv "$stage_dir" "$current_dir"
  rm -rf "$old_dir"
}

need_cmd openssl
need_cmd rg

PKI_ROOT="${PKI_ROOT:-tmp/pki/fr02}"
AGENT_ID="${AGENT_ID:-agent.local}"
timestamp="$(date +%Y%m%d_%H%M%S)"
artifact_dir="demo_artifacts/${timestamp}"
proof_json="${artifact_dir}/fr02_rotation_proof.json"
verify_log="${artifact_dir}/verify_fr02_mtls.out"

mkdir -p "$artifact_dir"

old_server_fp="$(cert_fp_or_empty "configs/certs/master.pem")"
old_client_fp="$(cert_fp_or_empty "configs/certs/agent.pem")"

./scripts/pki_init_ca.sh >/dev/null

if [[ ! -f "${PKI_ROOT}/master/current/master.pem" || ! -f "${PKI_ROOT}/master/current/master-key.pem" ]]; then
  SLOT=current FORCE=1 ./scripts/pki_issue_master_cert.sh >/dev/null
fi
if [[ ! -f "${PKI_ROOT}/agents/${AGENT_ID}/current/agent.pem" || ! -f "${PKI_ROOT}/agents/${AGENT_ID}/current/agent-key.pem" ]]; then
  SLOT=current FORCE=1 ./scripts/pki_issue_agent_cert.sh "$AGENT_ID" >/dev/null
fi

SLOT=next FORCE=1 ./scripts/pki_issue_master_cert.sh >/dev/null
SLOT=next FORCE=1 ./scripts/pki_issue_agent_cert.sh "$AGENT_ID" >/dev/null

promote_next_to_current "${PKI_ROOT}/master"
promote_next_to_current "${PKI_ROOT}/agents/${AGENT_ID}"

cp "${PKI_ROOT}/ca/ca.pem" configs/certs/ca.pem
cp "${PKI_ROOT}/ca/ca-key.pem" configs/certs/ca-key.pem
cp "${PKI_ROOT}/master/current/master.pem" configs/certs/master.pem
cp "${PKI_ROOT}/master/current/master-key.pem" configs/certs/master-key.pem
cp "${PKI_ROOT}/agents/${AGENT_ID}/current/agent.pem" configs/certs/agent.pem
cp "${PKI_ROOT}/agents/${AGENT_ID}/current/agent-key.pem" configs/certs/agent-key.pem
chmod 600 configs/certs/ca-key.pem configs/certs/master-key.pem configs/certs/agent-key.pem
chmod 644 configs/certs/ca.pem configs/certs/master.pem configs/certs/agent.pem

new_server_fp="$(cert_fp_or_empty "configs/certs/master.pem")"
new_client_fp="$(cert_fp_or_empty "configs/certs/agent.pem")"

# Rehearsal uses the existing demo lifecycle scripts.
./scripts/demo_down.sh >/dev/null 2>&1 || true
./scripts/demo_up.sh >/dev/null

verify_rc=0
if ./scripts/verify_fr02_mtls.sh >"$verify_log" 2>&1; then
  verify_rc=0
else
  verify_rc=$?
fi

verifier_pass_line="$(rg '^fr02_status=PASS$' "$verify_log" | tail -n 1 || true)"
verify_proof_log="$(sed -n 's/^proof_log=//p' "$verify_log" | tail -n 1 || true)"

generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
host_val="$(hostname)"
status="FAIL"
if [[ "$verify_rc" -eq 0 && -n "$verifier_pass_line" ]]; then
  status="PASS"
fi

cat > "$proof_json" <<EOF_JSON
{
  "generated_at": "${generated_at}",
  "hostname": "$(json_escape "$host_val")",
  "status": "${status}",
  "agent_id": "$(json_escape "$AGENT_ID")",
  "old_server_fingerprint_sha256": $(json_or_null "$old_server_fp"),
  "new_server_fingerprint_sha256": $(json_or_null "$new_server_fp"),
  "old_client_fingerprint_sha256": $(json_or_null "$old_client_fp"),
  "new_client_fingerprint_sha256": $(json_or_null "$new_client_fp"),
  "verify_fr02_log": "$(json_escape "$verify_log")",
  "verify_fr02_proof_log": $(json_or_null "$verify_proof_log"),
  "verify_pass_line": $(json_or_null "$verifier_pass_line")
}
EOF_JSON

echo "FR02_ROTATION_PROOF_JSON: ${proof_json}"

if [[ "$status" != "PASS" ]]; then
  echo "FAIL: FR-02 rotation rehearsal verification failed" >&2
  echo "Context: tail -n 120 ${verify_log}" >&2
  tail -n 120 "$verify_log" >&2 || true
  exit 1
fi

echo "PASS: FR-02 ROTATION REHEARSAL"
