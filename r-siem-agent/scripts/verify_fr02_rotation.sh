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

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

cert_fp() {
  local cert_path="$1"
  openssl x509 -in "$cert_path" -noout -fingerprint -sha256 \
    | sed 's/^.*=//' \
    | tr -d ':' \
    | tr 'A-F' 'a-f'
}

fail_with_context() {
  local msg="$1"
  local file="${2:-}"
  echo "FAIL: ${msg}" >&2
  if [[ -n "$file" && -f "$file" ]]; then
    echo "Context: tail -n 80 ${file}" >&2
    tail -n 80 "$file" >&2 || true
  fi
  exit 1
}

promote_next_to_current() {
  local component_dir="$1"
  local next_dir="${component_dir}/next"
  local current_dir="${component_dir}/current"
  local stage_dir="${component_dir}/.current.new.$$"
  local old_dir="${component_dir}/.current.old.$$"

  [[ -d "$next_dir" ]] || fail_with_context "missing next slot at ${next_dir}"

  rm -rf "$stage_dir" "$old_dir"
  cp -a "$next_dir" "$stage_dir"
  if [[ -d "$current_dir" ]]; then
    mv "$current_dir" "$old_dir"
  fi
  mv "$stage_dir" "$current_dir"
  rm -rf "$old_dir"
}

sync_current_to_configs() {
  local ca_crt="${PKI_ROOT}/ca/ca.crt"
  local ca_key="${PKI_ROOT}/ca/ca.key"
  local master_crt="${PKI_ROOT}/master/current/server.crt"
  local master_key="${PKI_ROOT}/master/current/server.key"
  local agent_crt="${PKI_ROOT}/agents/${AGENT_ID}/current/client.crt"
  local agent_key="${PKI_ROOT}/agents/${AGENT_ID}/current/client.key"

  [[ -f "$ca_crt" ]] || fail_with_context "missing file ${ca_crt}"
  [[ -f "$ca_key" ]] || fail_with_context "missing file ${ca_key}"
  [[ -f "$master_crt" ]] || fail_with_context "missing file ${master_crt}"
  [[ -f "$master_key" ]] || fail_with_context "missing file ${master_key}"
  [[ -f "$agent_crt" ]] || fail_with_context "missing file ${agent_crt}"
  [[ -f "$agent_key" ]] || fail_with_context "missing file ${agent_key}"

  cp "$ca_crt" configs/certs/ca.pem
  cp "$ca_key" configs/certs/ca-key.pem
  cp "$master_crt" configs/certs/master.pem
  cp "$master_key" configs/certs/master-key.pem
  cp "$agent_crt" configs/certs/agent.pem
  cp "$agent_key" configs/certs/agent-key.pem
  chmod 644 configs/certs/ca.pem configs/certs/master.pem configs/certs/agent.pem
  chmod 600 configs/certs/ca-key.pem configs/certs/master-key.pem configs/certs/agent-key.pem
}

run_verify() {
  local stage="$1"
  local out_file="$2"
  local rc=0

  if ./scripts/verify_fr02_mtls.sh >"$out_file" 2>&1; then
    rc=0
  else
    rc=$?
  fi

  if [[ "$rc" -ne 0 ]]; then
    fail_with_context "verify_fr02_mtls.sh failed during ${stage}" "$out_file"
  fi

  if ! rg -q '^fr02_status=PASS$' "$out_file"; then
    fail_with_context "fr02_status was not PASS during ${stage}" "$out_file"
  fi
}

need_cmd openssl
need_cmd rg

PKI_ROOT="${PKI_ROOT:-pki}"
AGENT_ID="${AGENT_ID:-agent.local}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
ARTIFACT_DIR="demo_artifacts/${TIMESTAMP}"
PROOF_JSON="${ARTIFACT_DIR}/fr02_rotation_proof.json"
VERIFY_BEFORE_LOG="${ARTIFACT_DIR}/verify_fr02_before.out"
VERIFY_AFTER_LOG="${ARTIFACT_DIR}/verify_fr02_after.out"

mkdir -p "$ARTIFACT_DIR"

./scripts/pki_init_ca.sh >/dev/null

if [[ ! -f "${PKI_ROOT}/master/current/server.crt" || ! -f "${PKI_ROOT}/master/current/server.key" ]]; then
  TARGET=current FORCE=1 ./scripts/pki_issue_master_cert.sh >/dev/null
fi
if [[ ! -f "${PKI_ROOT}/agents/${AGENT_ID}/current/client.crt" || ! -f "${PKI_ROOT}/agents/${AGENT_ID}/current/client.key" ]]; then
  TARGET=current FORCE=1 ./scripts/pki_issue_agent_cert.sh "$AGENT_ID" >/dev/null
fi

sync_current_to_configs

before_master_fp="$(cert_fp "${PKI_ROOT}/master/current/server.crt")"
before_agent_fp="$(cert_fp "${PKI_ROOT}/agents/${AGENT_ID}/current/client.crt")"

./scripts/demo_down.sh >/dev/null 2>&1 || true
./scripts/demo_up.sh >/dev/null
run_verify "baseline_before_rotation" "$VERIFY_BEFORE_LOG"

TARGET=next FORCE=1 ./scripts/pki_issue_master_cert.sh >/dev/null
TARGET=next FORCE=1 ./scripts/pki_issue_agent_cert.sh "$AGENT_ID" >/dev/null

promote_next_to_current "${PKI_ROOT}/master"
promote_next_to_current "${PKI_ROOT}/agents/${AGENT_ID}"
sync_current_to_configs

after_master_fp="$(cert_fp "${PKI_ROOT}/master/current/server.crt")"
after_agent_fp="$(cert_fp "${PKI_ROOT}/agents/${AGENT_ID}/current/client.crt")"

if [[ "$before_master_fp" == "$after_master_fp" || "$before_agent_fp" == "$after_agent_fp" ]]; then
  fail_with_context "rotation did not change certificate fingerprints"
fi

./scripts/demo_down.sh >/dev/null 2>&1 || true
./scripts/demo_up.sh >/dev/null
run_verify "after_rotation" "$VERIFY_AFTER_LOG"

agent_id_source_after="$(sed -n 's/^agent_id_source=//p' "$VERIFY_AFTER_LOG" | tail -n 1 || true)"
if [[ "$agent_id_source_after" != "cert_cn" ]]; then
  fail_with_context "agent_id_source expected cert_cn but got ${agent_id_source_after}" "$VERIFY_AFTER_LOG"
fi

generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
cat > "$PROOF_JSON" <<EOF_JSON
{
  "timestamp": "$(json_escape "$generated_at")",
  "agent_id": "$(json_escape "$AGENT_ID")",
  "before": {
    "master_fp_sha256": "$(json_escape "$before_master_fp")",
    "agent_fp_sha256": "$(json_escape "$before_agent_fp")"
  },
  "after": {
    "master_fp_sha256": "$(json_escape "$after_master_fp")",
    "agent_fp_sha256": "$(json_escape "$after_agent_fp")"
  },
  "verifier_before": "PASS",
  "verifier_after": "PASS",
  "agent_id_source": "cert_cn",
  "verify_before_log": "$(json_escape "$VERIFY_BEFORE_LOG")",
  "verify_after_log": "$(json_escape "$VERIFY_AFTER_LOG")"
}
EOF_JSON

echo "PASS: FR-02 ROTATION REHEARSAL completed"
echo "FR02_ROTATION_PROOF_JSON=${PROOF_JSON}"
