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

normalize_fp() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -d ':\r\n\t '
}

cert_fp() {
  local cert_path="$1"
  openssl x509 -in "$cert_path" -noout -fingerprint -sha256 \
    | sed 's/^.*=//' \
    | tr -d ':' \
    | tr 'A-F' 'a-f'
}

find_free_port() {
  local start="${1:-27990}"
  local p
  for ((p=start; p<start+200; p++)); do
    if command -v ss >/dev/null 2>&1; then
      if ! ss -ltn 2>/dev/null | rg -q "[:.]${p}([[:space:]]|$)"; then
        echo "$p"
        return 0
      fi
    else
      if ! timeout 1 bash -c "</dev/tcp/127.0.0.1/${p}" >/dev/null 2>&1; then
        echo "$p"
        return 0
      fi
    fi
  done
  return 1
}

line_count() {
  local file="$1"
  [[ -f "$file" ]] || { echo 0; return; }
  wc -l < "$file" | tr -d '[:space:]'
}

wait_new_log() {
  local file="$1"
  local base="$2"
  local pattern="$3"
  local timeout="${4:-15}"
  local sleep_s="${5:-0.2}"
  local i=0
  local max_iters
  max_iters="$(awk -v t="$timeout" -v s="$sleep_s" 'BEGIN{ if (s <= 0) s=0.2; print int(t/s) }')"
  if [[ -z "$max_iters" || "$max_iters" -lt 1 ]]; then
    max_iters=1
  fi
  while (( i < max_iters )); do
    local line
    line="$(tail -n "+$((base + 1))" "$file" 2>/dev/null | rg "$pattern" | head -n 1 || true)"
    if [[ -n "$line" ]]; then
      printf '%s\n' "$line"
      return 0
    fi
    sleep "$sleep_s"
    i=$((i + 1))
  done
  return 1
}

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
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

write_master_cfg() {
  cat > "$MASTER_CFG" <<EOF_MASTER
log_level: INFO
listen_addr: 127.0.0.1:${PORT}
transport:
  mode: grpc_mtls
  tls:
    ca: configs/certs/ca.pem
    cert: configs/certs/master.pem
    key: configs/certs/master-key.pem
    client_identity: "agent.local"
    client_identity_source: "cert_only"
    client_fingerprint_allowlist_path: "${ALLOWLIST_PATH}"
  server_name: master.local
jetstream:
  url: nats://127.0.0.1:4222
  stream: RSIEM
  subject_fast: rsiem.fast
  subject_standard: rsiem.standard
  durable_name_fast: master-fast
  durable_name_standard: master-standard
consumer:
  fast_workers: 1
  standard_workers: 1
  pull_batch: 10
  pull_timeout_ms: 500
ack_delay_ms: 0
ack_drop_rate: 0.0
EOF_MASTER
}

start_master() {
  : > "$MASTER_LOG"
  "$MASTER_BIN" --config "$MASTER_CFG" >"$MASTER_LOG" 2>&1 &
  master_pid=$!
  for _ in $(seq 1 150); do
    if ! kill -0 "$master_pid" 2>/dev/null; then
      break
    fi
    if rg -q '"msg":"grpc_mtls_server_started"' "$MASTER_LOG"; then
      return 0
    fi
    sleep 0.2
  done
  fail_with_context "master did not start for revocation test" "$MASTER_LOG"
}

stop_master() {
  if [[ -n "${master_pid:-}" ]] && kill -0 "$master_pid" 2>/dev/null; then
    kill "$master_pid" 2>/dev/null || true
    wait "$master_pid" 2>/dev/null || true
  fi
  master_pid=""
}

need_cmd openssl
need_cmd rg
need_cmd go

PKI_ROOT="${PKI_ROOT:-pki}"
AGENT_ID="${AGENT_ID:-agent.local}"
ALLOWLIST_PATH="${ALLOWLIST_PATH:-${PKI_ROOT}/allowlist_fingerprints.txt}"
TMP_DIR="tmp/fr02_mtls"
MASTER_CFG="${TMP_DIR}/revocation_master.yaml"
MASTER_BIN="${TMP_DIR}/master.bin"

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
ARTIFACT_DIR="demo_artifacts/${TIMESTAMP}"
MASTER_LOG="${ARTIFACT_DIR}/fr02.revocation.master.log"
VERIFY_REJECT_LOG="${ARTIFACT_DIR}/verify_fr02_reject.out"
VERIFY_REALLOW_LOG="${ARTIFACT_DIR}/verify_fr02_reallow.out"
PROOF_JSON="${ARTIFACT_DIR}/fr02_revocation_proof.json"

mkdir -p "$TMP_DIR" "$ARTIFACT_DIR"

master_pid=""
cleanup() {
  stop_master || true
}
trap cleanup EXIT

./scripts/demo_down.sh >/dev/null 2>&1 || true
./scripts/demo_up.sh >/dev/null

./scripts/pki_init_ca.sh >/dev/null
if [[ ! -f "${PKI_ROOT}/master/current/server.crt" || ! -f "${PKI_ROOT}/master/current/server.key" ]]; then
  TARGET=current FORCE=1 ./scripts/pki_issue_master_cert.sh >/dev/null
fi
if [[ ! -f "${PKI_ROOT}/agents/${AGENT_ID}/current/client.crt" || ! -f "${PKI_ROOT}/agents/${AGENT_ID}/current/client.key" ]]; then
  TARGET=current FORCE=1 ./scripts/pki_issue_agent_cert.sh "$AGENT_ID" >/dev/null
fi
sync_current_to_configs

REVOKED_FP="$(cert_fp "${PKI_ROOT}/agents/${AGENT_ID}/current/client.crt")"
if [[ ! "$REVOKED_FP" =~ ^[0-9a-f]{64}$ ]]; then
  fail_with_context "invalid revoked fingerprint derived from client cert"
fi

DENY_FP="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
if [[ "$DENY_FP" == "$REVOKED_FP" ]]; then
  DENY_FP="0000000000000000000000000000000000000000000000000000000000000000"
fi

./scripts/pki_allowlist_remove_fingerprint.sh "$REVOKED_FP" >/dev/null
./scripts/pki_allowlist_add_fingerprint.sh "$DENY_FP" >/dev/null

if [[ -n "${FR02_MTLS_PORT:-}" ]]; then
  PORT="${FR02_MTLS_PORT}"
else
  PORT="$(find_free_port 27990)" || fail_with_context "unable to find free port for revocation test"
fi

write_master_cfg
GOCACHE="$(pwd)/.cache/go-build" go build -mod=vendor -o "$MASTER_BIN" ./cmd/master
start_master

base_lines="$(line_count "$MASTER_LOG")"
openssl s_client -connect "127.0.0.1:${PORT}" -servername master.local \
  -CAfile configs/certs/ca.pem \
  -cert configs/certs/agent.pem \
  -key configs/certs/agent-key.pem </dev/null >/dev/null 2>&1 || true

reject_line="$(wait_new_log "$MASTER_LOG" "$base_lines" '"reason":"fingerprint_not_allowlisted"' 15 || true)"
{
  echo "revoked_fp_sha256=${REVOKED_FP}"
  echo "allowlist_path=${ALLOWLIST_PATH}"
  echo "reject_line=${reject_line}"
  tail -n 80 "$MASTER_LOG" || true
} > "$VERIFY_REJECT_LOG"

if [[ -z "$reject_line" ]]; then
  fail_with_context "expected fingerprint_not_allowlisted rejection not observed" "$MASTER_LOG"
fi
echo "ALLOWLIST_REJECT=PASS reason=fingerprint_not_allowlisted"

./scripts/pki_allowlist_add_fingerprint.sh "$REVOKED_FP" >/dev/null
stop_master

reallow_status="FAIL"
if ./scripts/verify_fr02_mtls.sh >"$VERIFY_REALLOW_LOG" 2>&1; then
  if rg -q '^fr02_status=PASS$' "$VERIFY_REALLOW_LOG"; then
    reallow_status="PASS"
  fi
fi

if [[ "$reallow_status" != "PASS" ]]; then
  fail_with_context "reallow verification failed (fr02_status not PASS)" "$VERIFY_REALLOW_LOG"
fi
echo "ALLOWLIST_ALLOW=PASS"

generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
cat > "$PROOF_JSON" <<EOF_JSON
{
  "timestamp": "$(json_escape "$generated_at")",
  "agent_id": "$(json_escape "$AGENT_ID")",
  "agent_id_source": "cert_cn",
  "allowlist_path": "$(json_escape "$ALLOWLIST_PATH")",
  "revoked_fp_sha256": "$(json_escape "$REVOKED_FP")",
  "reject_evidence": "fingerprint_not_allowlisted",
  "reallow_verifier": "$(json_escape "$reallow_status")",
  "verify_reject_log": "$(json_escape "$VERIFY_REJECT_LOG")",
  "verify_reallow_log": "$(json_escape "$VERIFY_REALLOW_LOG")"
}
EOF_JSON

echo "PASS: FR-02 REVOCATION WORKFLOW completed"
echo "FR02_REVOCATION_PROOF_JSON=${PROOF_JSON}"
