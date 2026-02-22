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

fingerprint_sha256() {
  local cert_path="$1"
  openssl x509 -in "$cert_path" -noout -fingerprint -sha256 \
    | sed 's/^.*=//' \
    | tr -d ':' \
    | tr 'A-F' 'a-f'
}

need_cmd openssl

if [[ $# -lt 1 ]]; then
  echo "Usage: ./scripts/pki_issue_agent_cert.sh <AGENT_ID>" >&2
  exit 1
fi

AGENT_ID="$1"
if [[ ! "$AGENT_ID" =~ ^[A-Za-z0-9._:-]+$ ]]; then
  echo "FAIL: invalid AGENT_ID (allowed: letters, numbers, . _ : -)" >&2
  exit 1
fi

PKI_ROOT="${PKI_ROOT:-pki}"
TARGET="${TARGET:-${SLOT:-current}}"
DAYS="${DAYS:-365}"

if [[ "$TARGET" != "current" && "$TARGET" != "next" ]]; then
  echo "FAIL: TARGET must be current or next (got: $TARGET)" >&2
  exit 1
fi

CA_DIR="${PKI_ROOT}/ca"
CA_KEY="${CA_DIR}/ca.key"
CA_CERT="${CA_DIR}/ca.crt"
CA_SRL="${CA_DIR}/ca.srl"

AGENT_DIR="${PKI_ROOT}/agents/${AGENT_ID}/${TARGET}"
AGENT_KEY="${AGENT_DIR}/client.key"
AGENT_CSR="${AGENT_DIR}/client.csr"
AGENT_CERT="${AGENT_DIR}/client.crt"
AGENT_EXT="${AGENT_DIR}/client-ext.cnf"
AGENT_KEY_LEGACY="${AGENT_DIR}/agent-key.pem"
AGENT_CERT_LEGACY="${AGENT_DIR}/agent.pem"

mkdir -p "$AGENT_DIR"

if [[ ! -f "$CA_KEY" || ! -f "$CA_CERT" ]]; then
  ./scripts/pki_init_ca.sh >/dev/null 2>&1
fi

if [[ -f "$AGENT_KEY" && -f "$AGENT_CERT" && "${FORCE:-0}" != "1" ]]; then
  fp_existing="$(fingerprint_sha256 "$AGENT_CERT")"
  cp "$AGENT_KEY" "$AGENT_KEY_LEGACY"
  cp "$AGENT_CERT" "$AGENT_CERT_LEGACY"
  echo "AGENT_ID=${AGENT_ID}"
  echo "AGENT_CERT_PATH=${AGENT_CERT}"
  echo "AGENT_FP_SHA256=${fp_existing}"
  echo "PASS: pki_issue_agent_cert target=${TARGET}"
  exit 0
fi

rm -f "$AGENT_KEY" "$AGENT_CSR" "$AGENT_CERT" "$AGENT_EXT" "$AGENT_KEY_LEGACY" "$AGENT_CERT_LEGACY"

openssl req -newkey rsa:2048 -sha256 -nodes \
  -subj "/CN=${AGENT_ID}" \
  -keyout "$AGENT_KEY" \
  -out "$AGENT_CSR" >/dev/null 2>&1

cat > "$AGENT_EXT" <<EOF_EXT
extendedKeyUsage=clientAuth
keyUsage=digitalSignature,keyEncipherment
EOF_EXT

if [[ -f "$CA_SRL" ]]; then
  serial_args=(-CAserial "$CA_SRL")
else
  serial_args=(-CAcreateserial -CAserial "$CA_SRL")
fi

openssl x509 -req \
  -in "$AGENT_CSR" \
  -CA "$CA_CERT" \
  -CAkey "$CA_KEY" \
  "${serial_args[@]}" \
  -out "$AGENT_CERT" \
  -days "$DAYS" \
  -sha256 \
  -extfile "$AGENT_EXT" >/dev/null 2>&1

if [[ ! -f "$AGENT_KEY" || ! -f "$AGENT_CERT" ]]; then
  echo "FAIL: agent cert issuance failed" >&2
  exit 1
fi

chmod 600 "$AGENT_KEY"
chmod 644 "$AGENT_CERT"
cp "$AGENT_KEY" "$AGENT_KEY_LEGACY"
cp "$AGENT_CERT" "$AGENT_CERT_LEGACY"

fp="$(fingerprint_sha256 "$AGENT_CERT")"
echo "AGENT_ID=${AGENT_ID}"
echo "AGENT_CERT_PATH=${AGENT_CERT}"
echo "AGENT_FP_SHA256=${fp}"
echo "PASS: pki_issue_agent_cert target=${TARGET}"
