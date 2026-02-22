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

PKI_ROOT="${PKI_ROOT:-pki}"
TARGET="${TARGET:-${SLOT:-current}}"
MASTER_ID="${MASTER_ID:-master.local}"
DAYS="${DAYS:-365}"

if [[ "$TARGET" != "current" && "$TARGET" != "next" ]]; then
  echo "FAIL: TARGET must be current or next (got: $TARGET)" >&2
  exit 1
fi

CA_DIR="${PKI_ROOT}/ca"
CA_KEY="${CA_DIR}/ca.key"
CA_CERT="${CA_DIR}/ca.crt"
CA_SRL="${CA_DIR}/ca.srl"

MASTER_DIR="${PKI_ROOT}/master/${TARGET}"
MASTER_KEY="${MASTER_DIR}/server.key"
MASTER_CSR="${MASTER_DIR}/server.csr"
MASTER_CERT="${MASTER_DIR}/server.crt"
MASTER_EXT="${MASTER_DIR}/server-ext.cnf"
MASTER_KEY_LEGACY="${MASTER_DIR}/master-key.pem"
MASTER_CERT_LEGACY="${MASTER_DIR}/master.pem"

mkdir -p "$MASTER_DIR"

if [[ ! -f "$CA_KEY" || ! -f "$CA_CERT" ]]; then
  ./scripts/pki_init_ca.sh >/dev/null 2>&1
fi

if [[ -f "$MASTER_KEY" && -f "$MASTER_CERT" && "${FORCE:-0}" != "1" ]]; then
  fp_existing="$(fingerprint_sha256 "$MASTER_CERT")"
  cp "$MASTER_KEY" "$MASTER_KEY_LEGACY"
  cp "$MASTER_CERT" "$MASTER_CERT_LEGACY"
  echo "MASTER_CERT_PATH=${MASTER_CERT}"
  echo "MASTER_FP_SHA256=${fp_existing}"
  echo "PASS: pki_issue_master_cert target=${TARGET}"
  exit 0
fi

rm -f "$MASTER_KEY" "$MASTER_CSR" "$MASTER_CERT" "$MASTER_EXT" "$MASTER_KEY_LEGACY" "$MASTER_CERT_LEGACY"

openssl req -newkey rsa:2048 -sha256 -nodes \
  -subj "/CN=${MASTER_ID}" \
  -keyout "$MASTER_KEY" \
  -out "$MASTER_CSR" >/dev/null 2>&1

cat > "$MASTER_EXT" <<EOF_EXT
subjectAltName=DNS:${MASTER_ID}
extendedKeyUsage=serverAuth
keyUsage=digitalSignature,keyEncipherment
EOF_EXT

if [[ -f "$CA_SRL" ]]; then
  serial_args=(-CAserial "$CA_SRL")
else
  serial_args=(-CAcreateserial -CAserial "$CA_SRL")
fi

openssl x509 -req \
  -in "$MASTER_CSR" \
  -CA "$CA_CERT" \
  -CAkey "$CA_KEY" \
  "${serial_args[@]}" \
  -out "$MASTER_CERT" \
  -days "$DAYS" \
  -sha256 \
  -extfile "$MASTER_EXT" >/dev/null 2>&1

if [[ ! -f "$MASTER_KEY" || ! -f "$MASTER_CERT" ]]; then
  echo "FAIL: master cert issuance failed" >&2
  exit 1
fi

chmod 600 "$MASTER_KEY"
chmod 644 "$MASTER_CERT"
cp "$MASTER_KEY" "$MASTER_KEY_LEGACY"
cp "$MASTER_CERT" "$MASTER_CERT_LEGACY"

fp="$(fingerprint_sha256 "$MASTER_CERT")"
echo "MASTER_CERT_PATH=${MASTER_CERT}"
echo "MASTER_FP_SHA256=${fp}"
echo "PASS: pki_issue_master_cert target=${TARGET}"
