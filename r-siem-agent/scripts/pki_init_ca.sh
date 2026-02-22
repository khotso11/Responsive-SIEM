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

need_cmd openssl

PKI_ROOT="${PKI_ROOT:-pki}"
CA_DIR="${PKI_ROOT}/ca"
CA_KEY="${CA_DIR}/ca.key"
CA_CERT="${CA_DIR}/ca.crt"
CA_SRL="${CA_DIR}/ca.srl"
CA_KEY_LEGACY="${CA_DIR}/ca-key.pem"
CA_CERT_LEGACY="${CA_DIR}/ca.pem"
DAYS="${DAYS:-3650}"

mkdir -p "$CA_DIR"

created=0

if [[ "${FORCE:-0}" == "1" ]]; then
  rm -f "$CA_KEY" "$CA_CERT" "$CA_SRL" "$CA_KEY_LEGACY" "$CA_CERT_LEGACY"
fi

if [[ ! -f "$CA_KEY" || ! -f "$CA_CERT" ]]; then
  if [[ -f "$CA_KEY_LEGACY" && -f "$CA_CERT_LEGACY" && "${FORCE:-0}" != "1" ]]; then
    cp "$CA_KEY_LEGACY" "$CA_KEY"
    cp "$CA_CERT_LEGACY" "$CA_CERT"
  else
    openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
      -subj "/CN=rsiem-local-ca" \
      -days "$DAYS" \
      -keyout "$CA_KEY" \
      -out "$CA_CERT" >/dev/null 2>&1
    created=1
  fi
fi

if [[ ! -f "$CA_KEY" || ! -f "$CA_CERT" ]]; then
  echo "FAIL: CA generation failed" >&2
  exit 1
fi

chmod 600 "$CA_KEY"
chmod 644 "$CA_CERT"
cp "$CA_KEY" "$CA_KEY_LEGACY"
cp "$CA_CERT" "$CA_CERT_LEGACY"

echo "PASS: pki_init_ca created=${created} ca_crt=${CA_CERT} ca_key=${CA_KEY}"
