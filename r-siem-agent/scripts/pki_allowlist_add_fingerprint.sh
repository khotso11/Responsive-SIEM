#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

normalize_fp() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -d ':\r\n\t '
}

if [[ $# -lt 1 ]]; then
  echo "Usage: ./scripts/pki_allowlist_add_fingerprint.sh <FP>" >&2
  exit 1
fi

FP="$(normalize_fp "$1")"
if [[ ! "$FP" =~ ^[0-9a-f]{64}$ ]]; then
  echo "FAIL: fingerprint must be 64 hex chars (colons allowed in input)" >&2
  exit 1
fi

ALLOWLIST_PATH="${ALLOWLIST_PATH:-pki/allowlist_fingerprints.txt}"
mkdir -p "$(dirname "$ALLOWLIST_PATH")"
touch "$ALLOWLIST_PATH"

ADDED=1
if rg -q "^${FP}$" "$ALLOWLIST_PATH"; then
  ADDED=0
else
  printf '%s\n' "$FP" >> "$ALLOWLIST_PATH"
fi

echo "ALLOWLIST_PATH=${ALLOWLIST_PATH}"
echo "ADDED=${ADDED}"
echo "PASS: allowlist add fingerprint fp=${FP}"
