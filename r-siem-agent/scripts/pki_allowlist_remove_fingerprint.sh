#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

normalize_fp() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -d ':\r\n\t '
}

if [[ $# -lt 1 ]]; then
  echo "Usage: ./scripts/pki_allowlist_remove_fingerprint.sh <FP>" >&2
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

tmp_file="$(mktemp)"
REMOVED=0
while IFS= read -r line || [[ -n "$line" ]]; do
  normalized="$(normalize_fp "$line")"
  if [[ "$normalized" == "$FP" ]]; then
    REMOVED=1
    continue
  fi
  if [[ "$normalized" =~ ^[0-9a-f]{64}$ ]]; then
    printf '%s\n' "$normalized" >> "$tmp_file"
  fi
done < "$ALLOWLIST_PATH"
mv -f "$tmp_file" "$ALLOWLIST_PATH"

echo "ALLOWLIST_PATH=${ALLOWLIST_PATH}"
echo "REMOVED=${REMOVED}"
echo "PASS: allowlist remove fingerprint fp=${FP}"
