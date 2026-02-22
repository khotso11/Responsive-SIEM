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

normalize_fp() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -d ':\r\n\t '
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

line_count() {
  local file="$1"
  [[ -f "$file" ]] || { echo 0; return; }
  wc -l < "$file" | tr -d '[:space:]'
}

wait_new_log() {
  local file="$1"
  local base="$2"
  local pattern="$3"
  local timeout="${4:-12}"
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

json_or_null() {
  local value="${1:-}"
  if [[ -z "$value" ]]; then
    printf 'null'
  else
    printf '"%s"' "$(json_escape "$value")"
  fi
}

if [[ $# -lt 1 ]]; then
  echo "Usage: ./scripts/pki_revoke_fingerprint.sh <FINGERPRINT_SHA256>" >&2
  exit 1
fi

REVOKED_FP="$(normalize_fp "$1")"
if [[ ! "$REVOKED_FP" =~ ^[0-9a-f]{64}$ ]]; then
  echo "FAIL: fingerprint must be 64 hex chars (colons allowed in input)" >&2
  exit 1
fi

need_cmd openssl
need_cmd rg
need_cmd go

if command -v ss >/dev/null 2>&1; then
  if ! ss -ltn 2>/dev/null | rg -q '(^|[[:space:]])\*:4222([[:space:]]|$)|127\.0\.0\.1:4222'; then
    echo "FAIL: NATS not reachable on 127.0.0.1:4222" >&2
    exit 1
  fi
fi

PKI_ROOT="${PKI_ROOT:-tmp/pki/fr02}"
ALLOWLIST_DIR="${PKI_ROOT}/allowlist"
ALLOWLIST_PATH="${ALLOWLIST_DIR}/master_client_allowlist.txt"
TMP_DIR="tmp/fr02_mtls"
MASTER_CFG="${TMP_DIR}/revoke_master.yaml"
MASTER_BIN="${TMP_DIR}/master.bin"

timestamp="$(date +%Y%m%d_%H%M%S)"
artifact_dir="demo_artifacts/${timestamp}"
proof_json="${artifact_dir}/fr02_revocation_proof.json"
MASTER_LOG="${artifact_dir}/fr02.revoke.master.log"

mkdir -p "$ALLOWLIST_DIR" "$TMP_DIR" "$artifact_dir" .cache/go-build

if [[ ! -f "$ALLOWLIST_PATH" ]]; then
  current_fp="$(cert_fp_or_empty "configs/certs/agent.pem")"
  if [[ -n "$current_fp" ]]; then
    printf '%s\n' "$current_fp" > "$ALLOWLIST_PATH"
  else
    printf '%064d\n' 0 > "$ALLOWLIST_PATH"
  fi
fi

tmp_allowlist="${ALLOWLIST_PATH}.tmp.$$"
touch "$tmp_allowlist"
found_removed="false"
while IFS= read -r line || [[ -n "$line" ]]; do
  stripped="$(printf '%s' "$line" | sed 's/[[:space:]]*$//')"
  if [[ -z "$stripped" || "$stripped" =~ ^[[:space:]]*# ]]; then
    continue
  fi
  normalized="$(normalize_fp "$stripped")"
  if [[ ! "$normalized" =~ ^[0-9a-f]{64}$ ]]; then
    continue
  fi
  if [[ "$normalized" == "$REVOKED_FP" ]]; then
    found_removed="true"
    continue
  fi
  printf '%s\n' "$normalized" >> "$tmp_allowlist"
done < "$ALLOWLIST_PATH"

if [[ ! -s "$tmp_allowlist" ]]; then
  # Keep allowlist mode enabled while denying this cert.
  printf '%064d\n' 0 > "$tmp_allowlist"
fi
mv -f "$tmp_allowlist" "$ALLOWLIST_PATH"

PORT="${FR02_MTLS_PORT:-}"
if [[ -z "$PORT" ]]; then
  PORT="$(find_free_port 27990)" || {
    echo "FAIL: unable to find free port for revocation test" >&2
    exit 1
  }
fi

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

GOCACHE="$(pwd)/.cache/go-build" go build -mod=vendor -o "$MASTER_BIN" ./cmd/master

master_pid=""
cleanup() {
  if [[ -n "$master_pid" ]] && kill -0 "$master_pid" 2>/dev/null; then
    kill "$master_pid" 2>/dev/null || true
    wait "$master_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT

: > "$MASTER_LOG"
"$MASTER_BIN" --config "$MASTER_CFG" >"$MASTER_LOG" 2>&1 &
master_pid=$!

started_line=""
for _ in $(seq 1 100); do
  if ! kill -0 "$master_pid" 2>/dev/null; then
    break
  fi
  started_line="$(rg '"msg":"grpc_mtls_server_started"' "$MASTER_LOG" | head -n 1 || true)"
  if [[ -n "$started_line" ]]; then
    break
  fi
  sleep 0.2
done

if [[ -z "$started_line" ]]; then
  echo "FAIL: revocation test master did not start" >&2
  echo "Context: tail -n 80 ${MASTER_LOG}" >&2
  tail -n 80 "$MASTER_LOG" >&2 || true
  exit 1
fi

base_lines="$(line_count "$MASTER_LOG")"
openssl s_client -connect "127.0.0.1:${PORT}" -servername master.local \
  -CAfile configs/certs/ca.pem \
  -cert configs/certs/agent.pem \
  -key configs/certs/agent-key.pem </dev/null >/dev/null 2>&1 || true

reject_line="$(wait_new_log "$MASTER_LOG" "$base_lines" '"reason":"fingerprint_not_allowlisted"' 12 || true)"

generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
host_val="$(hostname)"
status="FAIL"
if [[ -n "$reject_line" ]]; then
  status="PASS"
fi

cat > "$proof_json" <<EOF_JSON
{
  "generated_at": "${generated_at}",
  "hostname": "$(json_escape "$host_val")",
  "status": "${status}",
  "fingerprint_revoked": "${REVOKED_FP}",
  "fingerprint_was_in_allowlist": ${found_removed},
  "allowlist_path": "$(json_escape "$ALLOWLIST_PATH")",
  "master_log": "$(json_escape "$MASTER_LOG")",
  "rejection_evidence": $(json_or_null "$reject_line")
}
EOF_JSON

echo "FR02_REVOCATION_PROOF_JSON: ${proof_json}"

if [[ "$status" != "PASS" ]]; then
  echo "FAIL: revocation reject proof missing" >&2
  echo "Context: tail -n 120 ${MASTER_LOG}" >&2
  tail -n 120 "$MASTER_LOG" >&2 || true
  exit 1
fi

echo "PASS: FR-02 REVOCATION WORKFLOW"
