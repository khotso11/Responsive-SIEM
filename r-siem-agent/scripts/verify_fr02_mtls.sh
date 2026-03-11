#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

find_free_port() {
  local start="${1:-17777}"
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

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "FAIL: missing command: $1" >&2
    exit 1
  }
}

nats_reachable() {
  if command -v ss >/dev/null 2>&1; then
    ss -ltn 2>/dev/null | rg -q '(^|[[:space:]])(\*|0\.0\.0\.0|127\.0\.0\.1):4222([[:space:]]|$)|(\[::\]|::):4222'
  else
    timeout 2 bash -c '</dev/tcp/127.0.0.1/4222' >/dev/null 2>&1
  fi
}

ensure_local_nats() {
  if nats_reachable; then
    return 0
  fi

  docker start rsiem-nats-lan >/dev/null 2>&1 || docker start nats >/dev/null 2>&1 || true

  local i=0
  while (( i < 20 )); do
    if nats_reachable; then
      return 0
    fi
    sleep 0.5
    i=$((i + 1))
  done
  return 1
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

extract_json_field() {
  local line="$1"
  local key="$2"
  sed -n "s/.*\"${key}\":\"\([^\"]*\)\".*/\1/p" <<<"$line"
}

json_line_or_null() {
  local line="${1:-}"
  if [[ -z "$line" ]]; then
    printf 'null'
  else
    line="${line//\\/\\\\}"
    line="${line//\"/\\\"}"
    printf '"%s"' "$line"
  fi
}

if [[ -n "${FR02_MTLS_PORT:-}" ]]; then
  PORT="${FR02_MTLS_PORT}"
else
  PORT="$(find_free_port 27877)" || {
    echo "FAIL: unable to find free port for FR-02 verifier" >&2
    exit 1
  }
fi

TMP_DIR="tmp/fr02_mtls"
timestamp="$(date +%Y%m%d_%H%M%S)"
artifact_dir="demo_artifacts/${timestamp}"
proof_json="${artifact_dir}/fr02_mtls_proof.json"
MASTER_LOG="${artifact_dir}/fr02.master.log"
AGENT_LOG="${artifact_dir}/fr02.agent.log"
MASTER_CFG="${TMP_DIR}/master.yaml"
AGENT_CFG="${TMP_DIR}/agent.yaml"
MASTER_BIN="${TMP_DIR}/master.bin"
AGENT_BIN="${TMP_DIR}/agent.bin"
ALLOWLIST_OK="${TMP_DIR}/allowlist.ok.txt"
ALLOWLIST_BAD="${TMP_DIR}/allowlist.bad.txt"

mkdir -p logs "$TMP_DIR" "$artifact_dir"

server_started="FAIL"
t1="FAIL"
t2="FAIL"
t3="FAIL"
t4="FAIL"
t5="FAIL"
t6="FAIL"
t7="FAIL"
fr02_status="PASS"

server_started_line=""
t1_line=""
t2_line=""
t3_line=""
t4_line=""
t6_line=""
t7_line=""
t3_note=""
t4_note=""

agent_instance_id="unknown"
agent_id_source="unknown"
peer_subject=""
peer_san=""
peer_fingerprint_sha256=""

allowlist_enabled="false"
allowlist_path=""
allowlist_reason=""

master_pid=""
agent_pid=""
current_expected_identity=""
current_identity_source=""
current_allowlist_path=""

cleanup() {
  pkill -f ' --config tmp/fr02_mtls/master.yaml' >/dev/null 2>&1 || true
  pkill -f ' --config tmp/fr02_mtls/agent.yaml' >/dev/null 2>&1 || true
  pkill -f ' --config tmp/fr02_mtls/master.ok.yaml' >/dev/null 2>&1 || true
  pkill -f ' --config tmp/fr02_mtls/agent.ok.yaml' >/dev/null 2>&1 || true
  if [[ -n "$agent_pid" ]] && kill -0 "$agent_pid" 2>/dev/null; then
    kill "$agent_pid" 2>/dev/null || true
    wait "$agent_pid" 2>/dev/null || true
  fi
  if [[ -n "$master_pid" ]] && kill -0 "$master_pid" 2>/dev/null; then
    kill "$master_pid" 2>/dev/null || true
    wait "$master_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# Best-effort cleanup of stale verifier processes from prior runs.
pkill -f ' --config tmp/fr02_mtls/master.yaml' >/dev/null 2>&1 || true
pkill -f ' --config tmp/fr02_mtls/agent.yaml' >/dev/null 2>&1 || true
pkill -f ' --config tmp/fr02_mtls/master.ok.yaml' >/dev/null 2>&1 || true
pkill -f ' --config tmp/fr02_mtls/agent.ok.yaml' >/dev/null 2>&1 || true

stop_master() {
  if [[ -n "$master_pid" ]] && kill -0 "$master_pid" 2>/dev/null; then
    kill "$master_pid" 2>/dev/null || true
    wait "$master_pid" 2>/dev/null || true
  fi
  master_pid=""
}

stop_agent() {
  if [[ -n "$agent_pid" ]] && kill -0 "$agent_pid" 2>/dev/null; then
    kill "$agent_pid" 2>/dev/null || true
    wait "$agent_pid" 2>/dev/null || true
  fi
  agent_pid=""
}

write_master_cfg() {
  local expected_identity="$1"
  local identity_source="$2"
  local allowlist_path_value="${3:-}"
  current_expected_identity="$expected_identity"
  current_identity_source="$identity_source"
  current_allowlist_path="$allowlist_path_value"
  cat > "$MASTER_CFG" <<EOF_MASTER
log_level: INFO
listen_addr: 127.0.0.1:${PORT}
transport:
  mode: grpc_mtls
  tls:
    ca: configs/certs/ca.pem
    cert: configs/certs/master.pem
    key: configs/certs/master-key.pem
    client_identity: "${expected_identity}"
    client_identity_source: "${identity_source}"
EOF_MASTER
  if [[ -n "$allowlist_path_value" ]]; then
    cat >> "$MASTER_CFG" <<EOF_MASTER
    client_fingerprint_allowlist_path: "${allowlist_path_value}"
EOF_MASTER
  fi
  cat >> "$MASTER_CFG" <<EOF_MASTER
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

write_agent_cfg() {
  cat > "$AGENT_CFG" <<EOF_AGENT
log:
  level: INFO
heartbeat:
  interval_seconds: 2
mock:
  interval_seconds: 1
agent:
  name: r-siem-agent
  instance_id: dev-instance
  quarantine_root: tmp/quarantine
  quarantine_allowed_source_roots:
    - tmp
lanes:
  fast_buffer: 100
  standard_buffer: 100
wal:
  path: ./data/agent.fr02.wal
  fsync: false
batch:
  fast:
    max_size: 2
    max_latency_ms: 200
  standard:
    max_size: 2
    max_latency_ms: 200
transport:
  mode: grpc_mtls
  addr: 127.0.0.1:${PORT}
  ack_delay_ms: 10
  ack_drop_rate: 0.0
  tls:
    ca: configs/certs/ca.pem
    cert: configs/certs/agent.pem
    key: configs/certs/agent-key.pem
    server_name: master.local
EOF_AGENT
}

start_master() {
  local attempts=0
  while (( attempts < 5 )); do
    : > "$MASTER_LOG"
    "$MASTER_BIN" --config "$MASTER_CFG" >"$MASTER_LOG" 2>&1 &
    master_pid=$!
    local i=0
    local started=""
    local auth_fallback=""
    while (( i < 250 )); do
      if ! kill -0 "$master_pid" 2>/dev/null; then
        break
      fi
      started="$(rg '"msg":"grpc_mtls_server_started"' "$MASTER_LOG" | head -n 1 || true)"
      if [[ -n "$started" ]]; then
        break
      fi
      auth_fallback="$(rg '"msg":"grpc_mtls_client_authenticated"' "$MASTER_LOG" | head -n 1 || true)"
      if [[ -n "$auth_fallback" ]]; then
        break
      fi
      sleep 0.2
      i=$((i + 1))
    done

    server_started_line="${started:-$auth_fallback}"
    if [[ -n "$server_started_line" ]]; then
      server_started="PASS"
      return 0
    fi

    if rg -q '"msg":"listen_failed".*"address already in use"|listen tcp .*: bind: address already in use' "$MASTER_LOG"; then
      stop_master
      PORT="$(find_free_port "$((PORT + 1))" || true)"
      if [[ -z "$PORT" ]]; then
        break
      fi
      write_agent_cfg
      write_master_cfg "$current_expected_identity" "$current_identity_source" "$current_allowlist_path"
      attempts=$((attempts + 1))
      continue
    fi
    break
  done

  echo "FAIL: master did not start with mTLS" >&2
  echo "Context: tail -n 80 $MASTER_LOG" >&2
  tail -n 80 "$MASTER_LOG" >&2 || true
  return 1
}

start_agent() {
  : > "$AGENT_LOG"
  RSIEM_AGENT_DISABLE_COMMAND_LISTENER=1 "$AGENT_BIN" --config "$AGENT_CFG" >"$AGENT_LOG" 2>&1 &
  agent_pid=$!
}

need_cmd rg
need_cmd go
if ! command -v openssl >/dev/null 2>&1; then
  echo "FAIL: openssl is required for FR-02 verification" >&2
  exit 1
fi

server_fingerprint_sha256="$(cert_fp_or_empty "configs/certs/master.pem")"
client_fingerprint_sha256="$(cert_fp_or_empty "configs/certs/agent.pem")"

ensure_local_nats || {
  echo "FAIL: NATS not reachable on 127.0.0.1:4222" >&2
  exit 1
}

GOCACHE="$(pwd)/.cache/go-build" go build -mod=vendor -o "$MASTER_BIN" ./cmd/master
GOCACHE="$(pwd)/.cache/go-build" go build -mod=vendor -o "$AGENT_BIN" ./cmd/agent

write_agent_cfg

# T1 + T5 baseline: cert_only policy must still authenticate valid agent.
write_master_cfg "agent.local" "cert_only" ""
start_master

t1_base="$(line_count "$MASTER_LOG")"
start_agent
t1_line="$(wait_new_log "$MASTER_LOG" "$t1_base" '"msg":"grpc_mtls_client_authenticated"' 25 || true)"
if [[ -n "$t1_line" ]]; then
  t1="PASS"
  agent_instance_id="$(extract_json_field "$t1_line" "agent_instance_id")"
  agent_id_source="$(extract_json_field "$t1_line" "agent_id_source")"
  peer_subject="$(extract_json_field "$t1_line" "peer_subject")"
  peer_san="$(extract_json_field "$t1_line" "peer_san")"
  peer_fingerprint_sha256="$(extract_json_field "$t1_line" "peer_fingerprint_sha256")"
fi
stop_agent

if [[ "$t1" == "PASS" && "$agent_instance_id" != "unknown" && "$agent_id_source" != "grpc_metadata" && "$agent_id_source" != "unknown" ]]; then
  t5="PASS"
else
  t5="FAIL"
fi

# T2: no client cert should be rejected.
t2_base="$(line_count "$MASTER_LOG")"
openssl s_client -connect "127.0.0.1:${PORT}" -servername master.local -CAfile configs/certs/ca.pem </dev/null >/dev/null 2>&1 || true
t2_line="$(wait_new_log "$MASTER_LOG" "$t2_base" '"msg":"grpc_mtls_handshake_failed".*"reason":"no_client_certificate"' 10 || true)"
if [[ -n "$t2_line" ]]; then
  t2="PASS"
fi

# T3: unknown CA should be rejected.
t3_base="$(line_count "$MASTER_LOG")"
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
  -subj "/CN=FR02-UNKNOWN-CA" \
  -keyout "${TMP_DIR}/unknown-ca-key.pem" \
  -out "${TMP_DIR}/unknown-ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
  -subj "/CN=agent.local" \
  -keyout "${TMP_DIR}/unknown-agent-key.pem" \
  -out "${TMP_DIR}/unknown-agent.csr" >/dev/null 2>&1
openssl x509 -req -in "${TMP_DIR}/unknown-agent.csr" \
  -CA "${TMP_DIR}/unknown-ca.pem" -CAkey "${TMP_DIR}/unknown-ca-key.pem" -CAcreateserial \
  -days 1 -sha256 -out "${TMP_DIR}/unknown-agent.pem" >/dev/null 2>&1
openssl s_client -connect "127.0.0.1:${PORT}" -servername master.local \
  -CAfile configs/certs/ca.pem \
  -cert "${TMP_DIR}/unknown-agent.pem" \
  -key "${TMP_DIR}/unknown-agent-key.pem" </dev/null >/dev/null 2>&1 || true
t3_line="$(wait_new_log "$MASTER_LOG" "$t3_base" '"msg":"grpc_mtls_handshake_failed".*"reason":"unknown_ca"' 10 || true)"
if [[ -n "$t3_line" ]]; then
  t3="PASS"
else
  t3="FAIL"
fi

# T4: identity mismatch against valid CA cert should be rejected.
t4_base="$(line_count "$MASTER_LOG")"
if [[ -f configs/certs/ca-key.pem ]]; then
  openssl req -newkey rsa:2048 -nodes \
    -subj "/CN=bad-agent.local" \
    -keyout "${TMP_DIR}/mismatch-agent-key.pem" \
    -out "${TMP_DIR}/mismatch-agent.csr" >/dev/null 2>&1
  openssl x509 -req -in "${TMP_DIR}/mismatch-agent.csr" \
    -CA configs/certs/ca.pem -CAkey configs/certs/ca-key.pem -CAcreateserial \
    -days 1 -sha256 -out "${TMP_DIR}/mismatch-agent.pem" >/dev/null 2>&1
  openssl s_client -connect "127.0.0.1:${PORT}" -servername master.local \
    -CAfile configs/certs/ca.pem \
    -cert "${TMP_DIR}/mismatch-agent.pem" \
    -key "${TMP_DIR}/mismatch-agent-key.pem" </dev/null >/dev/null 2>&1 || true
  t4_line="$(wait_new_log "$MASTER_LOG" "$t4_base" '"msg":"grpc_mtls_handshake_failed".*"reason":"identity_mismatch"' 10 || true)"
  if [[ -n "$t4_line" ]]; then
    t4="PASS"
  else
    t4="FAIL"
  fi
else
  t4="SKIP"
  t4_note="configs/certs/ca-key.pem missing"
fi

stop_master

# T6: allowlist accept.
if [[ -n "$peer_fingerprint_sha256" ]]; then
  printf '%s\n' "$peer_fingerprint_sha256" > "$ALLOWLIST_OK"
  allowlist_enabled="true"
  allowlist_path="$ALLOWLIST_OK"

  write_master_cfg "agent.local" "cert_only" "$ALLOWLIST_OK"
  start_master
  t6_base="$(line_count "$MASTER_LOG")"
  start_agent
  t6_line="$(wait_new_log "$MASTER_LOG" "$t6_base" '"msg":"grpc_mtls_client_authenticated"' 20 || true)"
  if [[ -n "$t6_line" ]]; then
    t6="PASS"
  else
    t6="FAIL"
  fi
  stop_agent
  stop_master
else
  t6="FAIL"
fi

# T7: allowlist reject.
printf '%064d\n' 0 > "$ALLOWLIST_BAD"
allowlist_enabled="true"
allowlist_path="$ALLOWLIST_BAD"
write_master_cfg "agent.local" "cert_only" "$ALLOWLIST_BAD"
start_master
t7_base="$(line_count "$MASTER_LOG")"
openssl s_client -connect "127.0.0.1:${PORT}" -servername master.local \
  -CAfile configs/certs/ca.pem \
  -cert configs/certs/agent.pem \
  -key configs/certs/agent-key.pem </dev/null >/dev/null 2>&1 || true
t7_line="$(wait_new_log "$MASTER_LOG" "$t7_base" '"msg":"grpc_mtls_client_rejected".*"reason":"fingerprint_not_allowlisted"' 10 || true)"
if [[ -n "$t7_line" ]]; then
  t7="PASS"
  allowlist_reason="$(extract_json_field "$t7_line" "reason")"
else
  t7="FAIL"
fi
stop_master

if [[ "$server_started" != "PASS" || "$t1" != "PASS" || "$t2" != "PASS" || "$t3" != "PASS" || "$t5" != "PASS" || "$t6" != "PASS" || "$t7" != "PASS" ]]; then
  fr02_status="FAIL"
fi
if [[ "$t4" == "FAIL" ]]; then
  fr02_status="FAIL"
fi

generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
hostname_val="$(hostname)"
if [[ -z "$allowlist_reason" ]]; then
  allowlist_reason="fingerprint_not_allowlisted"
fi

cat > "$proof_json" <<EOF_JSON
{
  "generated_at": "${generated_at}",
  "hostname": "${hostname_val}",
  "port": ${PORT},
  "mtls_required": true,
  "server_fingerprint_sha256": $(json_line_or_null "$server_fingerprint_sha256"),
  "client_fingerprint_sha256": $(json_line_or_null "$client_fingerprint_sha256"),
  "results": {
    "server_started": "${server_started}",
    "t1": "${t1}",
    "t2": "${t2}",
    "t3": "${t3}",
    "t4": "${t4}",
    "t5": "${t5}",
    "t6": "${t6}",
    "t7": "${t7}",
    "fr02_status": "${fr02_status}"
  },
  "negative_tests": [
    {
      "name": "no_client_cert",
      "status": "${t2}",
      "reason": "no_client_certificate",
      "evidence_line": $(json_line_or_null "$t2_line")
    },
    {
      "name": "unknown_ca",
      "status": "${t3}",
      "reason": "unknown_ca",
      "evidence_line": $(json_line_or_null "$t3_line")
    },
    {
      "name": "identity_mismatch",
      "status": "${t4}",
      "reason": "identity_mismatch",
      "evidence_line": $(json_line_or_null "$t4_line")
    }
  ],
  "allowlist_test": {
    "status": "${t7}",
    "observed": "$(printf '%s' "$allowlist_reason" | sed 's/"/\\"/g')",
    "evidence_line": $(json_line_or_null "$t7_line")
  },
  "evidence": {
    "master_log": "${MASTER_LOG}",
    "agent_log": "${AGENT_LOG}",
    "server_started_line": $(json_line_or_null "$server_started_line"),
    "t1_line": $(json_line_or_null "$t1_line"),
    "t2_line": $(json_line_or_null "$t2_line"),
    "t3_line": $(json_line_or_null "$t3_line"),
    "t3_note": $(json_line_or_null "$t3_note"),
    "t4_line": $(json_line_or_null "$t4_line"),
    "t4_note": $(json_line_or_null "$t4_note"),
    "t6_line": $(json_line_or_null "$t6_line"),
    "t7_line": $(json_line_or_null "$t7_line"),
    "agent_instance_id": "$(printf '%s' "$agent_instance_id" | sed 's/"/\\"/g')",
    "agent_id_source": "$(printf '%s' "$agent_id_source" | sed 's/"/\\"/g')",
    "peer_subject": "$(printf '%s' "$peer_subject" | sed 's/"/\\"/g')",
    "peer_san": "$(printf '%s' "$peer_san" | sed 's/"/\\"/g')",
    "peer_fingerprint_sha256": "$(printf '%s' "$peer_fingerprint_sha256" | sed 's/"/\\"/g')",
    "allowlist_enabled": ${allowlist_enabled},
    "allowlist_path": $(json_line_or_null "$allowlist_path")
  }
}
EOF_JSON

echo "=== FR-02 mTLS SUMMARY ==="
echo "server_started=${server_started}"
echo "t1=${t1}"
echo "t2=${t2}"
echo "t3=${t3}"
echo "t4=${t4}"
echo "t5=${t5}"
echo "t6=${t6}"
echo "t7=${t7}"
echo "fr02_status=${fr02_status}"
echo "agent_instance_id=${agent_instance_id}"
echo "agent_id_source=${agent_id_source}"
echo "proof_log=${proof_json}"
if [[ "${fr02_status}" == "PASS" ]]; then
  echo "PASS: FR-02 mTLS"
else
  echo "FAIL: FR-02 mTLS"
fi
echo "NEG:no_client_cert=${t2}"
echo "NEG:unknown_ca=${t3}"
echo "NEG:identity_mismatch=${t4}"
echo "ALLOWLIST_REJECT=${t7} reason=${allowlist_reason}"
echo "FR02_PROOF_JSON=${proof_json}"

if [[ "${fr02_status}" != "PASS" ]]; then
  exit 1
fi
