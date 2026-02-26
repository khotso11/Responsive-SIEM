#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

need_cmd() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "FAIL: missing command: ${cmd}" >&2
    exit 1
  }
}

find_free_port() {
  local start="${1:-18443}"
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

json_escape() {
  local s="${1:-}"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/}"
  printf '%s' "$s"
}

fail_with_context() {
  local msg="$1"
  echo "FAIL: ${msg}" >&2
  if [[ -f "${OPENSSL_CLIENT_LOG:-}" ]]; then
    echo "Context: tail -n 40 ${OPENSSL_CLIENT_LOG}" >&2
    tail -n 40 "${OPENSSL_CLIENT_LOG}" >&2 || true
  fi
  if [[ -f "${TCPDUMP_LOG:-}" ]]; then
    echo "Context: tail -n 40 ${TCPDUMP_LOG}" >&2
    tail -n 40 "${TCPDUMP_LOG}" >&2 || true
  fi
  if [[ -f "${SERVER_LOG:-}" ]]; then
    echo "Context: tail -n 40 ${SERVER_LOG}" >&2
    tail -n 40 "${SERVER_LOG}" >&2 || true
  fi
  exit 1
}

stop_server() {
  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait_for_pid_exit "${SERVER_PID}" 3 || true
    if kill -0 "${SERVER_PID}" 2>/dev/null; then
      kill -9 "${SERVER_PID}" 2>/dev/null || true
      wait_for_pid_exit "${SERVER_PID}" 2 || true
    fi
  fi
  SERVER_PID=""
}

wait_for_pid_exit() {
  local pid="${1:-}"
  local timeout_s="${2:-3}"
  local i
  for ((i=0; i<timeout_s*10; i++)); do
    if ! kill -0 "${pid}" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

stop_tcpdump() {
  if [[ -n "${TCPDUMP_PID:-}" ]] && kill -0 "${TCPDUMP_PID}" 2>/dev/null; then
    kill -2 "${TCPDUMP_PID}" 2>/dev/null || kill "${TCPDUMP_PID}" 2>/dev/null || true
    wait_for_pid_exit "${TCPDUMP_PID}" 5 || true
    if kill -0 "${TCPDUMP_PID}" 2>/dev/null; then
      kill -9 "${TCPDUMP_PID}" 2>/dev/null || true
      wait_for_pid_exit "${TCPDUMP_PID}" 2 || true
    fi
  fi
  TCPDUMP_PID=""
}

cleanup() {
  stop_server
  stop_tcpdump
  if [[ -n "${TMP_CERT_DIR:-}" && -d "${TMP_CERT_DIR}" ]]; then
    rm -rf "${TMP_CERT_DIR}"
  fi
}
trap cleanup EXIT

need_cmd tcpdump
need_cmd openssl
need_cmd rg
need_cmd sha256sum

TS="$(date -u +%Y%m%d_%H%M%S)"
ART_DIR="demo_artifacts/${TS}"
mkdir -p "${ART_DIR}"

PCAP="${ART_DIR}/fr02_tls13.pcap"
PROOF_JSON="${ART_DIR}/fr02_tls13_proof.json"
OPENSSL_CLIENT_LOG="${ART_DIR}/openssl_client.out"
SERVER_LOG="${ART_DIR}/openssl_server.out"
TCPDUMP_LOG="${ART_DIR}/tcpdump.out"

TMP_CERT_DIR="$(mktemp -d -t fr02_tls13_pcap.XXXXXX)"
CERT_PATH="${TMP_CERT_DIR}/cert.pem"
KEY_PATH="${TMP_CERT_DIR}/key.pem"

openssl req -x509 -newkey rsa:2048 -keyout "${KEY_PATH}" -out "${CERT_PATH}" \
  -days 1 -nodes -subj "/CN=localhost" >/dev/null 2>&1

if [[ -n "${FR02_TLS13_PORT:-}" ]]; then
  PORT="${FR02_TLS13_PORT}"
else
  PORT="$(find_free_port 18443)" || fail_with_context "unable to find free port from 18443"
fi

tcpdump -i lo -w "${PCAP}" -U -n "tcp port ${PORT}" >"${TCPDUMP_LOG}" 2>&1 &
TCPDUMP_PID=$!
sleep 0.7
if ! kill -0 "${TCPDUMP_PID}" 2>/dev/null; then
  fail_with_context "tcpdump failed to start on lo for port ${PORT}"
fi

openssl s_server -tls1_3 -accept "${PORT}" -cert "${CERT_PATH}" -key "${KEY_PATH}" \
  -quiet >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
sleep 0.6
if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
  fail_with_context "openssl s_server failed to start on port ${PORT}"
fi

client_rc=0
if ! timeout 10 openssl s_client -tls1_3 -connect "127.0.0.1:${PORT}" -servername localhost \
  < /dev/null >"${OPENSSL_CLIENT_LOG}" 2>&1; then
  client_rc=$?
fi

negotiated_protocol="$(sed -n 's/^[[:space:]]*Protocol[[:space:]]*:[[:space:]]*\(.*\)$/\1/p' "${OPENSSL_CLIENT_LOG}" | head -n 1 | tr -d '\r' || true)"
if [[ -z "${negotiated_protocol}" ]] && rg -q "TLSv1\\.3" "${OPENSSL_CLIENT_LOG}"; then
  negotiated_protocol="TLSv1.3"
fi
if [[ "${negotiated_protocol}" != "TLSv1.3" ]]; then
  fail_with_context "expected negotiated protocol TLSv1.3 (client_rc=${client_rc})"
fi

stop_server
sleep 0.3
stop_tcpdump

[[ -f "${PCAP}" ]] || fail_with_context "pcap missing at ${PCAP}"
pcap_size_bytes="$(stat -c '%s' "${PCAP}")"
if [[ "${pcap_size_bytes}" -le 0 ]]; then
  fail_with_context "pcap is empty: ${PCAP}"
fi
pcap_sha256="$(sha256sum "${PCAP}" | awk '{print $1}')"
[[ -n "${pcap_sha256}" ]] || fail_with_context "failed to compute pcap sha256"

tshark_present=false
tls13_confirmed_by="openssl_only"
if command -v tshark >/dev/null 2>&1; then
  tshark_present=true
  TSHARK_LOG="${ART_DIR}/tshark_tls_decode.out"
  if tshark -r "${PCAP}" -d "tcp.port==${PORT},tls" -V >"${TSHARK_LOG}" 2>/dev/null \
    && rg -q "TLSv1\\.3|TLS 1\\.3|supported_versions.*0x0304|0x0304" "${TSHARK_LOG}"; then
    tls13_confirmed_by="tshark"
  else
    fail_with_context "tshark present but TLS 1.3 not detected in pcap"
  fi
fi

USER_NAME="${SUDO_USER:-$USER}"
GROUP_NAME="$(id -gn "$USER_NAME" 2>/dev/null || echo "$USER_NAME")"
TARGET_OWNER="${USER_NAME}:${GROUP_NAME}"
ownership_normalized=true

if [[ "$(id -u)" -eq 0 ]]; then
  chown -R "${TARGET_OWNER}" "${ART_DIR}" 2>/dev/null || ownership_normalized=false
fi
if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
  sudo chown -R "${TARGET_OWNER}" "${ART_DIR}" 2>/dev/null || ownership_normalized=false
fi
chmod -R u+rwX "${ART_DIR}" 2>/dev/null || true

artifact_owner="$(stat -c '%U:%G' "${ART_DIR}" 2>/dev/null || echo "${TARGET_OWNER}")"
pcap_owner="$(stat -c '%U:%G' "${PCAP}" 2>/dev/null || echo "${TARGET_OWNER}")"
if [[ "${pcap_owner}" != "${TARGET_OWNER}" ]] || [[ "${ownership_normalized}" != "true" ]]; then
  echo "WARN: could_not_normalize_artifact_ownership expected=${TARGET_OWNER} actual_artifact=${artifact_owner} actual_pcap=${pcap_owner}" >&2
fi

cat > "${PROOF_JSON}" <<EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "interface": "lo",
  "port": ${PORT},
  "pcap_path": "${PCAP}",
  "pcap_size_bytes": ${pcap_size_bytes},
  "pcap_sha256": "${pcap_sha256}",
  "openssl_client_log": "${OPENSSL_CLIENT_LOG}",
  "negotiated_protocol": "$(json_escape "${negotiated_protocol}")",
  "tshark_present": ${tshark_present},
  "tls13_confirmed_by": "${tls13_confirmed_by}",
  "artifact_owner": "$(json_escape "${artifact_owner}")",
  "pcap_owner": "$(json_escape "${pcap_owner}")",
  "pass": true
}
EOF

# Final ownership normalization after writing proof JSON so the whole artifact
# directory (pcap + logs + proof) is user-owned when possible.
post_ownership_normalized=true
if [[ "$(id -u)" -eq 0 ]]; then
  chown -R "${TARGET_OWNER}" "${ART_DIR}" 2>/dev/null || post_ownership_normalized=false
fi
if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
  sudo chown -R "${TARGET_OWNER}" "${ART_DIR}" 2>/dev/null || post_ownership_normalized=false
fi
chmod -R u+rwX "${ART_DIR}" 2>/dev/null || true

if [[ "${post_ownership_normalized}" != "true" ]]; then
  proof_owner="$(stat -c '%U:%G' "${PROOF_JSON}" 2>/dev/null || echo "unknown")"
  echo "WARN: could_not_normalize_artifact_ownership_after_proof expected=${TARGET_OWNER} proof_owner=${proof_owner}" >&2
fi

echo "PASS: FR-02 TLS1.3 pcap completed"
echo "FR02_TLS13_PCAP_PROOF_JSON=${PROOF_JSON}"
