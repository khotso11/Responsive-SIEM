#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

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
  local file="${2:-}"
  echo "FAIL: ${msg}" >&2
  if [[ -n "$file" && -f "$file" ]]; then
    echo "Context: tail -n 80 ${file}" >&2
    tail -n 80 "$file" >&2 || true
  fi
  exit 1
}

require_cmd() {
  local name="$1"
  command -v "$name" >/dev/null 2>&1 || fail_with_context "required command not found: ${name}"
}

pick_port() {
  local port
  for port in $(seq 18080 18090); do
    if ! ss -ltn | awk '{print $4}' | rg -q "(^|:)${port}$"; then
      echo "$port"
      return 0
    fi
  done
  return 1
}

TCPDUMP_PID=""
HONEYPOT_PID=""
CAPTURE_STOPPED=0
CAPTURE_END_RFC3339=""
TCPDUMP_MODE="host"
TCPDUMP_CONTAINER_NAME=""

stop_capture() {
  if [[ "${CAPTURE_STOPPED}" -eq 1 ]]; then
    return 0
  fi
  CAPTURE_STOPPED=1
  if [[ -n "${TCPDUMP_PID}" ]] && kill -0 "${TCPDUMP_PID}" >/dev/null 2>&1; then
    kill -INT "${TCPDUMP_PID}" >/dev/null 2>&1 || true
    wait "${TCPDUMP_PID}" >/dev/null 2>&1 || true
  fi
  if [[ "${TCPDUMP_MODE}" == "docker" && -n "${TCPDUMP_CONTAINER_NAME}" ]]; then
    docker kill "${TCPDUMP_CONTAINER_NAME}" >/dev/null 2>&1 || true
    docker rm -f "${TCPDUMP_CONTAINER_NAME}" >/dev/null 2>&1 || true
  fi
  CAPTURE_END_RFC3339="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}

cleanup() {
  if [[ -n "${HONEYPOT_PID}" ]] && kill -0 "${HONEYPOT_PID}" >/dev/null 2>&1; then
    kill "${HONEYPOT_PID}" >/dev/null 2>&1 || true
    wait "${HONEYPOT_PID}" >/dev/null 2>&1 || true
  fi
  stop_capture
}
trap cleanup EXIT

require_cmd tcpdump
require_cmd sha256sum
require_cmd python3
require_cmd curl
require_cmd go
require_cmd ss
require_cmd rg

USER_NAME="${SUDO_USER:-${USER:-}}"
if [[ -z "${USER_NAME}" ]]; then
  USER_NAME="$(id -un 2>/dev/null || true)"
fi
[[ -n "${USER_NAME}" ]] || USER_NAME="unknown"
GROUP_NAME="$(id -gn "${USER_NAME}" 2>/dev/null || true)"

tcpdump_version="$(tcpdump --version 2>&1 | head -n 1)"
if [[ -z "${tcpdump_version}" ]]; then
  fail_with_context "unable to read tcpdump version"
fi

mkdir -p demo_artifacts
timestamp="$(date +%Y%m%d_%H%M%S)"
fr04_dir="demo_artifacts/${timestamp}/fr04"
mkdir -p "${fr04_dir}"
host_name="$(hostname)"

pcap_path="${fr04_dir}/capture.pcap"
custody_path="${fr04_dir}/chain_of_custody.json"
proof_path="${fr04_dir}/fr04_proof.json"
tcpdump_log="${fr04_dir}/tcpdump.log"
honeypot_log="${fr04_dir}/honeypot.log"
honeypot_bin="${fr04_dir}/honeypot"
honeypot_config="${fr04_dir}/honeypot.yaml"

./scripts/demo_down.sh >/dev/null 2>&1 || true
./scripts/demo_up.sh >/dev/null

for _ in $(seq 1 40); do
  [[ -f "logs/detector.log" ]] && break
  sleep 0.25
done
[[ -f "logs/detector.log" ]] || fail_with_context "logs/detector.log not found after demo_up"
base_detector_lines="$(wc -l < logs/detector.log | tr -d '[:space:]')"
[[ -f "logs/master-roe.log" ]] || fail_with_context "logs/master-roe.log not found after demo_up"
base_master_lines="$(wc -l < logs/master-roe.log | tr -d '[:space:]')"

capture_start_rfc3339="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

start_tcpdump_host() {
  TCPDUMP_MODE="host"
  tcpdump -i lo -w "${pcap_path}" -U -n -Z "${USER_NAME}" 'tcp' >"${tcpdump_log}" 2>&1 &
  TCPDUMP_PID="$!"
  sleep 1
  kill -0 "${TCPDUMP_PID}" >/dev/null 2>&1
}

start_tcpdump_docker() {
  require_cmd docker
  TCPDUMP_MODE="docker"
  TCPDUMP_CONTAINER_NAME="fr04-tcpdump-${timestamp}"
  docker run --rm --name "${TCPDUMP_CONTAINER_NAME}" \
    --network host --cap-add NET_ADMIN --cap-add NET_RAW \
    -v "${ROOT_DIR}/${fr04_dir}:/fr04" \
    nicolaka/netshoot tcpdump -i lo -w /fr04/capture.pcap -U -n 'tcp' >"${tcpdump_log}" 2>&1 &
  TCPDUMP_PID="$!"
  sleep 2
  kill -0 "${TCPDUMP_PID}" >/dev/null 2>&1
}

capture_backend="${FR04_TCPDUMP_BACKEND:-auto}"
case "${capture_backend}" in
  host)
    start_tcpdump_host || fail_with_context "tcpdump failed to start" "${tcpdump_log}"
    ;;
  docker)
    start_tcpdump_docker || fail_with_context "docker tcpdump failed to start" "${tcpdump_log}"
    tcpdump_version="$(docker run --rm nicolaka/netshoot tcpdump --version 2>&1 | head -n 1)"
    ;;
  auto)
    if ! start_tcpdump_host; then
      if rg -q "Operation not permitted|You don't have permission" "${tcpdump_log}"; then
        start_tcpdump_docker || fail_with_context "docker tcpdump failed to start after host permission error" "${tcpdump_log}"
        tcpdump_version="$(docker run --rm nicolaka/netshoot tcpdump --version 2>&1 | head -n 1)"
      else
        fail_with_context "tcpdump failed to start" "${tcpdump_log}"
      fi
    fi
    ;;
  *)
    fail_with_context "invalid FR04_TCPDUMP_BACKEND=${capture_backend} (expected host|docker|auto)"
    ;;
esac

port="$(pick_port || true)"
[[ -n "${port}" ]] || fail_with_context "no free deterministic localhost port in range 18080-18090"

env GOCACHE="$ROOT_DIR/.cache/go-build" go build -mod=vendor -o "${honeypot_bin}" ./cmd/honeypot

cat > "${honeypot_config}" <<EOF_HONEYPOT
log_level: info
node_id: honeypot-local
host: honeypot-local
response_target_agent_id: ${host_name}
jetstream:
  url: nats://127.0.0.1:4222
  stream: RSIEM_EVENTS
  subject: rsiem.events.raw
  spool_path: ${fr04_dir}/honeypot.spool.jsonl
  spool_fsync: false
  retry_interval_ms: 1000
limits:
  read_timeout_ms: 2500
  write_timeout_ms: 2500
  max_payload_bytes: 2048
  max_concurrent: 16
services:
  - id: decoy-admin-http
    enabled: true
    protocol: http
    listen: 127.0.0.1:${port}
    http_title: Restricted Administration Portal
    realm: Operations Console
EOF_HONEYPOT

"${honeypot_bin}" -config "${honeypot_config}" >"${honeypot_log}" 2>&1 &
HONEYPOT_PID="$!"
sleep 1
kill -0 "${HONEYPOT_PID}" >/dev/null 2>&1 || fail_with_context "honeypot failed to start" "${honeypot_log}"

for _ in $(seq 1 20); do
  if rg -n "honeypot_service_listening.*decoy-admin-http" "${honeypot_log}" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done
rg -n "honeypot_service_listening.*decoy-admin-http" "${honeypot_log}" >/dev/null 2>&1 || fail_with_context "honeypot listen evidence not found" "${honeypot_log}"

event_ts_unix_ms="$(date +%s%3N)"
curl -sS -o /dev/null \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'X-RSIEM-Source-IP: 10.66.12.250' \
  --data 'username=honeypot-admin&password=should_not_leak' \
  "http://127.0.0.1:${port}/admin/login?probe=fr04" || fail_with_context "curl probe to honeypot failed" "${honeypot_log}"

evidence_line=""
severity=""
for _ in $(seq 1 40); do
  evidence_line="$(tail -n "+$((base_detector_lines + 1))" logs/detector.log 2>/dev/null | rg "\"msg\":\"detector_rule_matched\".*\"rule_id\":\"R-FR03-DECEPTION-TRIPWIRE\".*\"severity\":\"(critical|high)\"" | tail -n 1 || true)"
  if [[ -n "${evidence_line}" ]]; then
    severity="$(printf '%s\n' "${evidence_line}" | sed -n 's/.*"severity":"\([^"]*\)".*/\1/p')"
    break
  fi
  sleep 0.25
done

[[ -n "${evidence_line}" ]] || fail_with_context "deception alert evidence not found for ts=${event_ts_unix_ms}" "logs/detector.log"
if [[ "${severity}" != "critical" && "${severity}" != "high" ]]; then
  fail_with_context "unexpected deception severity: ${severity}" "logs/detector.log"
fi

run_line=""
for _ in $(seq 1 40); do
  run_line="$(tail -n "+$((base_master_lines + 1))" logs/master-roe.log 2>/dev/null | rg "\"msg\":\"response_run_created\".*\"rule_id\":\"R-FR03-DECEPTION-TRIPWIRE\".*\"playbook_id\":\"PB-DECEPTION-HONEYPOT-TRIAGE\"" | tail -n 1 || true)"
  if [[ -n "${run_line}" ]]; then
    break
  fi
  sleep 0.25
done
[[ -n "${run_line}" ]] || fail_with_context "response run evidence not found for honeypot playbook" "logs/master-roe.log"

stop_capture
if [[ -n "${HONEYPOT_PID}" ]] && kill -0 "${HONEYPOT_PID}" >/dev/null 2>&1; then
  kill "${HONEYPOT_PID}" >/dev/null 2>&1 || true
  wait "${HONEYPOT_PID}" >/dev/null 2>&1 || true
fi

[[ -f "${pcap_path}" ]] || fail_with_context "pcap not found at ${pcap_path}" "${tcpdump_log}"

pcap_owner_before="$(stat -c '%U:%G' "${pcap_path}" 2>/dev/null || echo "unknown:unknown")"
pcap_owner_user="${pcap_owner_before%%:*}"
if [[ "${pcap_owner_user}" != "${USER_NAME}" ]]; then
  chown_target="${USER_NAME}"
  if [[ -n "${GROUP_NAME}" ]]; then
    chown_target="${USER_NAME}:${GROUP_NAME}"
  fi
  if [[ "$(id -u)" -eq 0 ]]; then
    chown "${chown_target}" "${pcap_path}" 2>/dev/null || true
  elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    sudo chown "${chown_target}" "${pcap_path}" 2>/dev/null || true
  fi
fi
pcap_owner_after="$(stat -c '%U:%G' "${pcap_path}" 2>/dev/null || echo "unknown:unknown")"
if [[ "${pcap_owner_after%%:*}" != "${USER_NAME}" && "${TCPDUMP_MODE}" == "docker" && -n "${USER_NAME}" && "${USER_NAME}" != "unknown" ]]; then
  user_uid="$(id -u "${USER_NAME}" 2>/dev/null || true)"
  user_gid="$(id -g "${USER_NAME}" 2>/dev/null || true)"
  if [[ -n "${user_uid}" && -n "${user_gid}" ]]; then
    docker run --rm -v "${ROOT_DIR}/${fr04_dir}:/fr04" nicolaka/netshoot sh -c "chown ${user_uid}:${user_gid} /fr04/capture.pcap" >/dev/null 2>&1 || true
  fi
fi
chmod u+rw "${pcap_path}" 2>/dev/null || true
pcap_owner_after="$(stat -c '%U:%G' "${pcap_path}" 2>/dev/null || echo "unknown:unknown")"
if [[ "${pcap_owner_after%%:*}" != "${USER_NAME}" ]]; then
  echo "WARN: could_not_chown_pcap owner_before=${pcap_owner_before} owner_after=${pcap_owner_after} target_user=${USER_NAME}" >&2
fi

pcap_size_bytes="$(stat -c '%s' "${pcap_path}")"
[[ "${pcap_size_bytes}" -gt 0 ]] || fail_with_context "pcap is empty: ${pcap_path}" "${tcpdump_log}"
pcap_sha256="$(sha256sum "${pcap_path}" | awk '{print $1}')"
[[ -n "${pcap_sha256}" ]] || fail_with_context "failed to compute pcap sha256"

generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cat > "${custody_path}" <<EOF_CUSTODY
{
  "timestamp": "$(json_escape "${generated_at}")",
  "host": "$(json_escape "${host_name}")",
  "interface": "lo",
  "capture_start_rfc3339": "$(json_escape "${capture_start_rfc3339}")",
  "capture_end_rfc3339": "$(json_escape "${CAPTURE_END_RFC3339}")",
  "tcpdump_version": "$(json_escape "${tcpdump_version}")",
  "pcap_path": "$(json_escape "${pcap_path}")",
  "pcap_owner": "$(json_escape "${pcap_owner_after}")",
  "pcap_size_bytes": ${pcap_size_bytes},
  "pcap_sha256": "$(json_escape "${pcap_sha256}")",
  "case_link": {
    "rule_id": "R-FR03-DECEPTION-TRIPWIRE",
    "severity": "$(json_escape "${severity}")",
    "evidence_log": "logs/detector.log",
    "evidence_line": "$(json_escape "${evidence_line}")",
    "run_evidence_log": "logs/master-roe.log",
    "run_evidence_line": "$(json_escape "${run_line}")"
  }
}
EOF_CUSTODY

cat > "${proof_path}" <<EOF_PROOF
{
  "timestamp": "$(json_escape "${generated_at}")",
  "pcap_path": "$(json_escape "${pcap_path}")",
  "chain_of_custody_path": "$(json_escape "${custody_path}")",
  "pcap_sha256": "$(json_escape "${pcap_sha256}")",
  "pcap_size_bytes": ${pcap_size_bytes},
  "alert_rule_id": "R-FR03-DECEPTION-TRIPWIRE",
  "severity": "$(json_escape "${severity}")",
  "detector_evidence_line": "$(json_escape "${evidence_line}")",
  "run_evidence_line": "$(json_escape "${run_line}")",
  "pass": true
}
EOF_PROOF

echo "PASS: FR-04 live honeypot+pcap+chain_of_custody completed"
echo "FR04_PROOF_JSON=${proof_path}"
