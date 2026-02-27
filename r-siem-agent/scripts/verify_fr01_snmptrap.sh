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

need_cmd go
need_cmd rg
need_cmd jq
need_cmd snmptrap
need_cmd nats

TS="$(date -u +%Y%m%d_%H%M%S)"
ART_DIR="demo_artifacts/${TS}"
mkdir -p "$ART_DIR" logs .pids .cache/go-build tmp
PROOF_JSON="${ART_DIR}/fr01_snmptrap_proof.json"
LOG_FILE="logs/collector-snmptrap.log"

collector_pid=""
cleanup() {
  if [[ -n "${collector_pid}" ]] && kill -0 "${collector_pid}" 2>/dev/null; then
    kill "${collector_pid}" >/dev/null 2>&1 || true
    wait "${collector_pid}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

./scripts/demo_down.sh >/dev/null 2>&1 || true
./scripts/demo_up.sh >/dev/null

: > "$LOG_FILE"
GOCACHE="$ROOT_DIR/.cache/go-build" go run -mod=vendor ./cmd/collector-snmptrap --config configs/collector-snmptrap.yaml >> "$LOG_FILE" 2>&1 &
collector_pid=$!
sleep 1
if ! kill -0 "$collector_pid" 2>/dev/null; then
  echo "FAIL: collector-snmptrap failed to start" >&2
  tail -n 80 "$LOG_FILE" >&2 || true
  exit 1
fi

published_before="$(rg -c '"msg":"collector_event_published".*"collector":"snmp_trap"' "$LOG_FILE" || true)"
published_before="${published_before:-0}"

count_sent=0
for i in $(seq 1 20); do
  snmptrap -v 2c -c public 127.0.0.1:9162 123 \
    .1.3.6.1.6.3.1.1.5.1 \
    .1.3.6.1.2.1.1.1.0 s "rsiem-snmptrap-test-i=${i}" >/dev/null
  count_sent=$((count_sent + 1))
  sleep 0.02
done

published_after="$published_before"
for _ in $(seq 1 40); do
  published_after="$(rg -c '"msg":"collector_event_published".*"collector":"snmp_trap"' "$LOG_FILE" || true)"
  published_after="${published_after:-0}"
  if (( published_after - published_before >= count_sent )); then
    break
  fi
  sleep 0.5
done

published_delta=$(( published_after - published_before ))
if (( published_delta < count_sent )); then
  echo "FAIL: snmptrap collector published ${published_delta}, expected >= ${count_sent}" >&2
  tail -n 120 "$LOG_FILE" >&2 || true
  exit 1
fi

sample_line="$(rg '"msg":"collector_event_published".*"collector":"snmp_trap"' "$LOG_FILE" | head -n 1 || true)"
if [[ -z "$sample_line" ]]; then
  echo "FAIL: missing collector_event_published sample line" >&2
  exit 1
fi

sample_src_ip="$(printf '%s\n' "$sample_line" | sed -n 's/.*"src_ip":"\([^"]*\)".*/\1/p' | head -n1)"
sample_raw_len="$(printf '%s\n' "$sample_line" | sed -n 's/.*"raw_len":\([0-9]\+\).*/\1/p' | head -n1)"
sample_raw_sha256="$(printf '%s\n' "$sample_line" | sed -n 's/.*"raw_sha256":"\([0-9a-f]\+\)".*/\1/p' | head -n1)"
sample_community="$(printf '%s\n' "$sample_line" | sed -n 's/.*"community":"\([^"]*\)".*/\1/p' | head -n1)"

sample_src_ip="${sample_src_ip:-}"
sample_raw_len="${sample_raw_len:-0}"
sample_raw_sha256="${sample_raw_sha256:-}"
sample_community="${sample_community:-}"

cat > "$PROOF_JSON" <<JSON
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "bind": "127.0.0.1:9162",
  "count_sent": ${count_sent},
  "count_published": ${published_delta},
  "sample": {
    "src_ip": "${sample_src_ip}",
    "raw_len": ${sample_raw_len},
    "raw_sha256": "${sample_raw_sha256}",
    "community": "${sample_community}"
  },
  "store_boundary": "logs/collector-snmptrap.log collector_event_published",
  "pass": true
}
JSON

echo "PASS: FR-01 snmptrap streaming completed"
echo "FR01_SNMPTRAP_PROOF_JSON=${PROOF_JSON}"
