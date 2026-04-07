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
need_cmd python3

TS="$(date -u +%Y%m%d_%H%M%S)"
ART_DIR="demo_artifacts/${TS}"
mkdir -p "$ART_DIR" logs .pids .cache/go-build tmp
PROOF_JSON="${ART_DIR}/fr01_syslog_proof.json"
LOG_FILE="logs/collector-syslog.log"

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
GOCACHE="$ROOT_DIR/.cache/go-build" go run -mod=vendor ./cmd/collector-syslog --config configs/collector-syslog.yaml >> "$LOG_FILE" 2>&1 &
collector_pid=$!
sleep 1
if ! kill -0 "$collector_pid" 2>/dev/null; then
  echo "FAIL: collector-syslog failed to start" >&2
  tail -n 80 "$LOG_FILE" >&2 || true
  exit 1
fi

published_before="$(rg -c '"msg":"collector_event_published".*"collector":"syslog"' "$LOG_FILE" || true)"
published_before="${published_before:-0}"

run_tag="$(date +%H%M%S)"
user_prefix="fr01sys${run_tag}_"
count_sent=35
count_expected_min=30
latency_samples_min=30
for i in $(seq 1 "$count_sent"); do
  ts_ms=$(( $(date +%s%3N) + i ))
  src_oct=$(( (i % 200) + 20 ))
  user="${user_prefix}$(printf '%02d' "$i")"
  msg="<14>Jan 01 00:00:00 demohost sshd[123]: Failed password for invalid user ${user} from 10.66.0.${src_oct} port 22 ssh2 ts=${ts_ms}"
  printf '%s\n' "$msg" > /dev/udp/127.0.0.1/5140
  sleep 0.02
done

published_after="$published_before"
for _ in $(seq 1 40); do
  published_after="$(rg -c '"msg":"collector_event_published".*"collector":"syslog"' "$LOG_FILE" || true)"
  published_after="${published_after:-0}"
  if (( published_after - published_before >= count_expected_min )); then
    break
  fi
  sleep 0.5
done

published_delta=$(( published_after - published_before ))
if (( published_delta < count_expected_min )); then
  echo "FAIL: syslog collector published ${published_delta}, expected >= ${count_expected_min}" >&2
  tail -n 120 "$LOG_FILE" >&2 || true
  exit 1
fi

lat_file="${ART_DIR}/fr01_syslog_latencies.txt"
for _ in $(seq 1 30); do
  rg '"msg":"detector_rule_matched"' logs/detector.log \
    | rg "\"user\":\"${user_prefix}" \
    | sed -n 's/.*"latency_ms":\([0-9]\+\).*/\1/p' > "$lat_file" || true
  latency_count_now="$(wc -l < "$lat_file" | tr -d '[:space:]')"
  latency_count_now="${latency_count_now:-0}"
  if (( latency_count_now >= latency_samples_min )); then
    break
  fi
  sleep 1
done

read -r latency_count p50_latency_ms p95_latency_ms max_latency_ms <<PYOUT
$(python3 - "$lat_file" <<'PY'
import sys
path = sys.argv[1]
vals = []
try:
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            vals.append(int(line))
except FileNotFoundError:
    pass
vals.sort()
if not vals:
    print('0 0 0 0')
    raise SystemExit(0)
idx50 = max(0, int((len(vals) * 0.50) - 1))
idx95 = max(0, int((len(vals) * 0.95) - 1))
print(f"{len(vals)} {vals[idx50]} {vals[idx95]} {vals[-1]}")
PY
)
PYOUT

if (( latency_count < latency_samples_min )); then
  echo "FAIL: insufficient detector latency evidence for syslog test run" >&2
  rg '"msg":"detector_rule_matched"' logs/detector.log | tail -n 80 >&2 || true
  exit 1
fi
if (( p95_latency_ms > 5000 )); then
  echo "FAIL: syslog p95 latency ${p95_latency_ms}ms exceeds 5000ms" >&2
  exit 1
fi

cat > "$PROOF_JSON" <<JSON
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "bind": "127.0.0.1:5140",
  "count_sent": ${count_sent},
  "count_published": ${published_delta},
  "latency_ms": {
    "count": ${latency_count},
    "p50": ${p50_latency_ms},
    "p95": ${p95_latency_ms},
    "max": ${max_latency_ms}
  },
  "store_boundary": "logs/detector.log detector_rule_matched",
  "pass": true
}
JSON

echo "PASS: FR-01 syslog streaming completed"
echo "FR01_SYSLOG_PROOF_JSON=${PROOF_JSON}"
