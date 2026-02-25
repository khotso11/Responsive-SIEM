#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

LOG_DETECTOR="logs/detector.log"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "FAIL: missing command: $1" >&2
    exit 1
  }
}

tail_from() {
  local file="$1"
  local base="$2"
  tail -n "+$((base + 1))" "$file" 2>/dev/null || true
}

fail_with_context() {
  local msg="$1"
  echo "FAIL: ${msg}" >&2
  echo "Context: detector tail" >&2
  tail -n 120 "$LOG_DETECTOR" >&2 || true
  exit 1
}

need_cmd rg
need_cmd date
need_cmd python3

mkdir -p logs tmp demo_artifacts
: > tmp/demo.log
rm -f tmp/tail.checkpoint.json

./scripts/demo_down.sh >/dev/null 2>&1 || true
pkill -f 'cmd/collector-tail|/collector-tail' >/dev/null 2>&1 || true
pkill -f 'cmd/detector-v0|/detector-v0' >/dev/null 2>&1 || true
pkill -f 'cmd/master-roe-worker|/master-roe-worker' >/dev/null 2>&1 || true
pkill -f 'cmd/agent|/agent' >/dev/null 2>&1 || true
pkill -f 'cmd/master-roe([^[:alnum:]_-]|$)|/master-roe([^[:alnum:]_-]|$)' >/dev/null 2>&1 || true
sleep 1
./scripts/demo_up.sh >/dev/null

[[ -f "$LOG_DETECTOR" ]] || fail_with_context "missing ${LOG_DETECTOR}"

base_detector="$(wc -l < "$LOG_DETECTOR" | tr -d '[:space:]')"
run_ts="$(date +%Y%m%d_%H%M%S)"
artifact_dir="demo_artifacts/${run_ts}"
mkdir -p "$artifact_dir"
proof_json="${artifact_dir}/fr03_latency_proof.json"
alerts_lines_file="${artifact_dir}/fr03_alert_lines.jsonl"

host_rule_id="R-FR03-HOST-BRUTEFORCE-BURST"
network_rule_id="R-FR03-NETWORK-C2-BEACON"
deception_rule_id="R-FR03-DECEPTION-TRIPWIRE"

sample_per_category="${FR03_SAMPLE_PER_CATEGORY:-20}"
if ! [[ "$sample_per_category" =~ ^[0-9]+$ ]] || (( sample_per_category <= 0 )); then
  fail_with_context "FR03_SAMPLE_PER_CATEGORY must be a positive integer"
fi
sample_target=$((sample_per_category * 3))
minimum_count=60
if (( sample_target < minimum_count )); then
  minimum_count="$sample_target"
fi

now_ms="$(date +%s%3N)"
base_octet=$(( (now_ms / 1000) % 200 + 20 ))

for ((i = 0; i < sample_per_category; i++)); do
  host_ip="10.66.10.$((base_octet + i))"
  network_ip="10.66.11.$((base_octet + i))"
  deception_ip="10.66.12.$((base_octet + i))"
  host_ts_base=$((now_ms + (i * 10)))
  network_ts=$((now_ms + (sample_per_category * 10) + (i * 10)))
  deception_ts=$((now_ms + (sample_per_category * 20) + (i * 10)))

  # FR-03 host burst rule triggers when threshold=3 is reached per source key.
  for burst in 0 1 2; do
    printf 'ALERT invalid user=bf src=%s attack=host_bruteforce ts=%s\n' \
      "$host_ip" "$((host_ts_base + burst))" >> tmp/demo.log
  done
  printf 'ALERT invalid user=scanner src=%s attack=network_scan ts=%s\n' \
    "$network_ip" "$network_ts" >> tmp/demo.log
  printf 'ALERT invalid user=honeypot src=%s attack=deception_tripwire ts=%s\n' \
    "$deception_ip" "$deception_ts" >> tmp/demo.log
done

host_count=0
network_count=0
deception_count=0
alerts_total=0
for _ in $(seq 1 200); do
  tail_new="$(tail_from "$LOG_DETECTOR" "$base_detector")"
  host_count="$(printf '%s\n' "$tail_new" | rg -c "\"msg\":\"detector_alert_published\".*\"rule_id\":\"${host_rule_id}\"" || true)"
  network_count="$(printf '%s\n' "$tail_new" | rg -c "\"msg\":\"detector_alert_published\".*\"rule_id\":\"${network_rule_id}\"" || true)"
  deception_count="$(printf '%s\n' "$tail_new" | rg -c "\"msg\":\"detector_alert_published\".*\"rule_id\":\"${deception_rule_id}\"" || true)"
  host_count="${host_count:-0}"
  network_count="${network_count:-0}"
  deception_count="${deception_count:-0}"
  alerts_total=$((host_count + network_count + deception_count))
  if (( host_count >= sample_per_category && network_count >= sample_per_category && deception_count >= sample_per_category && alerts_total >= minimum_count )); then
    break
  fi
  sleep 0.2
done

tail_new="$(tail_from "$LOG_DETECTOR" "$base_detector")"
printf '%s\n' "$tail_new" \
  | rg '"msg":"detector_alert_published"' \
  | rg "\"rule_id\":\"(${host_rule_id}|${network_rule_id}|${deception_rule_id})\"" \
  > "$alerts_lines_file"

host_count="$(rg -c "\"rule_id\":\"${host_rule_id}\"" "$alerts_lines_file" || true)"
network_count="$(rg -c "\"rule_id\":\"${network_rule_id}\"" "$alerts_lines_file" || true)"
deception_count="$(rg -c "\"rule_id\":\"${deception_rule_id}\"" "$alerts_lines_file" || true)"
host_count="${host_count:-0}"
network_count="${network_count:-0}"
deception_count="${deception_count:-0}"
alerts_total=$((host_count + network_count + deception_count))

if (( host_count < sample_per_category || network_count < sample_per_category || deception_count < sample_per_category || alerts_total < minimum_count )); then
  fail_with_context "insufficient FR-03 alert sample (host=${host_count} network=${network_count} deception=${deception_count} total=${alerts_total} min_total=${minimum_count})"
fi

python3 - "$alerts_lines_file" "$proof_json" "$minimum_count" "$sample_target" <<'PY'
import datetime
import json
import math
import sys

lines_path = sys.argv[1]
proof_path = sys.argv[2]
minimum_count = int(sys.argv[3])
sample_target = int(sys.argv[4])

expected = [
    "R-FR03-HOST-BRUTEFORCE-BURST",
    "R-FR03-NETWORK-C2-BEACON",
    "R-FR03-DECEPTION-TRIPWIRE",
]
expected_sev = {
    "R-FR03-HOST-BRUTEFORCE-BURST": "high",
    "R-FR03-NETWORK-C2-BEACON": "high",
    "R-FR03-DECEPTION-TRIPWIRE": "critical",
}

alerts = []
with open(lines_path, "r", encoding="utf-8") as f:
    for raw in f:
        raw = raw.strip()
        if not raw:
            continue
        rec = json.loads(raw)
        if rec.get("rule_id", "") in expected:
            alerts.append(rec)

by_rule = {rid: [] for rid in expected}
for rec in alerts:
    by_rule[rec["rule_id"]].append(rec)

missing = [rid for rid in expected if not by_rule[rid]]
if missing:
    raise SystemExit(f"missing expected rule alerts: {','.join(missing)}")

for rid in expected:
    for rec in by_rule[rid]:
        sev = str(rec.get("severity", "")).strip().lower()
        if sev != expected_sev[rid]:
            raise SystemExit(f"severity mismatch for {rid}: got={sev} want={expected_sev[rid]}")
        if int(rec.get("event_ts_unix_ms", 0)) <= 0:
            raise SystemExit(f"missing event_ts_unix_ms for {rid}")
        if int(rec.get("alert_ts_unix_ms", 0)) <= 0:
            raise SystemExit(f"missing alert_ts_unix_ms for {rid}")

latencies = [max(0, int(rec.get("latency_ms", 0))) for rec in alerts]
latencies.sort()
n = len(latencies)
if n < minimum_count:
    raise SystemExit(f"insufficient latency sample size: {n} < {minimum_count}")

def percentile(sorted_vals, p):
    idx = max(0, min(len(sorted_vals) - 1, math.ceil(p * len(sorted_vals)) - 1))
    return int(sorted_vals[idx])

p50 = percentile(latencies, 0.50)
p95 = percentile(latencies, 0.95)
max_v = int(latencies[-1])

if p95 > 1000:
    raise SystemExit(f"latency p95 too high: {p95}ms > 1000ms")

proof = {
    "timestamp": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "alerts_expected": expected,
    "alerts_observed": expected,
    "severities": {rid: expected_sev[rid] for rid in expected},
    "latency_ms": {
        "count": n,
        "p50": p50,
        "p95": p95,
        "max": max_v,
    },
    "sample_target": sample_target,
    "sample_observed": n,
    "pass": True,
}

with open(proof_path, "w", encoding="utf-8") as f:
    json.dump(proof, f, indent=2)
    f.write("\n")
PY

echo "PASS: FR-03 correlation+severity+latency completed"
echo "FR03_PROOF_JSON=${proof_json}"
