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

fail_with_context() {
  local msg="$1"
  echo "FAIL: ${msg}" >&2
  echo "Context: detector (last 150)" >&2
  tail -n 150 logs/detector.log >&2 || true
  exit 1
}

need_cmd rg
need_cmd go
need_cmd python3
need_cmd date

echo "=== FR-01 full proposal verification ==="

scale_out="$(./scripts/verify_fr01_scale15.sh)"
printf '%s\n' "$scale_out"
scale_proof="$(printf '%s\n' "$scale_out" | sed -n 's/^FR01_SCALE15_PROOF_JSON=//p' | tail -n 1)"
[[ -n "$scale_proof" && -f "$scale_proof" ]] || fail_with_context "missing FR01 scale proof path"

source_out="$(./scripts/verify_fr01_source_types.sh)"
printf '%s\n' "$source_out"
source_proof="$(printf '%s\n' "$source_out" | sed -n 's/^FR01_SOURCE_TYPES_PROOF_JSON=//p' | tail -n 1)"
[[ -n "$source_proof" && -f "$source_proof" ]] || fail_with_context "missing FR01 source types proof path"

detector_log="logs/detector.log"
[[ -f "$detector_log" ]] || fail_with_context "missing ${detector_log}"
base_detector_lines="$(wc -l < "$detector_log" | tr -d '[:space:]')"

latency_token="fr01lat$(date +%s)"
sample_target=60
base_ms="$(date +%s%3N)"

for i in $(seq 1 "$sample_target"); do
  src_ip="10.79.$((i / 250)).$((i % 250 + 1))"
  ts_ms="$((base_ms + i))"
  printf 'FAILED login user=%s_%02d src=%s ts=%s\n' "$latency_token" "$i" "$src_ip" "$ts_ms" >> tmp/demo.log
done

for _ in $(seq 1 160); do
  observed="$(
    tail -n "+$((base_detector_lines + 1))" "$detector_log" 2>/dev/null \
      | rg -c "\"msg\":\"detector_rule_matched\".*\"rule_id\":\"R-COLLECT-INVALID-USER\".*\"user\":\"${latency_token}_" || true
  )"
  observed="${observed:-0}"
  if (( observed >= sample_target )); then
    break
  fi
  sleep 0.25
done

artifact_ts="$(date +%Y%m%d_%H%M%S)"
artifact_dir="demo_artifacts/${artifact_ts}"
mkdir -p "$artifact_dir"
retained_dir="${artifact_dir}/retained_latency"
mkdir -p "$retained_dir"

go run -mod=vendor ./cmd/retention-query ingest \
  --retained_dir "$retained_dir" \
  --runs_path exports/roe_runs.jsonl \
  --steps_path exports/roe_steps.jsonl \
  --detector_log logs/detector.log \
  --collector_log logs/collector.log \
  --master_log logs/master-roe.log \
  --max_age_seconds 86400 \
  --max_bytes $((50 * 1024 * 1024)) >/tmp/fr01_full_ingest.out

latency_records="${artifact_dir}/fr01_latency_alerts.jsonl"
latency_summary="${artifact_dir}/fr01_latency_alerts_summary.json"
go run -mod=vendor ./cmd/retention-query query \
  --retained_dir "$retained_dir" \
  --type alerts \
  --contains "$latency_token" \
  --out "$latency_records" \
  --summary_out "$latency_summary" >/tmp/fr01_full_query.out

proof_json="${artifact_dir}/fr01_full_proof.json"
python3 - "$latency_records" "$proof_json" "$scale_proof" "$source_proof" "$sample_target" <<'PY'
import json
import math
import sys
from pathlib import Path

latency_records = Path(sys.argv[1])
proof_path = Path(sys.argv[2])
scale_proof = sys.argv[3]
source_proof = sys.argv[4]
sample_target = int(sys.argv[5])

latencies = []
with latency_records.open("r", encoding="utf-8") as f:
    for raw in f:
        raw = raw.strip()
        if not raw:
            continue
        rec = json.loads(raw)
        inner = rec.get("line", "")
        if not inner:
            continue
        try:
            detector_line = json.loads(inner)
        except json.JSONDecodeError:
            continue
        evt = int(detector_line.get("event_ts_unix_ms", 0) or 0)
        alert = int(detector_line.get("alert_ts_unix_ms", 0) or 0)
        if evt <= 0 or alert <= 0:
            continue
        lat = alert - evt
        if lat < 0:
            lat = 0
        latencies.append(lat)

if len(latencies) < sample_target:
    raise SystemExit(f"insufficient latency sample size: got={len(latencies)} want>={sample_target}")

latencies.sort()
n = len(latencies)

def percentile(vals, p):
    idx = max(0, min(len(vals) - 1, math.ceil(p * len(vals)) - 1))
    return int(vals[idx])

p50 = percentile(latencies, 0.50)
p95 = percentile(latencies, 0.95)
max_v = int(latencies[-1])

if p95 > 5000:
    raise SystemExit(f"latency p95 too high: {p95}ms > 5000ms")

proof = {
    "timestamp": __import__("datetime").datetime.now(__import__("datetime").UTC).replace(tzinfo=None, microsecond=0).isoformat() + "Z",
    "scale15_proof": scale_proof,
    "source_types_proof": source_proof,
    "latency_ms": {
        "count": n,
        "p50": p50,
        "p95": p95,
        "max": max_v,
    },
    "store_boundary": "retained/alerts.jsonl (ingested from logs/detector.log detector_rule_matched)",
    "pass": True,
}
proof_path.write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")
PY

echo "PASS: FR-01 full suite completed"
echo "FR01_FULL_PROOF_JSON=${proof_json}"
