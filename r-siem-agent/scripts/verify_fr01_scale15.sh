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
  echo "Context: collector (last 120)" >&2
  tail -n 120 logs/collector.log >&2 || true
  echo "Context: detector (last 120)" >&2
  tail -n 120 logs/detector.log >&2 || true
  exit 1
}

need_cmd rg
need_cmd python3
need_cmd date

echo "=== FR-01 scale<=15 verification ==="

./scripts/demo_down.sh >/dev/null 2>&1 || true
pkill -f 'cmd/collector-tail|/collector-tail' >/dev/null 2>&1 || true
pkill -f 'cmd/detector-v0|/detector-v0' >/dev/null 2>&1 || true
pkill -f 'cmd/master-roe-worker|/master-roe-worker' >/dev/null 2>&1 || true
pkill -f 'cmd/agent|/agent' >/dev/null 2>&1 || true
pkill -f 'cmd/master-roe([^[:alnum:]_-]|$)|/master-roe([^[:alnum:]_-]|$)' >/dev/null 2>&1 || true
sleep 1
mkdir -p tmp logs demo_artifacts
: > tmp/demo.log
rm -f tmp/tail.checkpoint.json
./scripts/demo_up.sh >/dev/null

collector_log="logs/collector.log"
detector_log="logs/detector.log"
[[ -f "$collector_log" ]] || fail_with_context "missing ${collector_log}"
[[ -f "$detector_log" ]] || fail_with_context "missing ${detector_log}"

base_collector_lines="$(wc -l < "$collector_log" | tr -d '[:space:]')"
base_detector_lines="$(wc -l < "$detector_log" | tr -d '[:space:]')"

node_count_expected=15
base_ms="$(date +%s%3N)"
for i in $(seq 1 "$node_count_expected"); do
  node_id="$(printf 'node-%02d' "$i")"
  src_ip="10.77.0.$((100 + i))"
  ts_ms="$((base_ms + i))"
  printf 'FAILED login user=%s src=%s ts=%s\n' "$node_id" "$src_ip" "$ts_ms" >> tmp/demo.log
done

for _ in $(seq 1 120); do
  observed_count="$(
    tail -n "+$((base_collector_lines + 1))" "$collector_log" 2>/dev/null \
      | rg -c '"msg":"collector_event_published".*"user":"node-[0-9]{2}".*"src_ip":"10\.77\.0\.[0-9]+"' || true
  )"
  observed_count="${observed_count:-0}"
  if (( observed_count >= node_count_expected )); then
    break
  fi
  sleep 0.25
done

artifact_ts="$(date +%Y%m%d_%H%M%S)"
artifact_dir="demo_artifacts/${artifact_ts}"
mkdir -p "$artifact_dir"
proof_json="${artifact_dir}/fr01_scale15_proof.json"

python3 - "$collector_log" "$detector_log" "$base_collector_lines" "$base_detector_lines" "$proof_json" <<'PY'
import json
import sys
from pathlib import Path

collector_log = Path(sys.argv[1])
detector_log = Path(sys.argv[2])
base_collector = int(sys.argv[3])
base_detector = int(sys.argv[4])
proof_path = Path(sys.argv[5])

expected_nodes = [f"node-{i:02d}" for i in range(1, 16)]
expected_set = set(expected_nodes)

collector_records = []
with collector_log.open("r", encoding="utf-8") as f:
    for idx, raw in enumerate(f, start=1):
        if idx <= base_collector:
            continue
        raw = raw.strip()
        if not raw:
            continue
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if rec.get("msg") != "collector_event_published":
            continue
        user = str(rec.get("user", ""))
        src_ip = str(rec.get("src_ip", ""))
        event_type = str(rec.get("event_type", ""))
        if user in expected_set and src_ip.startswith("10.77.0.") and event_type == "auth_failed":
            collector_records.append(rec)

detector_records = []
with detector_log.open("r", encoding="utf-8") as f:
    for idx, raw in enumerate(f, start=1):
        if idx <= base_detector:
            continue
        raw = raw.strip()
        if not raw:
            continue
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if rec.get("msg") != "detector_rule_matched":
            continue
        user = str(rec.get("user", ""))
        if user in expected_set and str(rec.get("rule_id", "")) == "R-COLLECT-INVALID-USER":
            detector_records.append(rec)

observed_nodes = sorted({str(r.get("user", "")) for r in collector_records if str(r.get("user", "")) in expected_set})
missing_nodes = [n for n in expected_nodes if n not in observed_nodes]

if len(observed_nodes) != len(expected_nodes):
    raise SystemExit(f"missing node ids in collector decoded output: {','.join(missing_nodes)}")

if len(detector_records) < len(expected_nodes):
    raise SystemExit(f"insufficient detector decoded matches for scale proof: got={len(detector_records)} want>={len(expected_nodes)}")

proof = {
    "timestamp": __import__("datetime").datetime.now(__import__("datetime").UTC).replace(tzinfo=None, microsecond=0).isoformat() + "Z",
    "node_count_expected": len(expected_nodes),
    "node_count_observed": len(observed_nodes),
    "node_ids_observed": observed_nodes,
    "store_boundary": "logs/collector.log:collector_event_published",
    "detector_rule_id": "R-COLLECT-INVALID-USER",
    "detector_matches_observed": len(detector_records),
    "pass": True,
}
proof_path.write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")
PY

echo "PASS: FR-01 scale15 completed"
echo "FR01_SCALE15_PROOF_JSON=${proof_json}"
