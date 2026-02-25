#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

need_cmd() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "FAIL: missing command: $cmd" >&2
    exit 1
  }
}

need_cmd go
need_cmd python3
need_cmd date
need_cmd rg
need_cmd jq
need_cmd hostname

echo "=== FR-08 acceptance verification ==="

echo "[1/4] ensure baseline FR-08 retention proof data"
./scripts/verify_fr08_retention.sh >/tmp/fr08_accept_verify_retention.out

ts="$(date +%Y%m%d_%H%M%S)"
artifact_dir="demo_artifacts/${ts}"
mkdir -p "$artifact_dir"
proof_json="${artifact_dir}/fr08_acceptance_proof.json"

echo "[2/4] CSV export proof"
rq_bin="${artifact_dir}/retention-query.bin"
go build -mod=vendor -o "$rq_bin" ./cmd/retention-query

csv_out="${artifact_dir}/fr08_failed_safe_runs.csv"
csv_summary="${artifact_dir}/fr08_failed_safe_runs_summary.json"
"$rq_bin" query \
  --retained_dir retained \
  --type runs \
  --status FAILED_SAFE \
  --format csv \
  --out "$csv_out" \
  --summary_out "$csv_summary" >/tmp/fr08_accept_csv_query.out

[[ -f "$csv_out" ]] || {
  echo "FAIL: expected CSV export at ${csv_out}" >&2
  exit 1
}

expected_header='type,status,run_id,playbook_id,ts_unix_ms,source,rule_id,severity,event,step_id,operator_action,failed_safe_reason,line_sha256'
actual_header="$(head -n 1 "$csv_out" || true)"
header_ok=false
if [[ "$actual_header" == "$expected_header" ]]; then
  header_ok=true
fi
if [[ "$header_ok" != true ]]; then
  echo "FAIL: CSV header mismatch" >&2
  echo "expected: $expected_header" >&2
  echo "actual  : $actual_header" >&2
  exit 1
fi

csv_total_lines="$(wc -l < "$csv_out" | tr -d '[:space:]')"
csv_row_count=$((csv_total_lines - 1))
if (( csv_row_count < 1 )); then
  echo "FAIL: expected CSV export to contain at least 1 data row, got ${csv_row_count}" >&2
  exit 1
fi

echo "[3/4] random 24h query timing suite (K=15, seeded)"
runs_file="retained/runs.jsonl"
[[ -f "$runs_file" ]] || {
  echo "FAIL: missing retained runs file: ${runs_file}" >&2
  exit 1
}

windows_tsv="${artifact_dir}/fr08_24h_windows.tsv"
python3 - "$runs_file" "$windows_tsv" <<'PY'
import json
import random
import sys
import time

runs_path = sys.argv[1]
windows_path = sys.argv[2]
K = 15
WINDOW_MS = 24 * 60 * 60 * 1000
SEED = 20260225

min_ts = None
max_ts = None
with open(runs_path, "r", encoding="utf-8") as f:
    for raw in f:
        raw = raw.strip()
        if not raw:
            continue
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError:
            continue
        ts = int(rec.get("ts_unix_ms", 0) or 0)
        if ts <= 0:
            continue
        if min_ts is None or ts < min_ts:
            min_ts = ts
        if max_ts is None or ts > max_ts:
            max_ts = ts

now_ms = int(time.time() * 1000)
if min_ts is None:
    min_ts = now_ms
if max_ts is None:
    max_ts = now_ms
if max_ts < min_ts:
    max_ts = min_ts

span = max_ts - min_ts
rng = random.Random(SEED)

with open(windows_path, "w", encoding="utf-8") as out:
    for _ in range(K):
        if span >= WINDOW_MS:
            start = rng.randint(min_ts, max_ts - WINDOW_MS)
        else:
            low = max_ts - WINDOW_MS
            high = max_ts
            start = rng.randint(low, high)
        end = start + WINDOW_MS
        out.write(f"{start}\t{end}\n")
PY

timings_file="${artifact_dir}/fr08_24h_timing_ms.txt"
: > "$timings_file"
window_idx=0
while IFS=$'\t' read -r start_ms end_ms; do
  out_jsonl="${artifact_dir}/fr08_window_${window_idx}.jsonl"
  t0="$(date +%s%3N)"
  "$rq_bin" query \
    --retained_dir retained \
    --type runs \
    --since "$start_ms" \
    --until "$end_ms" \
    --out "$out_jsonl" >/tmp/fr08_accept_window_query_${window_idx}.out
  t1="$(date +%s%3N)"
  elapsed_ms=$((t1 - t0))
  echo "$elapsed_ms" >> "$timings_file"
  window_idx=$((window_idx + 1))
done < "$windows_tsv"

if [[ "$window_idx" -ne 15 ]]; then
  echo "FAIL: expected 15 timing windows, got ${window_idx}" >&2
  exit 1
fi

timing_stats_json="${artifact_dir}/fr08_24h_timing_stats.json"
python3 - "$timings_file" "$timing_stats_json" <<'PY'
import json
import math
import sys

timings_path = sys.argv[1]
out_path = sys.argv[2]
vals = []
with open(timings_path, "r", encoding="utf-8") as f:
    for raw in f:
        raw = raw.strip()
        if raw:
            vals.append(int(raw))
if not vals:
    raise SystemExit("no timing samples")
vals.sort()
n = len(vals)
def pct(p):
    idx = max(0, min(n - 1, math.ceil(p * n) - 1))
    return int(vals[idx])
stats = {
    "K": n,
    "p50_ms": pct(0.50),
    "p95_ms": pct(0.95),
    "max_ms": int(vals[-1]),
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(stats, f, indent=2)
    f.write("\n")
PY

p95_ms="$(jq -r '.p95_ms' "$timing_stats_json")"
if (( p95_ms > 3000 )); then
  echo "FAIL: 24h query timing p95 too high: ${p95_ms}ms > 3000ms" >&2
  exit 1
fi

echo "[4/4] write FR-08 acceptance proof artifact"
python3 - "$proof_json" "$csv_out" "$csv_row_count" "$header_ok" "$timing_stats_json" <<'PY'
import json
import sys
from datetime import datetime, timezone

proof_path = sys.argv[1]
csv_out = sys.argv[2]
csv_row_count = int(sys.argv[3])
header_ok = sys.argv[4].lower() == "true"
timing_stats_path = sys.argv[5]

with open(timing_stats_path, "r", encoding="utf-8") as f:
    timing = json.load(f)

proof = {
    "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "csv_export": {
        "out_csv": csv_out,
        "row_count": csv_row_count,
        "header_ok": header_ok,
    },
    "timing_24h": {
        "K": int(timing["K"]),
        "p50_ms": int(timing["p50_ms"]),
        "p95_ms": int(timing["p95_ms"]),
        "max_ms": int(timing["max_ms"]),
        "pass": int(timing["p95_ms"]) <= 3000,
    },
    "schema_doc": "docs/fr08_schema.md",
    "sizing_doc": "docs/fr08_sizing.md",
    "pass": header_ok and csv_row_count >= 1 and int(timing["p95_ms"]) <= 3000,
}

with open(proof_path, "w", encoding="utf-8") as f:
    json.dump(proof, f, indent=2)
    f.write("\n")
PY

echo "PASS: FR-08 acceptance completed"
echo "FR08_ACCEPTANCE_PROOF_JSON=${proof_json}"
