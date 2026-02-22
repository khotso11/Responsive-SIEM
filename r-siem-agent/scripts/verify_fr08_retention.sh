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
need_cmd rg
need_cmd date
need_cmd hostname

echo "=== FR-08 retention+query+export verification ==="

./scripts/demo_down.sh >/dev/null 2>&1 || true
./scripts/demo_up.sh >/dev/null

echo "[1/6] generate deterministic source activity"
./scripts/verify_fr01.sh >/tmp/fr08_verify_fr01.out
./scripts/verify_new_playbooks.sh >/tmp/fr08_verify_new_playbooks.out

echo "[2/6] ingest retained records"
rm -rf retained
mkdir -p retained
go run -mod=vendor ./cmd/retention-query ingest \
  --retained_dir retained \
  --runs_path exports/roe_runs.jsonl \
  --steps_path exports/roe_steps.jsonl \
  --detector_log logs/detector.log \
  --collector_log logs/collector.log \
  --master_log logs/master-roe.log \
  --max_age_seconds 86400 \
  --max_bytes $((50 * 1024 * 1024)) >/tmp/fr08_ingest.out

timestamp="$(date +%Y%m%d_%H%M%S)"
artifact_dir="demo_artifacts/${timestamp}"
mkdir -p "$artifact_dir"

echo "[3/6] run deterministic queries + exports"
since_unix="$(( $(date +%s) - 7200 ))"
recent_runs_out="${artifact_dir}/fr08_query_runs.jsonl"
recent_runs_summary="${artifact_dir}/fr08_query_runs_summary.json"
go run -mod=vendor ./cmd/retention-query query \
  --retained_dir retained \
  --type runs \
  --since "${since_unix}" \
  --out "${recent_runs_out}" \
  --summary_out "${recent_runs_summary}" >/tmp/fr08_query_recent.out
recent_runs_count="$(wc -l < "${recent_runs_out}" | tr -d '[:space:]')"
if [[ "${recent_runs_count}" -lt 1 ]]; then
  echo "FAIL: expected recent runs count >= 1, got ${recent_runs_count}" >&2
  exit 1
fi

failed_safe_out="${artifact_dir}/fr08_query_failed_safe.jsonl"
failed_safe_summary="${artifact_dir}/fr08_query_failed_safe_summary.json"
go run -mod=vendor ./cmd/retention-query query \
  --retained_dir retained \
  --type runs \
  --status FAILED_SAFE \
  --out "${failed_safe_out}" \
  --summary_out "${failed_safe_summary}" >/tmp/fr08_query_failed_safe.out
failed_safe_count="$(wc -l < "${failed_safe_out}" | tr -d '[:space:]')"
if [[ "${failed_safe_count}" -lt 1 ]]; then
  echo "FAIL: expected failed_safe runs count >= 1, got ${failed_safe_count}" >&2
  exit 1
fi

playbook_filter_id="PB-BRUTEFORCE-IP-CONTAIN"
playbook_filter_out="${artifact_dir}/fr08_query_playbook.jsonl"
playbook_filter_summary="${artifact_dir}/fr08_query_playbook_summary.json"
go run -mod=vendor ./cmd/retention-query query \
  --retained_dir retained \
  --type runs \
  --playbook_id "${playbook_filter_id}" \
  --out "${playbook_filter_out}" \
  --summary_out "${playbook_filter_summary}" >/tmp/fr08_query_playbook.out
playbook_filter_count="$(wc -l < "${playbook_filter_out}" | tr -d '[:space:]')"
if [[ "${playbook_filter_count}" -lt 1 ]]; then
  echo "FAIL: expected playbook filtered runs count >= 1, got ${playbook_filter_count}" >&2
  exit 1
fi

echo "[4/6] prune deterministically"
before_bytes="$(du -sb retained | awk '{print $1}')"
before_records="$(cat retained/*.jsonl 2>/dev/null | wc -l | tr -d '[:space:]')"
prune_max_bytes=$(( before_bytes > 1 ? before_bytes - 1 : 1 ))
go run -mod=vendor ./cmd/retention-query prune \
  --retained_dir retained \
  --max_age_seconds 31536000 \
  --max_bytes "${prune_max_bytes}" >/tmp/fr08_prune.out
after_bytes="$(du -sb retained | awk '{print $1}')"
after_records="$(cat retained/*.jsonl 2>/dev/null | wc -l | tr -d '[:space:]')"
if [[ "${after_bytes}" -ge "${before_bytes}" && "${after_records}" -ge "${before_records}" ]]; then
  echo "FAIL: expected pruning to reduce bytes or records (before_bytes=${before_bytes}, after_bytes=${after_bytes}, before_records=${before_records}, after_records=${after_records})" >&2
  exit 1
fi

echo "[5/6] verify queries still work after prune"
post_prune_out="${artifact_dir}/fr08_post_prune_runs.jsonl"
post_prune_summary="${artifact_dir}/fr08_post_prune_runs_summary.json"
go run -mod=vendor ./cmd/retention-query query \
  --retained_dir retained \
  --type runs \
  --out "${post_prune_out}" \
  --summary_out "${post_prune_summary}" >/tmp/fr08_post_prune_query.out
post_prune_count="$(wc -l < "${post_prune_out}" | tr -d '[:space:]')"

echo "[6/6] write FR-08 proof artifact"
proof_json="${artifact_dir}/fr08_retention_proof.json"
cat > "${proof_json}" <<EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "retained_dir": "retained",
  "inputs": {
    "exports_runs": "exports/roe_runs.jsonl",
    "exports_steps": "exports/roe_steps.jsonl",
    "detector_log": "logs/detector.log",
    "collector_log": "logs/collector.log",
    "master_log": "logs/master-roe.log"
  },
  "queries": [
    {
      "name": "recent_runs",
      "out_jsonl": "${recent_runs_out}",
      "summary_json": "${recent_runs_summary}",
      "count": ${recent_runs_count}
    },
    {
      "name": "failed_safe_runs",
      "out_jsonl": "${failed_safe_out}",
      "summary_json": "${failed_safe_summary}",
      "count": ${failed_safe_count}
    },
    {
      "name": "playbook_filter",
      "playbook_id": "${playbook_filter_id}",
      "out_jsonl": "${playbook_filter_out}",
      "summary_json": "${playbook_filter_summary}",
      "count": ${playbook_filter_count}
    }
  ],
  "prune": {
    "max_age_seconds": 31536000,
    "max_bytes": ${prune_max_bytes},
    "before_bytes": ${before_bytes},
    "after_bytes": ${after_bytes},
    "before_records": ${before_records},
    "after_records": ${after_records},
    "post_prune_runs_count": ${post_prune_count}
  },
  "pass": true
}
EOF

echo "PASS: FR-08 retention+query+export completed"
echo "FR08_PROOF_JSON=${proof_json}"
