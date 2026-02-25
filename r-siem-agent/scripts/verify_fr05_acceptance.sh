#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export GOCACHE="${GOCACHE:-$ROOT_DIR/.cache/go-build}"
mkdir -p "$GOCACHE"

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
    echo "Context: tail -n 120 ${file}" >&2
    tail -n 120 "$file" >&2 || true
  fi
  exit 1
}

extract_json_field() {
  local file="$1"
  local key="$2"
  tr -d '\n' < "$file" | sed -n 's/.*"'"${key}"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'
}

mkdir -p demo_artifacts
timestamp="$(date +%Y%m%d_%H%M%S)"
artifact_dir="demo_artifacts/${timestamp}"
mkdir -p "$artifact_dir"

verify_full_log="${artifact_dir}/verify_fr05_full.out"
go_test_log="${artifact_dir}/go_test_fr05_acceptance.out"
proof_json="${artifact_dir}/fr05_acceptance_proof.json"

fr05_out="$(./scripts/verify_fr05_full.sh)"
printf '%s\n' "$fr05_out" | tee "$verify_full_log"

success_proof_json="$(printf '%s\n' "$fr05_out" | sed -n 's/^FR05_SUCCESS_PROOF_JSON=\(.*\)$/\1/p' | tail -n 1)"
failed_proof_json="$(printf '%s\n' "$fr05_out" | sed -n 's/^FR05_FAILED_SAFE_PROOF_JSON=\(.*\)$/\1/p' | tail -n 1)"

[[ -n "$success_proof_json" ]] || fail_with_context "missing FR05_SUCCESS_PROOF_JSON output" "$verify_full_log"
[[ -n "$failed_proof_json" ]] || fail_with_context "missing FR05_FAILED_SAFE_PROOF_JSON output" "$verify_full_log"
[[ -f "$success_proof_json" ]] || fail_with_context "success proof json not found: ${success_proof_json}" "$verify_full_log"
[[ -f "$failed_proof_json" ]] || fail_with_context "failed-safe proof json not found: ${failed_proof_json}" "$verify_full_log"

run_id_ok="$(extract_json_field "$success_proof_json" "run_id")"
run_id_fail="$(extract_json_field "$failed_proof_json" "run_id")"
[[ -n "$run_id_ok" ]] || fail_with_context "could not parse run_id from ${success_proof_json}" "$verify_full_log"
[[ -n "$run_id_fail" ]] || fail_with_context "could not parse run_id from ${failed_proof_json}" "$verify_full_log"

check_export_fields() {
  local file="$1"
  local run_id="$2"
  local actor_field="$3"
  local target_field="$4"
  local ts_field="$5"
  local run_lines actor_line target_line ts_line

  run_lines="$(rg "\"run_id\":\"${run_id}\"" "$file" || true)"
  [[ -n "$run_lines" ]] || fail_with_context "missing run_id=${run_id} in ${file}" "$file"

  actor_line="$(printf '%s\n' "$run_lines" | rg "\"${actor_field}\":\"[^\"]+\"" | tail -n 1 || true)"
  target_line="$(printf '%s\n' "$run_lines" | rg "\"${target_field}\":\"[^\"]+\"" | tail -n 1 || true)"
  ts_line="$(printf '%s\n' "$run_lines" | rg "\"${ts_field}\":[0-9]+" | tail -n 1 || true)"

  [[ -n "$actor_line" ]] || fail_with_context "missing ${actor_field} for run_id=${run_id} in ${file}" "$file"
  [[ -n "$target_line" ]] || fail_with_context "missing ${target_field} for run_id=${run_id} in ${file}" "$file"
  [[ -n "$ts_line" ]] || fail_with_context "missing ${ts_field} for run_id=${run_id} in ${file}" "$file"
}

check_export_fields "exports/roe_steps.jsonl" "$run_id_ok" "actor" "target" "finished_at_unix_ms"
check_export_fields "exports/roe_steps.jsonl" "$run_id_fail" "actor" "target" "finished_at_unix_ms"
check_export_fields "exports/roe_runs.jsonl" "$run_id_ok" "actor" "target" "last_updated_at_unix_ms"
check_export_fields "exports/roe_runs.jsonl" "$run_id_fail" "actor" "target" "last_updated_at_unix_ms"

go test -v ./cmd/agent ./cmd/master-roe ./cmd/master-roe-worker | tee "$go_test_log"

for test_name in \
  TestMarkerCommandIdempotent \
  TestFailedSafeRunIncludesReasonAndOperatorAction \
  TestUpdateRunWithResultAuditEnrichment; do
  rg -q "${test_name}" "$go_test_log" || fail_with_context "expected unit test not found in output: ${test_name}" "$go_test_log"
done

generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
cat > "$proof_json" <<EOF_JSON
{
  "timestamp": "$(json_escape "$generated_at")",
  "run_id_ok": "$(json_escape "$run_id_ok")",
  "run_id_fail": "$(json_escape "$run_id_fail")",
  "actor_present": true,
  "target_present": true,
  "timestamp_present": true,
  "unit_tests_pass": true,
  "pass": true,
  "verify_fr05_full_log": "$(json_escape "$verify_full_log")",
  "go_test_log": "$(json_escape "$go_test_log")"
}
EOF_JSON

echo "PASS: FR-05 acceptance completed"
echo "FR05_ACCEPTANCE_PROOF_JSON=${proof_json}"
