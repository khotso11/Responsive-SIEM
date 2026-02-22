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

mkdir -p demo_artifacts

timestamp="$(date +%Y%m%d_%H%M%S)"
artifact_dir="demo_artifacts/${timestamp}"
mkdir -p "$artifact_dir"

demo_log="${artifact_dir}/demo_fr05.out"
operator_success_log="${artifact_dir}/verify_fr05_operator_success.out"
operator_failed_log="${artifact_dir}/verify_fr05_operator_failed_safe.out"
operator_success_json="${artifact_dir}/fr05_operator_success_proof.json"
operator_failed_json="${artifact_dir}/fr05_operator_failed_safe_proof.json"
success_json="${artifact_dir}/fr05_success_proof.json"
failed_json="${artifact_dir}/fr05_failed_safe_proof.json"

# Keep FR-05 trigger volume deterministic for this wrapper run.
mkdir -p tmp
: > tmp/demo.log
rm -f tmp/tail.checkpoint.json

./scripts/demo_down.sh >/dev/null 2>&1 || true
./scripts/demo_up.sh >/dev/null

fr05_out="$(./scripts/demo_fr05.sh)"
printf '%s\n' "$fr05_out" | tee "$demo_log"

summary_line="$(printf '%s\n' "$fr05_out" | rg '^PASS: FR05 completed \(safety \+ rollback \+ audit\) run_id_ok=[^ ]+ run_id_fail=[^ ]+$' | tail -n 1 || true)"
[[ -n "$summary_line" ]] || fail_with_context "unable to parse FR05 demo summary line" "$demo_log"

run_id_ok="$(printf '%s\n' "$summary_line" | sed -n 's/^PASS: FR05 completed (safety + rollback + audit) run_id_ok=\([^ ]*\) run_id_fail=\([^ ]*\)$/\1/p')"
run_id_fail="$(printf '%s\n' "$summary_line" | sed -n 's/^PASS: FR05 completed (safety + rollback + audit) run_id_ok=\([^ ]*\) run_id_fail=\([^ ]*\)$/\2/p')"
[[ -n "$run_id_ok" ]] || fail_with_context "run_id_ok parse failed" "$demo_log"
[[ -n "$run_id_fail" ]] || fail_with_context "run_id_fail parse failed" "$demo_log"

RUN_ID="$run_id_ok" EXPECTED_STATUS="SUCCEEDED" FR05_ARTIFACT_DIR="$artifact_dir" FR05_OPERATOR_PROOF_JSON_PATH="$operator_success_json" \
  ./scripts/verify_fr05_operator_recovery.sh | tee "$operator_success_log"

RUN_ID="$run_id_fail" EXPECTED_STATUS="FAILED_SAFE" FR05_ARTIFACT_DIR="$artifact_dir" FR05_OPERATOR_PROOF_JSON_PATH="$operator_failed_json" \
  ./scripts/verify_fr05_operator_recovery.sh | tee "$operator_failed_log"

failed_run_updated_line="$(rg '"msg":"response_run_updated".*"run_id":"'"${run_id_fail}"'".*"status":"FAILED_SAFE"' logs/master-roe.log | tail -n 1 || true)"
failed_safe_reason="$(printf '%s\n' "$failed_run_updated_line" | sed -n 's/.*"failed_safe_reason":"\([^"]*\)".*/\1/p' | tail -n 1)"
operator_line="$(rg '"msg":"response_run_partial_completion".*"run_id":"'"${run_id_fail}"'"' logs/master-roe.log | tail -n 1 || true)"
operator_action="$(printf '%s\n' "$operator_line" | sed -n 's/.*"operator_action":"\([^"]*\)".*/\1/p' | tail -n 1)"

generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cat > "$success_json" <<EOF_SUCCESS
{
  "timestamp": "$(json_escape "$generated_at")",
  "run_id": "$(json_escape "$run_id_ok")",
  "status": "SUCCEEDED",
  "operator_proof_json": "$(json_escape "$operator_success_json")",
  "demo_output_log": "$(json_escape "$demo_log")"
}
EOF_SUCCESS

cat > "$failed_json" <<EOF_FAILED
{
  "timestamp": "$(json_escape "$generated_at")",
  "run_id": "$(json_escape "$run_id_fail")",
  "status": "FAILED_SAFE",
  "operator_action": "$(json_escape "$operator_action")",
  "failed_safe_reason": "$(json_escape "$failed_safe_reason")",
  "operator_proof_json": "$(json_escape "$operator_failed_json")",
  "demo_output_log": "$(json_escape "$demo_log")"
}
EOF_FAILED

echo "PASS: FR-05 full suite completed"
echo "FR05_SUCCESS_PROOF_JSON=${success_json}"
echo "FR05_FAILED_SAFE_PROOF_JSON=${failed_json}"
