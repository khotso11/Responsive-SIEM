#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "FAIL: required command not found: $1" >&2
    exit 1
  }
}

need_cmd rg

TS="$(date +%Y%m%d_%H%M%S)"
OUT_DIR="demo_artifacts/${TS}/screenshot_panels"
mkdir -p "$OUT_DIR"

FR01_OUT="${OUT_DIR}/verify_fr01.out"
FR02_OUT="${OUT_DIR}/verify_fr02_mtls.out"

echo "=== STEP 1/2: run FR-01 verification ==="
./scripts/verify_fr01.sh | tee "$FR01_OUT"

echo "=== STEP 2/2: run FR-02 verification ==="
./scripts/verify_fr02_mtls.sh | tee "$FR02_OUT"

FR01_SUMMARY_PATH="$(sed -n 's/^DEMO_SUMMARY_JSON: //p' "$FR01_OUT" | tail -n 1)"
if [[ -z "$FR01_SUMMARY_PATH" || ! -f "$FR01_SUMMARY_PATH" ]]; then
  echo "FAIL: unable to locate FR-01 demo summary JSON from verify_fr01 output" >&2
  exit 1
fi

FR02_PROOF_PATH="$(sed -n 's/^proof_log=//p' "$FR02_OUT" | tail -n 1)"
if [[ -z "$FR02_PROOF_PATH" || ! -f "$FR02_PROOF_PATH" ]]; then
  echo "FAIL: unable to locate FR-02 proof JSON from verify_fr02_mtls output" >&2
  exit 1
fi

FR02_MASTER_LOG="$(sed -n 's/^[[:space:]]*"master_log":[[:space:]]*"\([^"]*\)".*/\1/p' "$FR02_PROOF_PATH" | head -n 1)"
if [[ -z "$FR02_MASTER_LOG" || ! -f "$FR02_MASTER_LOG" ]]; then
  echo "FAIL: unable to locate FR-02 master log from proof JSON" >&2
  exit 1
fi

FR02_T2_LINE="$(sed -n 's/^[[:space:]]*"t2_line":[[:space:]]*"\(.*\)",[[:space:]]*$/\1/p' "$FR02_PROOF_PATH" | head -n 1 | sed 's/\\"/"/g')"
FR02_T3_LINE="$(sed -n 's/^[[:space:]]*"t3_line":[[:space:]]*"\(.*\)",[[:space:]]*$/\1/p' "$FR02_PROOF_PATH" | head -n 1 | sed 's/\\"/"/g')"
FR02_T4_LINE="$(sed -n 's/^[[:space:]]*"t4_line":[[:space:]]*"\(.*\)",[[:space:]]*$/\1/p' "$FR02_PROOF_PATH" | head -n 1 | sed 's/\\"/"/g')"
FR02_T7_LINE="$(sed -n 's/^[[:space:]]*"t7_line":[[:space:]]*"\(.*\)",[[:space:]]*$/\1/p' "$FR02_PROOF_PATH" | head -n 1 | sed 's/\\"/"/g')"

FR05_FINAL_LINE="$(rg '^PASS: FR05 completed \(safety \+ rollback \+ audit\) run_id_ok=.* run_id_fail=.*$' "$FR01_OUT" | tail -n 1 || true)"
if [[ -z "$FR05_FINAL_LINE" ]]; then
  echo "FAIL: unable to parse FR-05 run IDs from verify_fr01 output" >&2
  exit 1
fi
RUN_ID_OK="$(printf '%s\n' "$FR05_FINAL_LINE" | sed -n 's/^PASS: FR05 completed (safety + rollback + audit) run_id_ok=\([^ ]*\) run_id_fail=\([^ ]*\)$/\1/p')"
RUN_ID_FAIL="$(printf '%s\n' "$FR05_FINAL_LINE" | sed -n 's/^PASS: FR05 completed (safety + rollback + audit) run_id_ok=\([^ ]*\) run_id_fail=\([^ ]*\)$/\2/p')"
if [[ -z "$RUN_ID_OK" || -z "$RUN_ID_FAIL" ]]; then
  echo "FAIL: FR-05 run_id parsing failed" >&2
  exit 1
fi

awk '/^=== FR-01 SUMMARY ===/{f=1} f{print} /^fr05_status=/{if(f) exit}' "$FR01_OUT" > "${OUT_DIR}/01_FR01_verify_summary.txt"
{
  rg '^PASS: FR-01 local verification completed$' "$FR01_OUT" || true
} >> "${OUT_DIR}/01_FR01_verify_summary.txt"

{
  rg '^PROOF_CHECKPOINT:' "$FR01_OUT"
  rg '^PROOF_AUTHLOG_OVERRIDE:' "$FR01_OUT"
} > "${OUT_DIR}/02_FR01_checkpoint_authlog.txt"

{
  echo "DEMO_SUMMARY_JSON: ${FR01_SUMMARY_PATH}"
  echo
  cat "$FR01_SUMMARY_PATH"
} > "${OUT_DIR}/03_FR08_demo_summary_json.txt"

awk '/^=== FR-02 mTLS SUMMARY ===/{f=1} f{print} /^proof_log=/{if(f) exit}' "$FR02_OUT" > "${OUT_DIR}/04_FR02_mtls_summary.txt"

{
  rg '^t2=' "${OUT_DIR}/04_FR02_mtls_summary.txt" || true
  rg '^t3=' "${OUT_DIR}/04_FR02_mtls_summary.txt" || true
  rg '^t4=' "${OUT_DIR}/04_FR02_mtls_summary.txt" || true
  echo
  [[ -n "$FR02_T2_LINE" ]] && printf '%s\n' "$FR02_T2_LINE"
  [[ -n "$FR02_T3_LINE" ]] && printf '%s\n' "$FR02_T3_LINE"
  [[ -n "$FR02_T4_LINE" ]] && printf '%s\n' "$FR02_T4_LINE"
} > "${OUT_DIR}/05_FR02_mtls_negative_tests.txt"

{
  rg '^t7=' "${OUT_DIR}/04_FR02_mtls_summary.txt" || true
  echo
  [[ -n "$FR02_T7_LINE" ]] && printf '%s\n' "$FR02_T7_LINE"
  rg '"msg":"grpc_mtls_handshake_failed".*"reason":"fingerprint_not_allowlisted"' "$FR02_MASTER_LOG" | tail -n 1 || true
} > "${OUT_DIR}/06_FR02_allowlist_reject.txt"

{
  rg "^PASS: FR05 quarantine rollback proof run_id=${RUN_ID_OK} " "$FR01_OUT" | tail -n 1 || true
  rg "\"msg\":\"response_run_updated\".*\"run_id\":\"${RUN_ID_OK}\".*\"status\":\"SUCCEEDED\"" logs/master-roe.log | tail -n 1
  rg "\"run_id\":\"${RUN_ID_OK}\".*\"status\":\"SUCCEEDED\"" exports/roe_runs.jsonl | tail -n 1
} > "${OUT_DIR}/07_FR05_rollback_success.txt"

{
  rg "^PASS: FR05 quarantine partial failure proof run_id=${RUN_ID_FAIL} " "$FR01_OUT" | tail -n 1 || true
  rg "\"msg\":\"response_run_updated\".*\"run_id\":\"${RUN_ID_FAIL}\".*\"status\":\"FAILED_SAFE\"" logs/master-roe.log | tail -n 1
  rg "\"msg\":\"response_run_partial_completion\".*\"run_id\":\"${RUN_ID_FAIL}\"" logs/master-roe.log | tail -n 1
  rg "\"run_id\":\"${RUN_ID_FAIL}\".*\"status\":\"FAILED_SAFE\"" exports/roe_runs.jsonl | tail -n 1
} > "${OUT_DIR}/08_FR05_partial_failure_safe.txt"

cat > "${OUT_DIR}/README.txt" <<EOF
Screenshot panels prepared in:
  ${OUT_DIR}

Take screenshots using these files and save as:
  01_FR01_verify_summary.png      <- ${OUT_DIR}/01_FR01_verify_summary.txt
  02_FR01_checkpoint_authlog.png  <- ${OUT_DIR}/02_FR01_checkpoint_authlog.txt
  03_FR08_demo_summary_json.png   <- ${OUT_DIR}/03_FR08_demo_summary_json.txt
  04_FR02_mtls_summary.png        <- ${OUT_DIR}/04_FR02_mtls_summary.txt
  05_FR02_mtls_negative_tests.png <- ${OUT_DIR}/05_FR02_mtls_negative_tests.txt
  06_FR02_allowlist_reject.png    <- ${OUT_DIR}/06_FR02_allowlist_reject.txt
  07_FR05_rollback_success.png    <- ${OUT_DIR}/07_FR05_rollback_success.txt
  08_FR05_partial_failure_safe.png<- ${OUT_DIR}/08_FR05_partial_failure_safe.txt

Quick preview:
  ls -1 ${OUT_DIR}
  sed -n '1,120p' ${OUT_DIR}/01_FR01_verify_summary.txt
EOF

echo "PASS: screenshot panels ready"
echo "OUT_DIR=${OUT_DIR}"
