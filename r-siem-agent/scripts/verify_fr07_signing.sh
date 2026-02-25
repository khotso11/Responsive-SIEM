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

json_escape() {
  local s="${1:-}"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/}"
  printf '%s' "$s"
}

need_cmd go
need_cmd date

mkdir -p demo_artifacts pki/fr07/hmac

ts="$(date +%Y%m%d_%H%M%S)"
artifact_dir="demo_artifacts/${ts}"
mkdir -p "$artifact_dir"

bundle_sig="${artifact_dir}/fr07_bundle.sig.json"
batch_sig="${artifact_dir}/fr07_batch.sig.json"
proof_json="${artifact_dir}/fr07_signing_proof.json"
neg_bundle_log="${artifact_dir}/fr07_negative_bundle_verify.out"
neg_batch_log="${artifact_dir}/fr07_negative_batch_verify.out"

playbooks_root="configs/master.yaml"
detector_rules_root="configs/master.yaml"
bundle_roots=( "configs" )
bundle_target="configs/master.yaml"
bundle_backup="${artifact_dir}/bundle_target.backup"

if [[ ! -f "$bundle_target" ]]; then
  echo "FAIL: bundle target missing: $bundle_target" >&2
  exit 1
fi

batch_in="exports/roe_runs.jsonl"
if [[ ! -s "$batch_in" ]]; then
  ./scripts/verify_fr01.sh >/tmp/fr07_verify_fr01.out 2>&1
fi
[[ -s "$batch_in" ]] || { echo "FAIL: missing batch file: $batch_in" >&2; exit 1; }

restore_bundle_target() {
  if [[ -f "$bundle_backup" ]]; then
    mv -f "$bundle_backup" "$bundle_target"
  fi
}
trap restore_bundle_target EXIT

go run -mod=vendor ./cmd/signctl init-key --key pki/fr07/hmac/active.key >"${artifact_dir}/fr07_init_key.out"

go run -mod=vendor ./cmd/signctl sign-bundle \
  --key pki/fr07/hmac/active.key \
  --bundle_root "${bundle_roots[0]}" \
  --out "$bundle_sig" >"${artifact_dir}/fr07_sign_bundle.out"

go run -mod=vendor ./cmd/signctl verify-bundle \
  --key pki/fr07/hmac/active.key \
  --bundle_root "${bundle_roots[0]}" \
  --sig "$bundle_sig" >"${artifact_dir}/fr07_verify_bundle.out"

cp "$bundle_target" "$bundle_backup"
printf '#' >> "$bundle_target"
if go run -mod=vendor ./cmd/signctl verify-bundle \
  --key pki/fr07/hmac/active.key \
  --bundle_root "${bundle_roots[0]}" \
  --sig "$bundle_sig" >"$neg_bundle_log" 2>&1; then
  echo "FAIL: expected bundle verification failure after tamper" >&2
  exit 1
fi
restore_bundle_target

bundle_reason="$(tail -n 1 "$neg_bundle_log" 2>/dev/null || true)"
if [[ -z "$bundle_reason" ]]; then
  bundle_reason="verify_bundle_failed"
fi

go run -mod=vendor ./cmd/signctl sign-batch \
  --key pki/fr07/hmac/active.key \
  --in "$batch_in" \
  --out "$batch_sig" >"${artifact_dir}/fr07_sign_batch.out"

go run -mod=vendor ./cmd/signctl verify-batch \
  --key pki/fr07/hmac/active.key \
  --in "$batch_in" \
  --sig "$batch_sig" >"${artifact_dir}/fr07_verify_batch.out"

tampered_batch="${artifact_dir}/roe_runs.tampered.jsonl"
cp "$batch_in" "$tampered_batch"
printf 'X' >> "$tampered_batch"
if go run -mod=vendor ./cmd/signctl verify-batch \
  --key pki/fr07/hmac/active.key \
  --in "$tampered_batch" \
  --sig "$batch_sig" >"$neg_batch_log" 2>&1; then
  echo "FAIL: expected batch verification failure after tamper" >&2
  exit 1
fi

batch_reason="$(tail -n 1 "$neg_batch_log" 2>/dev/null || true)"
if [[ -z "$batch_reason" ]]; then
  batch_reason="verify_batch_failed"
fi

key_id="$(sed -n 's/.*"key_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$bundle_sig" | head -n 1)"
if [[ -z "$key_id" ]]; then
  key_id="active"
fi

cat >"$proof_json" <<JSON
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "key_id": "$(json_escape "$key_id")",
  "bundle_roots": ["configs"],
  "playbooks_root": "$(json_escape "$playbooks_root")",
  "detector_rules_root": "$(json_escape "$detector_rules_root")",
  "batch_input": "$(json_escape "$batch_in")",
  "bundle_sig_path": "$(json_escape "$bundle_sig")",
  "batch_sig_path": "$(json_escape "$batch_sig")",
  "negative_tests": [
    {
      "name": "bundle_tamper_rejected",
      "expected_fail": true,
      "observed_fail": true,
      "reason": "$(json_escape "$bundle_reason")"
    },
    {
      "name": "batch_tamper_rejected",
      "expected_fail": true,
      "observed_fail": true,
      "reason": "$(json_escape "$batch_reason")"
    }
  ],
  "pass": true
}
JSON

echo "PASS: FR-07 signing+verification completed"
echo "FR07_SIGNING_PROOF_JSON=${proof_json}"
