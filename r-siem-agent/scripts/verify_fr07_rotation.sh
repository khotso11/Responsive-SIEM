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
need_cmd wc

mkdir -p demo_artifacts pki/fr07/hmac/rotated

ts="$(date +%Y%m%d_%H%M%S)"
artifact_dir="demo_artifacts/${ts}"
mkdir -p "$artifact_dir"

proof_json="${artifact_dir}/fr07_rotation_proof.json"

playbooks_root="configs/master.yaml"
detector_rules_root="configs/master.yaml"
bundle_roots=( "configs" )
batch_in="exports/roe_runs.jsonl"

./scripts/verify_fr01.sh >/tmp/fr07_rotation_verify_fr01.out 2>&1

[[ -s "$batch_in" ]] || { echo "FAIL: missing batch file: $batch_in" >&2; exit 1; }

go run -mod=vendor ./cmd/signctl init-key --key pki/fr07/hmac/active.key >"${artifact_dir}/fr07_rotation_init_key.out"

before_runs_count="$(wc -l < exports/roe_runs.jsonl | tr -d '[:space:]')"
before_steps_count="$(wc -l < exports/roe_steps.jsonl | tr -d '[:space:]')"

bundle_sig_before="${artifact_dir}/fr07_bundle_before.sig.json"
batch_sig_before="${artifact_dir}/fr07_batch_before.sig.json"

go run -mod=vendor ./cmd/signctl sign-bundle \
  --key pki/fr07/hmac/active.key \
  --bundle_root "${bundle_roots[0]}" \
  --out "$bundle_sig_before" >"${artifact_dir}/fr07_sign_bundle_before.out"

go run -mod=vendor ./cmd/signctl verify-bundle \
  --key pki/fr07/hmac/active.key \
  --bundle_root "${bundle_roots[0]}" \
  --sig "$bundle_sig_before" >"${artifact_dir}/fr07_verify_bundle_before.out"

go run -mod=vendor ./cmd/signctl sign-batch \
  --key pki/fr07/hmac/active.key \
  --in "$batch_in" \
  --out "$batch_sig_before" >"${artifact_dir}/fr07_sign_batch_before.out"

go run -mod=vendor ./cmd/signctl verify-batch \
  --key pki/fr07/hmac/active.key \
  --in "$batch_in" \
  --sig "$batch_sig_before" >"${artifact_dir}/fr07_verify_batch_before.out"

rotate_out="${artifact_dir}/fr07_rotate_key.out"
go run -mod=vendor ./cmd/signctl rotate-key \
  --key pki/fr07/hmac/active.key \
  --rotated_dir pki/fr07/hmac/rotated >"$rotate_out"

old_key_id="$(sed -n 's/^ROTATED_OLD_KEY_ID=//p' "$rotate_out" | head -n 1)"
new_key_id="$(sed -n 's/^NEW_KEY_ID=//p' "$rotate_out" | head -n 1)"
[[ -n "$old_key_id" ]] || { echo "FAIL: missing ROTATED_OLD_KEY_ID" >&2; exit 1; }
[[ -n "$new_key_id" ]] || { echo "FAIL: missing NEW_KEY_ID" >&2; exit 1; }
[[ "$new_key_id" != "$old_key_id" ]] || {
  echo "FAIL: rotate-key produced identical key ids old=${old_key_id} new=${new_key_id}" >&2
  exit 1
}

bundle_sig_after="${artifact_dir}/fr07_bundle_after.sig.json"
batch_sig_after="${artifact_dir}/fr07_batch_after.sig.json"

go run -mod=vendor ./cmd/signctl sign-bundle \
  --key pki/fr07/hmac/active.key \
  --bundle_root "${bundle_roots[0]}" \
  --out "$bundle_sig_after" >"${artifact_dir}/fr07_sign_bundle_after.out"

go run -mod=vendor ./cmd/signctl verify-bundle \
  --key pki/fr07/hmac/active.key \
  --bundle_root "${bundle_roots[0]}" \
  --sig "$bundle_sig_after" >"${artifact_dir}/fr07_verify_bundle_after.out"

go run -mod=vendor ./cmd/signctl sign-batch \
  --key pki/fr07/hmac/active.key \
  --in "$batch_in" \
  --out "$batch_sig_after" >"${artifact_dir}/fr07_sign_batch_after.out"

go run -mod=vendor ./cmd/signctl verify-batch \
  --key pki/fr07/hmac/active.key \
  --in "$batch_in" \
  --sig "$batch_sig_after" >"${artifact_dir}/fr07_verify_batch_after.out"

./scripts/verify_new_playbooks.sh >/tmp/fr07_rotation_verify_new_playbooks.out 2>&1

after_runs_count="$(wc -l < exports/roe_runs.jsonl | tr -d '[:space:]')"
after_steps_count="$(wc -l < exports/roe_steps.jsonl | tr -d '[:space:]')"

if (( after_runs_count < before_runs_count )); then
  echo "FAIL: runs export line count decreased after rotation (${before_runs_count} -> ${after_runs_count})" >&2
  exit 1
fi
if (( after_steps_count < before_steps_count )); then
  echo "FAIL: steps export line count decreased after rotation (${before_steps_count} -> ${after_steps_count})" >&2
  exit 1
fi

batch_sig_post_activity="${artifact_dir}/fr07_batch_post_activity.sig.json"
go run -mod=vendor ./cmd/signctl sign-batch \
  --key pki/fr07/hmac/active.key \
  --in "$batch_in" \
  --out "$batch_sig_post_activity" >"${artifact_dir}/fr07_sign_batch_post_activity.out"
go run -mod=vendor ./cmd/signctl verify-batch \
  --key pki/fr07/hmac/active.key \
  --in "$batch_in" \
  --sig "$batch_sig_post_activity" >"${artifact_dir}/fr07_verify_batch_post_activity.out"

cat >"$proof_json" <<JSON
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "bundle_roots": ["configs"],
  "playbooks_root": "$(json_escape "$playbooks_root")",
  "detector_rules_root": "$(json_escape "$detector_rules_root")",
  "batch_input": "$(json_escape "$batch_in")",
  "old_key_id": "$(json_escape "$old_key_id")",
  "new_key_id": "$(json_escape "$new_key_id")",
  "before": {
    "runs_count": ${before_runs_count},
    "steps_count": ${before_steps_count}
  },
  "after": {
    "runs_count": ${after_runs_count},
    "steps_count": ${after_steps_count}
  },
  "signatures": {
    "bundle_before": "$(json_escape "$bundle_sig_before")",
    "bundle_after": "$(json_escape "$bundle_sig_after")",
    "batch_before": "$(json_escape "$batch_sig_before")",
    "batch_after": "$(json_escape "$batch_sig_after")",
    "batch_post_activity": "$(json_escape "$batch_sig_post_activity")"
  },
  "pass": true
}
JSON

echo "PASS: FR-07 rotation completed"
echo "FR07_ROTATION_PROOF_JSON=${proof_json}"
