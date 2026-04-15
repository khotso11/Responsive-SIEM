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

need_cmd rg
need_cmd jq

TS="$(date -u +%Y%m%d_%H%M%S)"
ART_DIR="demo_artifacts/${TS}"
mkdir -p "$ART_DIR"
PROOF_JSON="${ART_DIR}/infrastructure_plane_phase3_proof.json"

PHASE2_OUT="/tmp/verify_infrastructure_phase2.out"
EASTWEST_OUT="/tmp/verify_infrastructure_eastwest.out"
CONFIG_OUT="/tmp/verify_infrastructure_cfg_oow.out"
POST_OUT="/tmp/verify_infrastructure_post_containment.out"

./scripts/verify_infrastructure_plane_phase2.sh | tee "$PHASE2_OUT"
./scripts/verify_infra_east_west_flow_scan.sh | tee "$EASTWEST_OUT"
./scripts/verify_infra_firewall_config_change_oow.sh | tee "$CONFIG_OUT"
./scripts/verify_infra_post_containment_block_verification.sh | tee "$POST_OUT"

phase2_proof="$(sed -n 's/^INFRASTRUCTURE_PLANE_PHASE2_PROOF_JSON=//p' "$PHASE2_OUT" | tail -n 1)"
eastwest_proof="$(sed -n 's/^INFRA_EAST_WEST_FLOW_SCAN_PROOF_JSON=//p' "$EASTWEST_OUT" | tail -n 1)"
config_proof="$(sed -n 's/^INFRA_FIREWALL_CONFIG_CHANGE_OOW_PROOF_JSON=//p' "$CONFIG_OUT" | tail -n 1)"
post_proof="$(sed -n 's/^INFRA_POST_CONTAINMENT_BLOCK_VERIFICATION_PROOF_JSON=//p' "$POST_OUT" | tail -n 1)"

[[ -n "$phase2_proof" && -f "$phase2_proof" ]] || { echo "FAIL: missing phase2 proof json" >&2; exit 1; }
[[ -n "$eastwest_proof" && -f "$eastwest_proof" ]] || { echo "FAIL: missing east-west proof json" >&2; exit 1; }
[[ -n "$config_proof" && -f "$config_proof" ]] || { echo "FAIL: missing config-change proof json" >&2; exit 1; }
[[ -n "$post_proof" && -f "$post_proof" ]] || { echo "FAIL: missing post-containment proof json" >&2; exit 1; }

jq -n \
  --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg phase2 "$phase2_proof" \
  --arg eastwest "$eastwest_proof" \
  --arg config "$config_proof" \
  --arg post "$post_proof" \
  '{
    timestamp: $timestamp,
    proofs: {
      phase2: $phase2,
      east_west_flow_scan: $eastwest,
      firewall_config_change_outside_window: $config,
      post_containment_block_verification: $post
    },
    pass: true
  }' > "$PROOF_JSON"

echo "PASS: infrastructure plane phase3 completed"
echo "INFRASTRUCTURE_PLANE_PHASE3_PROOF_JSON=${PROOF_JSON}"
