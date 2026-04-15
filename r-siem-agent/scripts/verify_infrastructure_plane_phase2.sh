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
PROOF_JSON="${ART_DIR}/infrastructure_plane_phase2_proof.json"

FIREWALL_OUT="/tmp/verify_infrastructure_firewall.out"
ADMIN_OUT="/tmp/verify_infrastructure_admin.out"
LINK_OUT="/tmp/verify_infrastructure_link.out"

./scripts/verify_infra_firewall_deny_burst.sh | tee "$FIREWALL_OUT"
./scripts/verify_infra_network_admin_login.sh | tee "$ADMIN_OUT"
./scripts/verify_infra_link_flap_burst.sh | tee "$LINK_OUT"

firewall_proof="$(sed -n 's/^INFRA_FIREWALL_DENY_BURST_PROOF_JSON=//p' "$FIREWALL_OUT" | tail -n 1)"
admin_proof="$(sed -n 's/^INFRA_NETWORK_ADMIN_LOGIN_PROOF_JSON=//p' "$ADMIN_OUT" | tail -n 1)"
link_proof="$(sed -n 's/^INFRA_LINK_FLAP_BURST_PROOF_JSON=//p' "$LINK_OUT" | tail -n 1)"

[[ -n "$firewall_proof" && -f "$firewall_proof" ]] || { echo "FAIL: missing firewall proof json" >&2; exit 1; }
[[ -n "$admin_proof" && -f "$admin_proof" ]] || { echo "FAIL: missing admin proof json" >&2; exit 1; }
[[ -n "$link_proof" && -f "$link_proof" ]] || { echo "FAIL: missing link proof json" >&2; exit 1; }

jq -n \
  --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg firewall "$firewall_proof" \
  --arg admin "$admin_proof" \
  --arg link "$link_proof" \
  '{
    timestamp: $timestamp,
    proofs: {
      firewall_deny_burst: $firewall,
      network_admin_login: $admin,
      link_flap_burst: $link
    },
    pass: true
  }' > "$PROOF_JSON"

echo "PASS: infrastructure plane phase2 completed"
echo "INFRASTRUCTURE_PLANE_PHASE2_PROOF_JSON=${PROOF_JSON}"
