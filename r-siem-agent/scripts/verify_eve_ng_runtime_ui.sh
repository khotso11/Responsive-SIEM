#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "FAIL: missing command: $1" >&2
    exit 1
  }
}

need_cmd curl
need_cmd jq

UI_API_URL="${UI_API_URL:-http://127.0.0.1:8090}"
UI_USERNAME="${RSIEM_UI_USERNAME:-admin}"
UI_PASSWORD="${RSIEM_UI_PASSWORD:-admin123}"
TS="$(date +%Y%m%d_%H%M%S)"
ART_DIR="demo_artifacts/${TS}"
mkdir -p "$ART_DIR"
PROOF_JSON="${ART_DIR}/eve_ng_runtime_ui_proof.json"

LOGIN_JSON="$(curl -sS --max-time 8 -H 'Content-Type: application/json' -X POST "${UI_API_URL}/api/auth/login" -d "{\"username\":\"${UI_USERNAME}\",\"password\":\"${UI_PASSWORD}\"}")"
TOKEN="$(printf '%s' "$LOGIN_JSON" | jq -r '.token // empty')"
[[ -n "$TOKEN" ]] || {
  echo "FAIL: admin login token missing" >&2
  exit 1
}

TOPOLOGY_JSON="$(curl -sS --max-time 10 -H "Authorization: Bearer ${TOKEN}" "${UI_API_URL}/api/infrastructure/topology")"

PROVIDER_KIND="$(printf '%s' "$TOPOLOGY_JSON" | jq -r '.provider.kind // ""')"
SOURCE_STATUS="$(printf '%s' "$TOPOLOGY_JSON" | jq -r '.provider.source_status // ""')"
RUNTIME_STATUS="$(printf '%s' "$TOPOLOGY_JSON" | jq -r '.provider.runtime_status // ""')"
NODE_COUNT="$(printf '%s' "$TOPOLOGY_JSON" | jq -r '.nodes | length')"
EVE_STATE_COUNT="$(printf '%s' "$TOPOLOGY_JSON" | jq -r '[.nodes[] | select((.live.eve_runtime_status // "") != "")] | length')"

[[ "$PROVIDER_KIND" == "eve_ng" ]] || {
  echo "FAIL: topology provider is not eve_ng" >&2
  exit 1
}
[[ "$SOURCE_STATUS" == "imported" ]] || {
  echo "FAIL: EVE topology source not imported" >&2
  exit 1
}
[[ "$RUNTIME_STATUS" == "connected" ]] || {
  echo "FAIL: EVE runtime is not connected" >&2
  echo "$TOPOLOGY_JSON" | jq '.provider'
  exit 1
}
[[ "$NODE_COUNT" -gt 0 ]] || {
  echo "FAIL: topology has no nodes" >&2
  exit 1
}
[[ "$EVE_STATE_COUNT" -gt 0 ]] || {
  echo "FAIL: topology nodes do not expose eve_runtime_status" >&2
  exit 1
}

printf '%s\n' "$TOPOLOGY_JSON" | jq '{
  verified_at: (now | floor),
  ui_api_url: env.UI_API_URL,
  provider: .provider,
  node_count: (.nodes | length),
  nodes_with_eve_runtime: ([.nodes[] | select((.live.eve_runtime_status // "") != "")] | length),
  runtime_state_breakdown: (reduce (.nodes[] | (.live.eve_runtime_status // "missing")) as $s ({}; .[$s] = (.[$s] // 0) + 1))
}' > "$PROOF_JSON"

echo "PASS: EVE-NG runtime UI verification completed"
echo "EVE_NG_RUNTIME_UI_PROOF_JSON=${PROOF_JSON}"
