#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "FAIL: missing command: $1" >&2; exit 1; }
}

need_cmd jq
need_cmd curl
need_cmd rg

TS="$(date -u +%Y%m%d_%H%M%S)"
RFC3339="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ART_DIR="demo_artifacts/${TS}/fr06_ui"
mkdir -p "$ART_DIR"

echo "=== FR-06 UI smoke ==="
echo "[1/6] ensure core stack"
./scripts/db_up.sh >/dev/null
./scripts/demo_up.sh >/dev/null

echo "[2/6] restart UI services"
./scripts/ui_down.sh >/dev/null 2>&1 || true
UI_UP_OUT="$(./scripts/ui_up.sh)"
printf '%s\n' "$UI_UP_OUT" > "$ART_DIR/ui_up.out"

UI_WEB_URL="$(printf '%s\n' "$UI_UP_OUT" | sed -n 's/^UI_WEB_URL=//p' | tail -n1)"
UI_API_URL="$(printf '%s\n' "$UI_UP_OUT" | sed -n 's/^UI_API_URL=//p' | tail -n1)"
UI_API_KEY="${UI_API_KEY:-dev-ui-key}"

if [[ -z "$UI_WEB_URL" || -z "$UI_API_URL" ]]; then
  echo "FAIL: ui_up.sh did not print UI URLs" >&2
  exit 1
fi

echo "[3/6] health + core endpoints"
HEALTH_JSON="$(curl -sS --max-time 8 "${UI_API_URL}/api/health")"
INCIDENTS_JSON="$(curl -sS --max-time 8 -H "X-API-Key: ${UI_API_KEY}" "${UI_API_URL}/api/incidents?limit=20")"
ENDPOINTS_JSON="$(curl -sS --max-time 8 -H "X-API-Key: ${UI_API_KEY}" "${UI_API_URL}/api/endpoints")"
AUDIT_JSON="$(curl -sS --max-time 8 -H "X-API-Key: ${UI_API_KEY}" "${UI_API_URL}/api/audit")"

printf '%s\n' "$HEALTH_JSON" > "$ART_DIR/health.json"
printf '%s\n' "$INCIDENTS_JSON" > "$ART_DIR/incidents.json"
printf '%s\n' "$ENDPOINTS_JSON" > "$ART_DIR/endpoints.json"
printf '%s\n' "$AUDIT_JSON" > "$ART_DIR/audit.json"

[[ "$(printf '%s\n' "$HEALTH_JSON" | jq -r '.ok // false')" == "true" ]] || { echo "FAIL: /api/health not ok" >&2; exit 1; }
INCIDENTS_COUNT="$(printf '%s\n' "$INCIDENTS_JSON" | jq -r '.count // 0')"
ENDPOINTS_COUNT="$(printf '%s\n' "$ENDPOINTS_JSON" | jq -r '.count // 0')"
AUDIT_COUNT="$(printf '%s\n' "$AUDIT_JSON" | jq -r '.count // 0')"

echo "[4/6] validate SSE first event"
SSE_RAW="$({ curl -sS --max-time 10 -N -H "X-API-Key: ${UI_API_KEY}" "${UI_API_URL}/api/stream" 2>/dev/null || true; } | awk '/^data: /{print substr($0,7); exit}')"
[[ -n "$SSE_RAW" ]] || { echo "FAIL: SSE stream returned no data event" >&2; exit 1; }
printf '%s\n' "$SSE_RAW" > "$ART_DIR/sse_first_event.json"
SSE_TYPE="$(printf '%s\n' "$SSE_RAW" | jq -r '.type // empty')"
[[ "$SSE_TYPE" == "refresh_hint" ]] || { echo "FAIL: SSE first event type != refresh_hint" >&2; exit 1; }

echo "[5/6] write proof"
ENDPOINTS_TESTED='["/api/health","/api/incidents","/api/endpoints","/api/audit","/api/stream"]'

jq -n \
  --arg timestamp "$RFC3339" \
  --arg ui_web_url "$UI_WEB_URL" \
  --arg ui_api_url "$UI_API_URL" \
  --argjson incidents_count "${INCIDENTS_COUNT:-0}" \
  --argjson endpoints_count "${ENDPOINTS_COUNT:-0}" \
  --argjson audit_count "${AUDIT_COUNT:-0}" \
  --argjson endpoints_tested "$ENDPOINTS_TESTED" \
  '{
    timestamp: $timestamp,
    ui_web_url: $ui_web_url,
    ui_api_url: $ui_api_url,
    endpoints_tested: $endpoints_tested,
    incidents_count: $incidents_count,
    endpoints_count: $endpoints_count,
    audit_count: $audit_count,
    pass: true
  }' > "$ART_DIR/fr06_ui_smoke_proof.json"

echo "[6/6] done"
echo "PASS: FR-06 UI smoke completed"
echo "FR06_UI_SMOKE_PROOF_JSON=${ART_DIR}/fr06_ui_smoke_proof.json"
