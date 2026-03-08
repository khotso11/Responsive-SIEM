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
echo "[1/7] ensure core stack"
./scripts/db_up.sh >/dev/null
./scripts/demo_up.sh >/dev/null

echo "[2/7] restart UI services"
./scripts/ui_down.sh >/dev/null 2>&1 || true
UI_UP_OUT="$(./scripts/ui_up.sh)"
printf '%s\n' "$UI_UP_OUT" > "$ART_DIR/ui_up.out"

UI_WEB_URL="$(printf '%s\n' "$UI_UP_OUT" | sed -n 's/^UI_WEB_URL=//p' | tail -n1)"
UI_API_URL="$(printf '%s\n' "$UI_UP_OUT" | sed -n 's/^UI_API_URL=//p' | tail -n1)"

if [[ -z "$UI_WEB_URL" || -z "$UI_API_URL" ]]; then
  echo "FAIL: ui_up.sh did not print UI URLs" >&2
  exit 1
fi

echo "[3/7] health"
HEALTH_JSON="$(curl -sS --max-time 8 "${UI_API_URL}/api/health")"
printf '%s\n' "$HEALTH_JSON" > "$ART_DIR/health.json"
[[ "$(printf '%s\n' "$HEALTH_JSON" | jq -r '.ok // false')" == "true" ]] || { echo "FAIL: /api/health not ok" >&2; exit 1; }

echo "[4/7] auth + RBAC checks"
ADMIN_LOGIN_JSON="$(curl -sS --max-time 8 -H 'Content-Type: application/json' -X POST "${UI_API_URL}/api/auth/login" -d '{"username":"admin","password":"admin123"}')"
ANALYST_LOGIN_JSON="$(curl -sS --max-time 8 -H 'Content-Type: application/json' -X POST "${UI_API_URL}/api/auth/login" -d '{"username":"analyst","password":"analyst123"}')"

ADMIN_TOKEN="$(printf '%s\n' "$ADMIN_LOGIN_JSON" | jq -r '.token // empty')"
ANALYST_TOKEN="$(printf '%s\n' "$ANALYST_LOGIN_JSON" | jq -r '.token // empty')"
[[ -n "$ADMIN_TOKEN" ]] || { echo "FAIL: admin login token missing" >&2; exit 1; }
[[ -n "$ANALYST_TOKEN" ]] || { echo "FAIL: analyst login token missing" >&2; exit 1; }

ADMIN_USERS_CODE="$(curl -sS -o "$ART_DIR/admin_users.json" -w '%{http_code}' -H "Authorization: Bearer ${ADMIN_TOKEN}" "${UI_API_URL}/api/users")"
ANALYST_USERS_CODE="$(curl -sS -o "$ART_DIR/analyst_users_denied.json" -w '%{http_code}' -H "Authorization: Bearer ${ANALYST_TOKEN}" "${UI_API_URL}/api/users")"

[[ "$ADMIN_USERS_CODE" == "200" ]] || { echo "FAIL: admin /api/users expected 200 got ${ADMIN_USERS_CODE}" >&2; exit 1; }
[[ "$ANALYST_USERS_CODE" == "403" ]] || { echo "FAIL: analyst /api/users expected 403 got ${ANALYST_USERS_CODE}" >&2; exit 1; }

RBAC_USER="smoke_analyst_${TS}"
ADMIN_CREATE_USER_CODE="$(curl -sS -o "$ART_DIR/admin_create_user.json" -w '%{http_code}' -H 'Content-Type: application/json' -H "Authorization: Bearer ${ADMIN_TOKEN}" -X POST "${UI_API_URL}/api/users" -d "{\"username\":\"${RBAC_USER}\",\"role\":\"analyst\",\"password\":\"smoke123\"}")"
[[ "$ADMIN_CREATE_USER_CODE" == "200" ]] || { echo "FAIL: admin /api/users create expected 200 got ${ADMIN_CREATE_USER_CODE}" >&2; exit 1; }
ADMIN_DISABLE_USER_CODE="$(curl -sS -o "$ART_DIR/admin_disable_user.json" -w '%{http_code}' -H 'Content-Type: application/json' -H "Authorization: Bearer ${ADMIN_TOKEN}" -X POST "${UI_API_URL}/api/users/${RBAC_USER}/disable" -d '{}')"
[[ "$ADMIN_DISABLE_USER_CODE" == "200" ]] || { echo "FAIL: admin /api/users/:id/disable expected 200 got ${ADMIN_DISABLE_USER_CODE}" >&2; exit 1; }

ADMIN_INCIDENTS_CODE="$(curl -sS -o "$ART_DIR/admin_incidents.json" -w '%{http_code}' -H "Authorization: Bearer ${ADMIN_TOKEN}" "${UI_API_URL}/api/incidents?limit=20")"
ANALYST_INCIDENTS_CODE="$(curl -sS -o "$ART_DIR/analyst_incidents.json" -w '%{http_code}' -H "Authorization: Bearer ${ANALYST_TOKEN}" "${UI_API_URL}/api/incidents?limit=20")"
[[ "$ADMIN_INCIDENTS_CODE" == "200" ]] || { echo "FAIL: admin incidents expected 200 got ${ADMIN_INCIDENTS_CODE}" >&2; exit 1; }
[[ "$ANALYST_INCIDENTS_CODE" == "200" ]] || { echo "FAIL: analyst incidents expected 200 got ${ANALYST_INCIDENTS_CODE}" >&2; exit 1; }

ADMIN_DASH_CODE="$(curl -sS -o "$ART_DIR/admin_dashboard_summary.json" -w '%{http_code}' -H "Authorization: Bearer ${ADMIN_TOKEN}" "${UI_API_URL}/api/dashboard/summary?window=24h")"
ANALYST_DASH_CODE="$(curl -sS -o "$ART_DIR/analyst_dashboard_summary.json" -w '%{http_code}' -H "Authorization: Bearer ${ANALYST_TOKEN}" "${UI_API_URL}/api/dashboard/summary?window=24h")"
[[ "$ADMIN_DASH_CODE" == "200" ]] || { echo "FAIL: admin dashboard expected 200 got ${ADMIN_DASH_CODE}" >&2; exit 1; }
[[ "$ANALYST_DASH_CODE" == "200" ]] || { echo "FAIL: analyst dashboard expected 200 got ${ANALYST_DASH_CODE}" >&2; exit 1; }

SMOKE_RUN_ID="ui_smoke_${TS}"
ADMIN_APPROVE_CODE="$(curl -sS -o "$ART_DIR/admin_approve.json" -w '%{http_code}' -H 'Content-Type: application/json' -H "Authorization: Bearer ${ADMIN_TOKEN}" -X POST "${UI_API_URL}/api/incidents/${SMOKE_RUN_ID}/approve" -d '{"decision":"approve","actor":"admin"}')"
ANALYST_APPROVE_CODE="$(curl -sS -o "$ART_DIR/analyst_approve.json" -w '%{http_code}' -H 'Content-Type: application/json' -H "Authorization: Bearer ${ANALYST_TOKEN}" -X POST "${UI_API_URL}/api/incidents/${SMOKE_RUN_ID}/approve" -d '{"decision":"approve","actor":"analyst"}')"
[[ "$ADMIN_APPROVE_CODE" == "200" ]] || { echo "FAIL: admin approve expected 200 got ${ADMIN_APPROVE_CODE}" >&2; exit 1; }
[[ "$ANALYST_APPROVE_CODE" == "200" ]] || { echo "FAIL: analyst approve expected 200 got ${ANALYST_APPROVE_CODE}" >&2; exit 1; }

echo "[5/8] dashboard endpoints"
DASH_SUMMARY="$(curl -sS --max-time 8 -H "Authorization: Bearer ${ANALYST_TOKEN}" "${UI_API_URL}/api/dashboard/summary?window=24h")"
DASH_INC="$(curl -sS --max-time 8 -H "Authorization: Bearer ${ANALYST_TOKEN}" "${UI_API_URL}/api/dashboard/series/incidents?window=24h&bucket=1h")"
DASH_SEV="$(curl -sS --max-time 8 -H "Authorization: Bearer ${ANALYST_TOKEN}" "${UI_API_URL}/api/dashboard/series/severity?window=24h")"
DASH_LANES="$(curl -sS --max-time 8 -H "Authorization: Bearer ${ANALYST_TOKEN}" "${UI_API_URL}/api/dashboard/series/lanes?window=24h")"
DASH_TOP="$(curl -sS --max-time 8 -H "Authorization: Bearer ${ANALYST_TOKEN}" "${UI_API_URL}/api/dashboard/top/entities?window=1h")"

printf '%s\n' "$DASH_SUMMARY" > "$ART_DIR/dashboard_summary.json"
printf '%s\n' "$DASH_INC" > "$ART_DIR/dashboard_incidents.json"
printf '%s\n' "$DASH_SEV" > "$ART_DIR/dashboard_severity.json"
printf '%s\n' "$DASH_LANES" > "$ART_DIR/dashboard_lanes.json"
printf '%s\n' "$DASH_TOP" > "$ART_DIR/dashboard_top.json"

jq -e '.incidents_last_window >= 0 and .approvals_pending >= 0 and .failed_safe_count >= 0 and .endpoints_active >= 0' "$ART_DIR/dashboard_summary.json" >/dev/null
jq -e '.items | type == "array"' "$ART_DIR/dashboard_incidents.json" >/dev/null
jq -e '.items | type == "array"' "$ART_DIR/dashboard_severity.json" >/dev/null
jq -e '.items | type == "array"' "$ART_DIR/dashboard_lanes.json" >/dev/null
jq -e '.src_ip | type == "array"' "$ART_DIR/dashboard_top.json" >/dev/null

echo "[6/8] geo endpoints"
GEO_JSON="$(curl -sS --max-time 8 -H "Authorization: Bearer ${ANALYST_TOKEN}" "${UI_API_URL}/api/endpoints/geo?window=1h")"
printf '%s\n' "$GEO_JSON" > "$ART_DIR/endpoints_geo.json"
jq -e '.endpoints | type == "array"' "$ART_DIR/endpoints_geo.json" >/dev/null
jq -e '(.endpoints | length) == 0 or ([.endpoints[] | ((.node_id|type=="string") and (.geo.source|type=="string"))] | all)' "$ART_DIR/endpoints_geo.json" >/dev/null
GEO_COUNT="$(jq -r '.endpoints | length' "$ART_DIR/endpoints_geo.json")"
GEO_HIST="$(jq -c '[.endpoints[].geo.source] | reduce .[] as $s ({}; .[$s] = (.[$s] // 0) + 1)' "$ART_DIR/endpoints_geo.json")"

echo "[7/8] SSE first event"
SSE_RAW="$({ curl -sS --max-time 10 -N "${UI_API_URL}/api/stream?token=${ANALYST_TOKEN}" 2>/dev/null || true; } | awk '/^data: /{print substr($0,7); exit}')"
[[ -n "$SSE_RAW" ]] || { echo "FAIL: SSE stream returned no data event" >&2; exit 1; }
printf '%s\n' "$SSE_RAW" > "$ART_DIR/sse_first_event.json"

echo "[8/8] write proof"

jq -n \
  --arg timestamp "$RFC3339" \
  --arg ui_web_url "$UI_WEB_URL" \
  --arg ui_api_url "$UI_API_URL" \
  --arg run_id "$SMOKE_RUN_ID" \
  --argjson geo_endpoint_count "${GEO_COUNT}" \
  --argjson geo_sources "${GEO_HIST}" \
  --argjson admin_ok true \
  --argjson analyst_ok true \
  --argjson analyst_user_mgmt_denied true \
  --argjson dashboard_ok true \
  '{
    timestamp: $timestamp,
    ui_web_url: $ui_web_url,
    ui_api_url: $ui_api_url,
    run_id: $run_id,
    rbac: {
      admin_ok: $admin_ok,
      analyst_ok: $analyst_ok,
      analyst_user_mgmt_denied: $analyst_user_mgmt_denied
    },
    geo_endpoint_count: $geo_endpoint_count,
    geo_sources: $geo_sources,
    dashboard_ok: $dashboard_ok,
    pass: true
  }' > "$ART_DIR/fr06_ui_smoke_proof.json"

echo "PASS: FR-06 UI smoke completed"
echo "FR06_UI_SMOKE_PROOF_JSON=${ART_DIR}/fr06_ui_smoke_proof.json"
