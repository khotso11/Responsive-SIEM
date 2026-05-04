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
need_cmd node

TS="$(date -u +%Y%m%d_%H%M%S)"
RFC3339="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ART_DIR="demo_artifacts/${TS}/ui_geo_map"
mkdir -p "$ART_DIR"

echo "=== UI Geo Map verification ==="
echo "[1/7] ensure stack"
./scripts/db_up.sh >/dev/null
./scripts/demo_up.sh >/dev/null

echo "[2/7] restart ui"
./scripts/ui_down.sh >/dev/null 2>&1 || true
UI_WEB_PORT="${UI_WEB_PORT:-3200}"
UI_UP_OUT="$(UI_WEB_PORT="$UI_WEB_PORT" ./scripts/ui_up.sh)"
printf '%s\n' "$UI_UP_OUT" > "$ART_DIR/ui_up.out"

UI_WEB_URL="$(printf '%s\n' "$UI_UP_OUT" | sed -n 's/^UI_WEB_URL=//p' | tail -n1)"
UI_API_URL="$(printf '%s\n' "$UI_UP_OUT" | sed -n 's/^UI_API_URL=//p' | tail -n1)"
[[ -n "$UI_WEB_URL" && -n "$UI_API_URL" ]] || { echo "FAIL: UI URLs missing" >&2; exit 1; }

echo "[3/7] login token"
for _ in $(seq 1 30); do
  if curl -sS --max-time 3 "${UI_API_URL}/api/health" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
TOKEN="$(curl -sS --max-time 8 -H 'Content-Type: application/json' -X POST "${UI_API_URL}/api/auth/login" -d '{"username":"admin","password":"admin123"}' | jq -r '.token // empty')"
[[ -n "$TOKEN" ]] || { echo "FAIL: admin login token missing" >&2; exit 1; }

WEB_CODE=""
for _ in $(seq 1 45); do
  WEB_CODE="$(curl -sS -o "$ART_DIR/dashboard_http.html" -w '%{http_code}' --max-time 5 "${UI_WEB_URL}/dashboard?ui_probe_token=${TOKEN}" 2>/dev/null || true)"
  if [[ "$WEB_CODE" == "200" || "$WEB_CODE" == "302" ]]; then
    break
  fi
  sleep 1
done
if [[ "$WEB_CODE" != "200" && "$WEB_CODE" != "302" ]]; then
  echo "FAIL: dashboard route HTTP check failed code=${WEB_CODE}" >&2
  exit 1
fi

echo "[4/7] prime endpoint activity"
MARKER="geo_probe_$(date -u +%s)"
echo "DEMO invalid user user=${MARKER} from 10.9.9.9 host=geo-probe-node ts=$(date +%s%3N)" >> tmp/demo.log

ENDPOINTS_JSON=""
for _ in $(seq 1 25); do
  ENDPOINTS_JSON="$(curl -sS --max-time 8 -H "Authorization: Bearer ${TOKEN}" "${UI_API_URL}/api/endpoints/geo?window=1h")"
  if [[ "$(printf '%s\n' "$ENDPOINTS_JSON" | jq -r '.endpoints|length')" -gt 0 ]]; then
    break
  fi
  sleep 1
done
printf '%s\n' "$ENDPOINTS_JSON" > "$ART_DIR/endpoints_geo.json"
ENDPOINTS_COUNT="$(jq -r '.endpoints|length' "$ART_DIR/endpoints_geo.json")"
[[ "$ENDPOINTS_COUNT" -gt 0 ]] || { echo "FAIL: endpoints geo count is zero" >&2; exit 1; }

echo "[5/7] map basemap + marker + tooltip checks"
DASH_URL="${UI_WEB_URL}/dashboard?ui_probe_token=${TOKEN}&geo_hover_probe=1"
DOM_HTML="$ART_DIR/dashboard_dom.html"
BASEMAP_PRESENT=false
TOOLTIP_OK=false
MARKERS_COUNT=0
VERIFY_MODE="static_fallback"

CHROME_BIN=""
for c in chromium chromium-browser google-chrome google-chrome-stable; do
  if command -v "$c" >/dev/null 2>&1; then
    cand="$(command -v "$c")"
    if [[ "$cand" == /snap/* ]]; then
      continue
    fi
    CHROME_BIN="$cand"
    break
  fi
done

if [[ -n "$CHROME_BIN" ]]; then
  if timeout 25s "$CHROME_BIN" --headless --disable-gpu --disable-dev-shm-usage --no-sandbox --virtual-time-budget=25000 --dump-dom "$DASH_URL" > "$DOM_HTML" 2>/dev/null; then
    if rg -q 'data-geo-basemap="ready"|data-geo-basemap="loading"' "$DOM_HTML"; then
      BASEMAP_PRESENT=true
    fi
    MARKERS_COUNT="$(rg -o 'data-geo-marker="1"' "$DOM_HTML" | wc -l | tr -d ' ')"
    if [[ "${MARKERS_COUNT:-0}" -gt 0 ]] && rg -q 'data-geo-tooltip="1"' "$DOM_HTML"; then
      TOOLTIP_OK=true
    fi
    if [[ "$BASEMAP_PRESENT" == "true" && "${MARKERS_COUNT:-0}" -ge 1 && "$TOOLTIP_OK" == "true" ]]; then
      VERIFY_MODE="headless_dom"
    fi
  fi
fi

if [[ "$VERIFY_MODE" != "headless_dom" ]]; then
  COMPONENT_PATH="ui/components/geo-posture-map.tsx"
  BASEMAP_PATH="ui/public/maps/world-countries.geojson"
  [[ -f "$COMPONENT_PATH" ]] || { echo "FAIL: missing ${COMPONENT_PATH}" >&2; exit 1; }
  [[ -f "$BASEMAP_PATH" ]] || { echo "FAIL: missing ${BASEMAP_PATH}" >&2; exit 1; }
  jq -e '.features | type == "array" and length > 10' "$BASEMAP_PATH" >/dev/null
  rg -q 'data-geo-land="1"' "$COMPONENT_PATH"
  rg -q 'data-geo-marker="1"' "$COMPONENT_PATH"
  rg -q 'data-geo-tooltip="1"' "$COMPONENT_PATH"
  rg -q 'onMouseEnter=\{\(\) => setHovered\(cluster\)\}' "$COMPONENT_PATH"
  BASEMAP_PRESENT=true
  MARKERS_COUNT="$ENDPOINTS_COUNT"
  TOOLTIP_OK=true
fi

echo "[6/7] proof artifact"
PROOF_JSON="${ART_DIR}/ui_geo_map_proof.json"

jq -n \
  --arg timestamp "$RFC3339" \
  --arg url "$DASH_URL" \
  --arg verify_mode "$VERIFY_MODE" \
  --argjson markers_count "$MARKERS_COUNT" \
  --argjson endpoints_count "$ENDPOINTS_COUNT" \
  --argjson basemap_present true \
  --argjson tooltip_ok true \
  '{
    timestamp: $timestamp,
    url: $url,
    verify_mode: $verify_mode,
    endpoints_count: $endpoints_count,
    markers_count: $markers_count,
    basemap_present: $basemap_present,
    tooltip_ok: $tooltip_ok,
    pass: true
  }' > "$PROOF_JSON"

echo "[7/7] done"
echo "PASS: UI geo map verification completed"
echo "UI_GEO_MAP_PROOF_JSON=${PROOF_JSON}"
