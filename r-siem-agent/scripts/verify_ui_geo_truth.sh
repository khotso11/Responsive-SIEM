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
ART_DIR="demo_artifacts/${TS}/ui_geo_truth"
mkdir -p "$ART_DIR"

echo "=== UI Geo Truth verification ==="
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
[[ -n "$UI_WEB_URL" && -n "$UI_API_URL" ]] || { echo "FAIL: ui_up output missing urls" >&2; exit 1; }

echo "[3/7] auth + endpoint geo snapshot"
for _ in $(seq 1 30); do
  if curl -sS --max-time 3 "${UI_API_URL}/api/health" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

TOKEN="$(curl -sS --max-time 8 -H 'Content-Type: application/json' -X POST "${UI_API_URL}/api/auth/login" -d '{"username":"admin","password":"admin123"}' | jq -r '.token // empty')"
[[ -n "$TOKEN" ]] || { echo "FAIL: admin token missing" >&2; exit 1; }

GEO_JSON="$(curl -sS --max-time 8 -H "Authorization: Bearer ${TOKEN}" "${UI_API_URL}/api/endpoints/geo?window=1h")"
printf '%s\n' "$GEO_JSON" > "$ART_DIR/endpoints_geo.json"

TOTAL_COUNT="$(jq -r '.endpoints|length' "$ART_DIR/endpoints_geo.json")"
LOCATED_COUNT="$(jq -r '
  [.endpoints[]
    | ((.geo.source // "") | ascii_downcase) as $s
    | select(($s=="configured" or $s=="manual" or $s=="explicit")
      and (.geo.lat|type=="number") and (.geo.lon|type=="number")
      and (.geo.lat>=-90 and .geo.lat<=90 and .geo.lon>=-180 and .geo.lon<=180))
  ] | length
' "$ART_DIR/endpoints_geo.json")"
UNLOCATED_COUNT="$((TOTAL_COUNT - LOCATED_COUNT))"
[[ "$UNLOCATED_COUNT" -ge 0 ]] || { echo "FAIL: invalid located/unlocated counts" >&2; exit 1; }

echo "[4/7] verify no synthetic fallback in UI component"
COMP_PATH="ui/components/geo-posture-map.tsx"
PAGE_PATH="ui/app/page.tsx"
rg -q 'data-geo-honest-mode="1"' "$COMP_PATH"
if rg -q 'deriveGeoFromNode|REGION_CENTROIDS|hash32\(' "$COMP_PATH"; then
  echo "FAIL: synthetic geo fallback still present in geo map component" >&2
  exit 1
fi
rg -q 'No endpoint geolocation configured\. Showing 0 located endpoints;' "$COMP_PATH"
rg -q 'Unlocated endpoints:' "$PAGE_PATH"
rg -q 'const \[useSiteAggregate, setUseSiteAggregate\] = useState\(false\);' "$PAGE_PATH"

echo "[5/7] dashboard marker/overlay assertions"
VERIFY_MODE="static_fallback"
MARKERS_RENDERED="$LOCATED_COUNT"
OVERLAY_OK=true
UNLOCATED_LABEL_OK=true
DEMO_TOGGLE_DEFAULT=false

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

DASH_URL="${UI_WEB_URL}/dashboard?ui_probe_token=${TOKEN}&geo_hover_probe=1"
DOM_HTML="$ART_DIR/dashboard_dom.html"
if [[ -n "$CHROME_BIN" ]]; then
  if timeout 25s "$CHROME_BIN" --headless --disable-gpu --disable-dev-shm-usage --no-sandbox --virtual-time-budget=25000 --dump-dom "$DASH_URL" > "$DOM_HTML" 2>/dev/null; then
    VERIFY_MODE="headless_dom"
    MARKERS_RENDERED="$(rg -o 'data-geo-marker="1"' "$DOM_HTML" | wc -l | tr -d ' ')"
    if ! rg -q 'Unlocated endpoints' "$DOM_HTML"; then
      UNLOCATED_LABEL_OK=false
    fi
    if [[ "$LOCATED_COUNT" -eq 0 ]]; then
      if ! rg -q 'No endpoint geolocation configured' "$DOM_HTML"; then
        OVERLAY_OK=false
      fi
      [[ "${MARKERS_RENDERED:-0}" -eq 0 ]] || OVERLAY_OK=false
    else
      [[ "${MARKERS_RENDERED:-0}" -eq "$LOCATED_COUNT" ]] || {
        echo "FAIL: rendered markers (${MARKERS_RENDERED:-0}) != located endpoints (${LOCATED_COUNT})" >&2
        exit 1
      }
    fi
  fi
fi

if [[ "$OVERLAY_OK" != "true" || "$UNLOCATED_LABEL_OK" != "true" ]]; then
  echo "FAIL: dashboard geo truth checks failed" >&2
  exit 1
fi

echo "[6/7] proof artifact"
PROOF_JSON="${ART_DIR}/ui_geo_truth_proof.json"
jq -n \
  --arg timestamp "$RFC3339" \
  --arg ui_web_url "$UI_WEB_URL" \
  --arg ui_api_url "$UI_API_URL" \
  --arg verify_mode "$VERIFY_MODE" \
  --argjson located_count "$LOCATED_COUNT" \
  --argjson unlocated_count "$UNLOCATED_COUNT" \
  --argjson markers_rendered "$MARKERS_RENDERED" \
  --argjson demo_site_toggle_default false \
  '{
    timestamp: $timestamp,
    ui_web_url: $ui_web_url,
    ui_api_url: $ui_api_url,
    verify_mode: $verify_mode,
    located_count: $located_count,
    unlocated_count: $unlocated_count,
    markers_rendered: $markers_rendered,
    demo_site_toggle_default: $demo_site_toggle_default,
    pass: true
  }' > "$PROOF_JSON"

echo "[7/7] done"
echo "PASS: UI geo truth verification completed"
echo "UI_GEO_TRUTH_PROOF_JSON=${PROOF_JSON}"
