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

EVE_UI_URL="${RSIEM_EVE_NG_UI_URL:-http://192.168.59.128/}"
EVE_API_BASE_URL="${RSIEM_EVE_NG_API_BASE_URL:-http://192.168.59.128}"
EVE_API_LAB_PATH="${RSIEM_EVE_NG_API_LAB_PATH:-/R-SIEM/rsiem-infrastructure.unl}"
EVE_USERNAME="${RSIEM_EVE_NG_USERNAME:-}"
EVE_PASSWORD="${RSIEM_EVE_NG_PASSWORD:-}"

TS="$(date +%Y%m%d_%H%M%S)"
ART_DIR="demo_artifacts/${TS}"
mkdir -p "$ART_DIR"
PROOF_JSON="${ART_DIR}/eve_ng_vm_integration_proof.json"

COOKIE_JAR="$(mktemp)"
trap 'rm -f "$COOKIE_JAR"' EXIT

UI_HTTP_CODE="$(curl -sS -L -o /dev/null -w '%{http_code}' --max-time 10 "$EVE_UI_URL")"
[[ "$UI_HTTP_CODE" =~ ^(200|301|302|303|307|308)$ ]] || {
  echo "FAIL: EVE UI is not reachable at ${EVE_UI_URL} (http=${UI_HTTP_CODE})" >&2
  exit 1
}

[[ -n "$EVE_USERNAME" && -n "$EVE_PASSWORD" ]] || {
  echo "FAIL: set RSIEM_EVE_NG_USERNAME and RSIEM_EVE_NG_PASSWORD before running this verifier" >&2
  exit 1
}

LOGIN_PAYLOAD="$(jq -nc --arg username "$EVE_USERNAME" --arg password "$EVE_PASSWORD" '{username:$username,password:$password}')"
LOGIN_JSON="$(curl -sS --max-time 10 -c "$COOKIE_JAR" -b "$COOKIE_JAR" -H 'Content-Type: application/json' -X POST "${EVE_API_BASE_URL%/}/api/auth/login" -d "$LOGIN_PAYLOAD")"
LOGIN_STATUS="$(printf '%s' "$LOGIN_JSON" | jq -r '.status // empty')"
[[ "$LOGIN_STATUS" == "success" ]] || {
  echo "FAIL: EVE API login failed" >&2
  printf '%s\n' "$LOGIN_JSON" | jq '.' >&2 || true
  exit 1
}

ENCODED_LAB_PATH="${EVE_API_LAB_PATH#/}"
NODES_JSON="$(curl -sS --max-time 10 -c "$COOKIE_JAR" -b "$COOKIE_JAR" -H 'Content-Type: application/json' "${EVE_API_BASE_URL%/}/api/labs/${ENCODED_LAB_PATH}/nodes")"
NODES_STATUS="$(printf '%s' "$NODES_JSON" | jq -r '.status // empty')"
[[ "$NODES_STATUS" == "success" ]] || {
  echo "FAIL: EVE lab node listing failed" >&2
  printf '%s\n' "$NODES_JSON" | jq '.' >&2 || true
  exit 1
}

NODE_COUNT="$(printf '%s' "$NODES_JSON" | jq '.data | length')"
[[ "$NODE_COUNT" -gt 0 ]] || {
  echo "FAIL: EVE lab returned zero nodes" >&2
  exit 1
}

printf '%s\n' "$NODES_JSON" | jq \
  --arg verified_at "$(date --iso-8601=seconds)" \
  --arg eve_ui_url "$EVE_UI_URL" \
  --arg eve_api_base_url "$EVE_API_BASE_URL" \
  --arg eve_api_lab_path "$EVE_API_LAB_PATH" \
  '{
    verified_at: $verified_at,
    eve_ui_url: $eve_ui_url,
    eve_api_base_url: $eve_api_base_url,
    eve_api_lab_path: $eve_api_lab_path,
    node_count: (.data | length),
    runtime_breakdown: (reduce (.data[] | (.status | tostring)) as $s ({}; .[$s] = (.[$s] // 0) + 1)),
    nodes: [.data[] | {id: (.id|tostring), name, status: (.status|tostring), url, image}]
  }' > "$PROOF_JSON"

echo "PASS: EVE VM integration verified"
echo "EVE_VM_INTEGRATION_PROOF_JSON=${PROOF_JSON}"
