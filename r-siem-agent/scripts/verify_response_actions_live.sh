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

for cmd in curl jq nmap; do
  need_cmd "$cmd"
done

UI_API_URL="${UI_API_URL:-http://127.0.0.1:8090}"
ART_DIR="${ART_DIR:-/tmp/rsiem_response_actions_live_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$ART_DIR"

echo "ART_DIR=$ART_DIR"

for _ in $(seq 1 30); do
  if curl -sS --max-time 3 "${UI_API_URL}/api/health" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

LOGIN_JSON="$(curl -sS --max-time 8 -H 'Content-Type: application/json' -X POST "${UI_API_URL}/api/auth/login" -d '{"username":"analyst","password":"analyst123"}')"
TOKEN="$(printf '%s' "$LOGIN_JSON" | jq -r '.token // empty')"
[[ -n "$TOKEN" ]] || { echo "FAIL: unable to obtain analyst token" >&2; exit 1; }

date '+SCAN_START %F %T %z'
nmap -Pn -n -sT -T3 --scan-delay 400ms --max-retries 1 -p 3389,5985 172.30.50.11 172.30.50.12 172.30.50.13 172.30.50.14 >/dev/null
date '+SCAN_END %F %T %z'

sleep 4

INCIDENTS_JSON="$(curl -sS --max-time 10 -H "Authorization: Bearer ${TOKEN}" "${UI_API_URL}/api/incidents?rule_id=R-NET-INTERNAL-WINRM-SCAN&limit=5")"
printf '%s\n' "$INCIDENTS_JSON" > "$ART_DIR/incidents.json"
RUN_ID="$(printf '%s' "$INCIDENTS_JSON" | jq -r '.items[0].run_id // empty')"
NODE_ID="$(printf '%s' "$INCIDENTS_JSON" | jq -r '.items[0].node_id // empty')"
[[ -n "$RUN_ID" && -n "$NODE_ID" ]] || { echo "FAIL: missing incident run_id or node_id" >&2; exit 1; }

echo "RUN_ID=$RUN_ID"
echo "NODE_ID=$NODE_ID"

INCIDENT_ACTION_JSON="$(curl -sS --max-time 10 -H 'Content-Type: application/json' -H "Authorization: Bearer ${TOKEN}" \
  -X POST "${UI_API_URL}/api/incidents/${RUN_ID}/actions" \
  -d '{"actor":"analyst","action_name":"block_matching_connections","duration_ms":60000,"reason":"live_smoke_incident_action","reference":"smoke-incident-1"}')"
printf '%s\n' "$INCIDENT_ACTION_JSON" > "$ART_DIR/incident_action_launch.json"
INCIDENT_ACTION_ID="$(printf '%s' "$INCIDENT_ACTION_JSON" | jq -r '.action.action_id // empty')"
[[ -n "$INCIDENT_ACTION_ID" ]] || { echo "FAIL: incident action launch failed" >&2; cat "$ART_DIR/incident_action_launch.json" >&2; exit 1; }

INCIDENT_ACTIONS_JSON="$(curl -sS --max-time 10 -H "Authorization: Bearer ${TOKEN}" "${UI_API_URL}/api/incidents/${RUN_ID}/actions")"
printf '%s\n' "$INCIDENT_ACTIONS_JSON" > "$ART_DIR/incident_actions_before_clear.json"
INCIDENT_BUCKET="$(printf '%s' "$INCIDENT_ACTIONS_JSON" | jq -r --arg id "$INCIDENT_ACTION_ID" '.items[] | select(.action_id==$id) | .bucket' | head -n1)"
[[ "$INCIDENT_BUCKET" == "active" ]] || { echo "FAIL: incident action not active" >&2; exit 1; }

curl -sS --max-time 10 -H 'Content-Type: application/json' -H "Authorization: Bearer ${TOKEN}" \
  -X POST "${UI_API_URL}/api/incidents/${RUN_ID}/actions/${INCIDENT_ACTION_ID}/clear" \
  -d '{"actor":"analyst","reason":"live_smoke_incident_clear","reference":"smoke-incident-clear-1"}' > "$ART_DIR/incident_action_clear.json"

INCIDENT_ACTIONS_AFTER="$(curl -sS --max-time 10 -H "Authorization: Bearer ${TOKEN}" "${UI_API_URL}/api/incidents/${RUN_ID}/actions")"
printf '%s\n' "$INCIDENT_ACTIONS_AFTER" > "$ART_DIR/incident_actions_after_clear.json"
INCIDENT_BUCKET_AFTER="$(printf '%s' "$INCIDENT_ACTIONS_AFTER" | jq -r --arg id "$INCIDENT_ACTION_ID" '.items[] | select(.action_id==$id) | .bucket' | head -n1)"
[[ "$INCIDENT_BUCKET_AFTER" == "cleared" ]] || { echo "FAIL: incident action not cleared" >&2; exit 1; }

ENDPOINT_ACTION_JSON="$(curl -sS --max-time 10 -H 'Content-Type: application/json' -H "Authorization: Bearer ${TOKEN}" \
  -X POST "${UI_API_URL}/api/endpoints/${NODE_ID}/actions" \
  -d '{"actor":"analyst","action_name":"block_matching_connections","duration_ms":60000,"reason":"live_smoke_endpoint_action","reference":"smoke-endpoint-1","target":"203.0.113.10","target_agent_id":"'"${NODE_ID}"'"}')"
printf '%s\n' "$ENDPOINT_ACTION_JSON" > "$ART_DIR/endpoint_action_launch.json"
ENDPOINT_ACTION_ID="$(printf '%s' "$ENDPOINT_ACTION_JSON" | jq -r '.action.action_id // empty')"
[[ -n "$ENDPOINT_ACTION_ID" ]] || { echo "FAIL: endpoint action launch failed" >&2; cat "$ART_DIR/endpoint_action_launch.json" >&2; exit 1; }

ENDPOINT_ACTIONS_JSON="$(curl -sS --max-time 10 -H "Authorization: Bearer ${TOKEN}" "${UI_API_URL}/api/endpoints/${NODE_ID}/actions")"
printf '%s\n' "$ENDPOINT_ACTIONS_JSON" > "$ART_DIR/endpoint_actions_before_clear.json"
ENDPOINT_BUCKET="$(printf '%s' "$ENDPOINT_ACTIONS_JSON" | jq -r --arg id "$ENDPOINT_ACTION_ID" '.items[] | select(.action_id==$id) | .bucket' | head -n1)"
[[ "$ENDPOINT_BUCKET" == "active" ]] || { echo "FAIL: endpoint action not active" >&2; exit 1; }

curl -sS --max-time 10 -H 'Content-Type: application/json' -H "Authorization: Bearer ${TOKEN}" \
  -X POST "${UI_API_URL}/api/endpoints/${NODE_ID}/actions/${ENDPOINT_ACTION_ID}/clear" \
  -d '{"actor":"analyst","reason":"live_smoke_endpoint_clear","reference":"smoke-endpoint-clear-1"}' > "$ART_DIR/endpoint_action_clear.json"

ENDPOINT_ACTIONS_AFTER="$(curl -sS --max-time 10 -H "Authorization: Bearer ${TOKEN}" "${UI_API_URL}/api/endpoints/${NODE_ID}/actions")"
printf '%s\n' "$ENDPOINT_ACTIONS_AFTER" > "$ART_DIR/endpoint_actions_after_clear.json"
ENDPOINT_BUCKET_AFTER="$(printf '%s' "$ENDPOINT_ACTIONS_AFTER" | jq -r --arg id "$ENDPOINT_ACTION_ID" '.items[] | select(.action_id==$id) | .bucket' | head -n1)"
[[ "$ENDPOINT_BUCKET_AFTER" == "cleared" ]] || { echo "FAIL: endpoint action not cleared" >&2; exit 1; }

FLEET_ACTIONS_JSON="$(curl -sS --max-time 10 -H "Authorization: Bearer ${TOKEN}" "${UI_API_URL}/api/actions?q=smoke&page=1&limit=20")"
printf '%s\n' "$FLEET_ACTIONS_JSON" > "$ART_DIR/fleet_actions.json"

echo "PASS: live response actions verified"
echo "  incident_action_id=$INCIDENT_ACTION_ID"
echo "  endpoint_action_id=$ENDPOINT_ACTION_ID"
echo "  artifacts=$ART_DIR"
