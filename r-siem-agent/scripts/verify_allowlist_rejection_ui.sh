#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

NATS_URL="${NATS_URL:-nats://127.0.0.1:4222}"
UI_API_URL="${UI_API_URL:-http://127.0.0.1:8090}"
UI_WEB_URL="${UI_WEB_URL:-http://127.0.0.1:3200}"
EXPECTED_DENY_RULE="${EXPECTED_DENY_RULE:-deny_proc_first_seen_other_agent_commands}"
TEMP_CONFIG="${TEMP_CONFIG:-tmp/master_lan_db.allowlist_reject.yaml}"
PROCESS_WAIT_SECS="${PROCESS_WAIT_SECS:-6}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "FAIL: missing command: $1" >&2
    exit 1
  }
}

for cmd in jq curl nats rg perl sed tail; do
  need_cmd "$cmd"
done

new_lines() {
  local file="$1"
  local start_line="$2"
  if [ ! -f "$file" ]; then
    return 0
  fi
  tail -n +"$((start_line + 1))" "$file"
}

line_count() {
  local file="$1"
  if [ -f "$file" ]; then
    wc -l < "$file"
  else
    echo 0
  fi
}

extract_run_id() {
  sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p' | tail -n 1
}

restart_repo_stack_with_config() {
  local cfg="$1"
  pkill -f '/master-roe --config' 2>/dev/null || true
  pkill -f '/master-roe-worker --config' 2>/dev/null || true
  pkill -f 'go run -mod=vendor ./cmd/master-roe --config' 2>/dev/null || true
  pkill -f 'go run -mod=vendor ./cmd/master-roe-worker --config' 2>/dev/null || true
  pkill -f '/detector-v0 --config' 2>/dev/null || true
  pkill -f 'go run -mod=vendor ./cmd/detector-v0 --config' 2>/dev/null || true
  sleep 2

  env GOCACHE="$ROOT_DIR/.cache/go-build" go run -mod=vendor ./cmd/master-roe --config "$cfg" >> logs/master-roe.log 2>&1 &
  echo $! > .pids/master-roe.pid

  env GOCACHE="$ROOT_DIR/.cache/go-build" go run -mod=vendor ./cmd/master-roe-worker --config "$cfg" --lane BOTH >> logs/worker.log 2>&1 &
  echo $! > .pids/worker.pid

  env GOCACHE="$ROOT_DIR/.cache/go-build" go run -mod=vendor ./cmd/detector-v0 --config configs/detector.yaml >> logs/detector.log 2>&1 &
  echo $! > .pids/detector.pid

  sleep 3
  rg -n '"msg":"db_sink_enabled"' logs/master-roe.log | tail -n 1 >/dev/null || {
    echo "FAIL: db_sink_enabled not observed after restarting stack with $cfg" >&2
    exit 1
  }
}

build_mismatch_config() {
  cp tmp/master_lan_db.yaml "$TEMP_CONFIG"
  perl -0pi -e '
    s/(  - id: "PB-PROC-FIRST-SEEN-CONTAIN".*?          command: )"contain_process_exec"/${1}"auth_contain_src_ip"/s
  ' "$TEMP_CONFIG"

  if ! rg -q 'PB-PROC-FIRST-SEEN-CONTAIN' "$TEMP_CONFIG"; then
    echo "FAIL: temporary config missing PB-PROC-FIRST-SEEN-CONTAIN" >&2
    exit 1
  fi
  if ! rg -q 'command: "auth_contain_src_ip"' "$TEMP_CONFIG"; then
    echo "FAIL: temporary config did not inject mismatched command" >&2
    exit 1
  fi
}

trigger_process_first_seen() {
  local before_master="$1"
  local now_ms proof_user payload
  now_ms="$(date +%s%3N)"
  proof_user="proof_reject_${now_ms}"
  payload="$(
    jq -cn \
      --arg evt "evt.allowlist.reject.proc.${now_ms}" \
      --arg now "$now_ms" \
      --arg node "$(hostname)" \
      --arg user "$proof_user" \
      '{
        event_idem_key:$evt,
        observed_at_unix_ms:($now|tonumber),
        event_ts_unix_ms:($now|tonumber),
        recv_ts_unix_ms:($now|tonumber),
        message:"PROC exec=\"/usr/bin/nmap\" comm=\"nmap\" cmdline=\"/usr/bin/nmap --version\" user=\($user) src=127.0.0.1 ts=\($now) node=\($node)",
        raw_line:"PROC exec=\"/usr/bin/nmap\"",
        host:$node,
        node_id:$node,
        group_key:$node,
        source:"allowlist_reject_proof",
        source_type:"auditd_exec",
        event_type:"process_exec",
        src_ip:"127.0.0.1",
        user:$user,
        exec_path:"/usr/bin/nmap",
        comm:"nmap",
        cmdline:"/usr/bin/nmap --version",
        exec_sha256:"proof-sha256",
        signer_hint:"unsigned"
      }'
  )"
  nats --server "$NATS_URL" pub rsiem.events.raw "$payload" >/dev/null
  sleep "$PROCESS_WAIT_SECS"
  new_lines logs/master-roe.log "$before_master" \
    | rg "\"msg\":\"response_run_rejected\".*\"allowlist_rule_id\":\"${EXPECTED_DENY_RULE}\"" \
    | extract_run_id
}

fetch_token() {
  curl -sS --max-time 8 \
    -H 'Content-Type: application/json' \
    -X POST "${UI_API_URL}/api/auth/login" \
    -d '{"username":"admin","password":"admin123"}' | jq -r '.token // empty'
}

echo "[1/6] Clean-starting the stack"
INJECT_DEMO_EVENT=0 ./scripts/demo_local_endpoint_clean_start.sh >/tmp/verify_allowlist_reject_clean_start.out
tail -n 10 /tmp/verify_allowlist_reject_clean_start.out

echo "[2/6] Building mismatched runtime config"
build_mismatch_config
echo "TEMP_CONFIG=${TEMP_CONFIG}"

echo "[3/6] Restarting stack with mismatched policy config"
restart_repo_stack_with_config "$TEMP_CONFIG"

echo "[4/6] Triggering intentionally rejected process first-seen run"
before_master="$(line_count logs/master-roe.log)"
run_id="$(trigger_process_first_seen "$before_master" || true)"
if [ -z "${run_id}" ]; then
  echo "FAIL: did not observe response_run_rejected with allowlist deny rule ${EXPECTED_DENY_RULE}" >&2
  new_lines logs/master-roe.log "$before_master" | tail -n 40 >&2 || true
  exit 1
fi
echo "RUN_ID=${run_id}"
new_lines logs/master-roe.log "$before_master" | rg "\"run_id\":\"${run_id}\"|response_run_rejected" | tail -n 20 || true

echo "[5/6] Verifying incident API view"
TOKEN="$(fetch_token)"
if [ -z "$TOKEN" ]; then
  echo "FAIL: unable to obtain admin token from ${UI_API_URL}" >&2
  exit 1
fi
INCIDENT_JSON="$(curl -sS --max-time 8 -H "Authorization: Bearer ${TOKEN}" "${UI_API_URL}/api/incidents/${run_id}")"
printf '%s\n' "$INCIDENT_JSON" | jq .

ACTUAL_FAILED_SAFE_REASON="$(printf '%s\n' "$INCIDENT_JSON" | jq -r '.run.failed_safe_reason // empty')"
ACTUAL_ALLOWLIST_RULE_ID="$(printf '%s\n' "$INCIDENT_JSON" | jq -r '.run.allowlist_rule_id // empty')"

if [[ "$ACTUAL_FAILED_SAFE_REASON" != "policy_rejected" ]]; then
  echo "FAIL: expected failed_safe_reason=policy_rejected got ${ACTUAL_FAILED_SAFE_REASON}" >&2
  exit 1
fi
if [[ "$ACTUAL_ALLOWLIST_RULE_ID" != "$EXPECTED_DENY_RULE" ]]; then
  echo "FAIL: expected allowlist_rule_id=${EXPECTED_DENY_RULE} got ${ACTUAL_ALLOWLIST_RULE_ID}" >&2
  exit 1
fi

echo "[6/6] PASS: rejected incident view carries allowlist_rule_id"
echo "RUN_ID=${run_id}"
echo "UI_INCIDENT_URL=${UI_WEB_URL}/incidents/${run_id}"
echo "FAILED_SAFE_REASON=${ACTUAL_FAILED_SAFE_REASON}"
echo "ALLOWLIST_RULE_ID=${ACTUAL_ALLOWLIST_RULE_ID}"
