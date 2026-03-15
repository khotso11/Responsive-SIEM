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

for cmd in curl jq rg sudo; do
  need_cmd "$cmd"
done

UI_API_URL="${UI_API_URL:-http://127.0.0.1:8090}"
UI_WEB_URL="${UI_WEB_URL:-http://127.0.0.1:3100}"
OUTBOUND_URL="${OUTBOUND_URL:-https://example.com}"
SLEEP_AFTER_EVENT_SEC="${SLEEP_AFTER_EVENT_SEC:-3}"
INCIDENT_LIMIT="${INCIDENT_LIMIT:-50}"

TS="$(date +%s%3N)"
AUTH_USER="${AUTH_USER:-real_auth_${TS}}"
AUTH_SRC_IP="${AUTH_SRC_IP:-10.88.77.66}"
FILE_PROOF_PATH="${FILE_PROOF_PATH:-/etc/sudoers.d/rsiem-proof}"

echo "=== real agent event smoke ==="
echo "UI_API_URL=${UI_API_URL}"
echo "UI_WEB_URL=${UI_WEB_URL}"
echo "AUTH_USER=${AUTH_USER}"
echo "AUTH_SRC_IP=${AUTH_SRC_IP}"
echo "FILE_PROOF_PATH=${FILE_PROOF_PATH}"
echo "OUTBOUND_URL=${OUTBOUND_URL}"

for _ in $(seq 1 30); do
  if curl -sS --max-time 3 "${UI_API_URL}/api/health" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

TOKEN="$(curl -sS --max-time 8 -H 'Content-Type: application/json' \
  -X POST "${UI_API_URL}/api/auth/login" \
  -d '{"username":"admin","password":"admin123"}' | jq -r '.token // empty')"
[[ -n "$TOKEN" ]] || {
  echo "FAIL: admin token missing" >&2
  exit 1
}

BASE_MASTER="$(wc -l < logs/master-roe.log 2>/dev/null || echo 0)"
BASE_DETECTOR="$(wc -l < logs/detector.log 2>/dev/null || echo 0)"
BASE_AUDITD="$(sudo wc -l < /var/log/rsiem/collector-auditd.log 2>/dev/null || echo 0)"
BASE_TAIL="$(sudo wc -l < /var/log/rsiem/collector-tail.log 2>/dev/null || echo 0)"
BASE_INOTIFY="$(sudo wc -l < /var/log/rsiem/collector-inotify.log 2>/dev/null || echo 0)"

new_master() {
  sed -n "$((BASE_MASTER + 1)),\$p" logs/master-roe.log 2>/dev/null || true
}

new_detector() {
  sed -n "$((BASE_DETECTOR + 1)),\$p" logs/detector.log 2>/dev/null || true
}

new_auditd() {
  sudo sed -n "$((BASE_AUDITD + 1)),\$p" /var/log/rsiem/collector-auditd.log 2>/dev/null || true
}

new_tail() {
  sudo sed -n "$((BASE_TAIL + 1)),\$p" /var/log/rsiem/collector-tail.log 2>/dev/null || true
}

new_inotify() {
  sudo sed -n "$((BASE_INOTIFY + 1)),\$p" /var/log/rsiem/collector-inotify.log 2>/dev/null || true
}

echo "[1/5] Generate real auth event through /var/log/auth.log"
sudo bash -lc "printf \"%s %s sshd[12345]: Failed password for invalid user ${AUTH_USER} from ${AUTH_SRC_IP} port 51150 ssh2\\n\" \"\$(date \"+%b %e %H:%M:%S\")\" \"\$(hostname)\" >> /var/log/auth.log"
sleep "$SLEEP_AFTER_EVENT_SEC"

echo "[2/5] Generate real sensitive file activity under /etc"
sudo touch "$FILE_PROOF_PATH"
sudo rm -f "$FILE_PROOF_PATH"
sleep "$SLEEP_AFTER_EVENT_SEC"

echo "[3/5] Generate real outbound network/process activity"
curl -I --max-time 10 "$OUTBOUND_URL" >/dev/null || true
sleep "$SLEEP_AFTER_EVENT_SEC"

echo "[4/5] Collector and detector evidence"
echo "--- collector-tail ---"
new_tail | rg "${AUTH_USER}|${AUTH_SRC_IP}|collector_event_published" | tail -n 20 || true
echo "--- collector-auditd ---"
new_auditd | rg "${FILE_PROOF_PATH}|/usr/bin/curl|collector_event_published|recent_file_access_recorded" | tail -n 40 || true
echo "--- collector-inotify ---"
new_inotify | rg "${FILE_PROOF_PATH}|collector_event_published" | tail -n 20 || true
echo "--- detector ---"
new_detector | rg "${AUTH_USER}|${AUTH_SRC_IP}|${FILE_PROOF_PATH}|R-AUTH-PROC-FILE-CHAIN|R-FILE-SENSITIVE-CHANGE|detector_rule_matched" | tail -n 40 || true
echo "--- master-roe ---"
new_master | rg "${AUTH_USER}|${AUTH_SRC_IP}|${FILE_PROOF_PATH}|response_run_created|response_run_waiting_approval|response_run_updated" | tail -n 40 || true

echo "[5/5] API incidents snapshot"
INCIDENTS_JSON="$(curl -sS --max-time 10 -H "Authorization: Bearer ${TOKEN}" \
  "${UI_API_URL}/api/incidents?limit=${INCIDENT_LIMIT}&page=1&sort=updated_desc")"
printf '%s\n' "$INCIDENTS_JSON" | jq '{
  count,
  items: [
    .items[]
    | {
        run_id,
        rule_id,
        severity,
        lane,
        status,
        node_id,
        source_type,
        event_type,
        src_ip,
        dst_ip,
        user_name,
        exec_path,
        comm,
        target,
        last_updated_at_unix_ms
      }
  ][0:10]
}'

echo "UI_INCIDENTS_URL=${UI_WEB_URL}/incidents"
echo "NOTE: auth marker user=${AUTH_USER} src_ip=${AUTH_SRC_IP}"
echo "NOTE: file proof path=${FILE_PROOF_PATH}"
echo "PASS: real agent event smoke completed"
