#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

MASTER_IP="${MASTER_IP:-$(hostname -I | awk '{print $1}')}"
NATS_URL="${NATS_URL:-nats://${MASTER_IP}:4222}"
NODE_ID="${NODE_ID:-$(hostname)}"
FAST_USER="${FAST_USER:-demo_fast_local}"
FAST_SRC_IP="${FAST_SRC_IP:-10.99.1.41}"
STD_USER="${STD_USER:-demo_std_local}"
STD_SRC_IP="${STD_SRC_IP:-10.88.1.41}"
DECEPTION_USER="${DECEPTION_USER:-honeypot_local}"
DECEPTION_SRC_IP="${DECEPTION_SRC_IP:-10.66.12.21}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "FAIL: missing command: $1" >&2
    exit 1
  }
}

for cmd in jq nats rg sudo; do
  need_cmd "$cmd"
done

echo "MASTER_IP=$MASTER_IP"
echo "NATS_URL=$NATS_URL"
echo "NODE_ID=$NODE_ID"

BASE_MASTER="$(wc -l < logs/master-roe.log 2>/dev/null || echo 0)"
BASE_DETECTOR="$(wc -l < logs/detector.log 2>/dev/null || echo 0)"
BASE_COLLECTOR_LINES="$(sudo wc -l < /var/log/rsiem/collector-tail.log 2>/dev/null || echo 0)"

new_master() {
  sed -n "$((BASE_MASTER+1)),\$p" logs/master-roe.log
}

new_detector() {
  sed -n "$((BASE_DETECTOR+1)),\$p" logs/detector.log
}

new_collector() {
  sudo sed -n "$((BASE_COLLECTOR_LINES+1)),\$p" /var/log/rsiem/collector-tail.log
}

echo "[1/5] Injecting FAST event via real local collector path"
sudo bash -lc "printf \"%s %s sshd[12345]: Failed password for invalid user ${FAST_USER} from ${FAST_SRC_IP} port 51150 ssh2\\n\" \"\$(date \"+%b %e %H:%M:%S\")\" \"\$(hostname)\" >> /var/log/auth.log"

sleep 2

echo "[2/5] Injecting DECEPTION event via real local collector path"
sudo bash -lc "printf \"%s %s ALERT invalid user user=${DECEPTION_USER} from ${DECEPTION_SRC_IP} attack=deception_tripwire ts=%s\\n\" \"\$(date \"+%b %e %H:%M:%S\")\" \"\$(hostname)\" \"\$(date +%s%3N)\" >> /var/log/auth.log"

sleep 2

echo "[3/5] Injecting STANDARD event via canonical raw-event publish path"
NOW_MS="$(date +%s%3N)"
STD_EVENT_ID="evt_std_local_${NOW_MS}"
STD_PAYLOAD="$(jq -cn \
  --arg evt "$STD_EVENT_ID" \
  --arg now "$NOW_MS" \
  --arg node "$NODE_ID" \
  --arg src_ip "$STD_SRC_IP" \
  --arg user "$STD_USER" \
  '{
    event_idem_key:$evt,
    observed_at_unix_ms:($now|tonumber),
    event_ts_unix_ms:($now|tonumber),
    recv_ts_unix_ms:($now|tonumber),
    message:("process_count=3 host=" + $node + " src=" + $src_ip + " ts=" + $now),
    line:("process_count=3 host=" + $node + " src=" + $src_ip + " ts=" + $now),
    host:$node,
    node_id:$node,
    source_type:"tail",
    event_type:"process",
    src_ip:$src_ip,
    user:$user,
    group_key:$node,
    source:"local-endpoint-standard-demo"
  }')"
nats --server "$NATS_URL" pub rsiem.events.raw "$STD_PAYLOAD" >/dev/null

sleep 4

echo "[4/5] Evidence"
echo "--- new collector evidence ---"
new_collector | tail -n 20 || true

echo "--- new detector evidence ---"
new_detector | rg "${FAST_USER}|${FAST_SRC_IP}|${STD_USER}|${STD_SRC_IP}|${DECEPTION_USER}|${DECEPTION_SRC_IP}|detector_rule_matched" | tail -n 30 || true

echo "--- new master evidence ---"
new_master | rg "${FAST_USER}|${FAST_SRC_IP}|${STD_USER}|${STD_SRC_IP}|${DECEPTION_USER}|${DECEPTION_SRC_IP}|response_run_created|response_run_waiting_approval|response_run_updated" | tail -n 40 || true

echo "--- db evidence ---"
docker exec -i rsiem-timescale psql -U rsiem -d rsiem -t -A -F '|' -c \
"SELECT node_id, source_type, event_type, src_ip, user_name, recv_ts_unix_ms
 FROM normalized_events
 WHERE user_name IN ('${FAST_USER}','${STD_USER}','${DECEPTION_USER}')
 ORDER BY recv_ts_unix_ms DESC;"

echo "[5/5] Summary"
FAST_RUN_ID="$(new_master | rg '"msg":"response_run_created".*"rule_id":"R-COLLECT-INVALID-USER"' | tail -n 1 | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"
STD_RUN_ID="$(new_master | rg '"msg":"response_run_created".*"rule_id":"R-COUNT-PROCESS-HOST"' | tail -n 1 | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"

echo "FAST_EXPECTED=rule:R-COLLECT-INVALID-USER playbook:PB-AUTH-ABUSE-CONTAIN lane:FAST approval:required"
echo "FAST_RUN_ID=${FAST_RUN_ID:-}"
echo "STANDARD_EXPECTED=rule:R-COUNT-PROCESS-HOST lane:STANDARD approval:auto"
echo "STANDARD_RUN_ID=${STD_RUN_ID:-}"
echo "DECEPTION_EXPECTED=rule:R-FR03-DECEPTION-TRIPWIRE lane:FAST approval:none"
echo "NOTE: STANDARD uses the canonical raw-event publish path because /var/log/auth.log cannot organically produce process_count events for the installed local collector."
echo "PASS: local endpoint triptych injection completed"
