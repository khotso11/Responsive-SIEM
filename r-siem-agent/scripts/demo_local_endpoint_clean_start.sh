#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PACKAGE_DIR="${PACKAGE_DIR:-/tmp/rsiem-endpoint-package-local}"
AGENT_ID="${AGENT_ID:-$(hostname)}"
UI_WEB_PORT="${UI_WEB_PORT:-3100}"
INJECT_DEMO_EVENT="${INJECT_DEMO_EVENT:-1}"
DEMO_USER="${DEMO_USER:-demo_local}"
DEMO_SRC_IP="${DEMO_SRC_IP:-10.99.1.31}"
IDENTITY_DEMO_ROUTE="${IDENTITY_DEMO_ROUTE:-1}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "FAIL: missing command: $1" >&2
    exit 1
  }
}

for cmd in awk docker go pkill rg sed sudo; do
  need_cmd "$cmd"
done

echo "[0/10] Preparing local endpoint package"
mkdir -p "$PACKAGE_DIR/bin" "$PACKAGE_DIR/pki"

echo "Building agent binary into $PACKAGE_DIR/bin/agent"
env GOCACHE="$ROOT_DIR/.cache/go-build" go build -mod=vendor -o "$PACKAGE_DIR/bin/agent" ./cmd/agent

echo "Building collector-tail binary into $PACKAGE_DIR/bin/collector-tail"
env GOCACHE="$ROOT_DIR/.cache/go-build" go build -mod=vendor -o "$PACKAGE_DIR/bin/collector-tail" ./cmd/collector-tail

if [[ -f "cmd/collector-auditd/main.go" ]]; then
  echo "Building collector-auditd binary into $PACKAGE_DIR/bin/collector-auditd"
  env GOCACHE="$ROOT_DIR/.cache/go-build" go build -mod=vendor -o "$PACKAGE_DIR/bin/collector-auditd" ./cmd/collector-auditd
fi

if [[ -f "cmd/collector-inotify/main.go" ]]; then
  echo "Building collector-inotify binary into $PACKAGE_DIR/bin/collector-inotify"
  env GOCACHE="$ROOT_DIR/.cache/go-build" go build -mod=vendor -o "$PACKAGE_DIR/bin/collector-inotify" ./cmd/collector-inotify
fi

if [[ -f "cmd/collector-procnet/main.go" ]]; then
  echo "Building collector-procnet binary into $PACKAGE_DIR/bin/collector-procnet"
  env GOCACHE="$ROOT_DIR/.cache/go-build" go build -mod=vendor -o "$PACKAGE_DIR/bin/collector-procnet" ./cmd/collector-procnet
fi

if [[ -f "cmd/collector-dns/main.go" ]]; then
  echo "Building collector-dns binary into $PACKAGE_DIR/bin/collector-dns"
  env GOCACHE="$ROOT_DIR/.cache/go-build" go build -mod=vendor -o "$PACKAGE_DIR/bin/collector-dns" ./cmd/collector-dns
fi

mkdir -p "$PACKAGE_DIR/configs"
for cfg in collector-auditd.yaml collector-inotify.yaml collector-procnet.yaml collector-dns.yaml; do
  if [[ -f "configs/$cfg" ]]; then
    cp "configs/$cfg" "$PACKAGE_DIR/configs/$cfg"
  fi
done

if [[ ! -f "pki/agents/${AGENT_ID}/current/agent.pem" || ! -f "pki/agents/${AGENT_ID}/current/agent-key.pem" ]]; then
  echo "Issuing endpoint cert for AGENT_ID=$AGENT_ID"
  ./scripts/pki_issue_agent_cert.sh "$AGENT_ID" >/tmp/demo_local_endpoint_pki_issue.out
else
  ./scripts/pki_issue_agent_cert.sh "$AGENT_ID" >/tmp/demo_local_endpoint_pki_issue.out
fi

AGENT_FP_SHA256="$(sed -n 's/^AGENT_FP_SHA256=//p' /tmp/demo_local_endpoint_pki_issue.out | tail -n1)"
if [[ -n "$AGENT_FP_SHA256" ]]; then
  ./scripts/pki_allowlist_add_fingerprint.sh "$AGENT_FP_SHA256" >/tmp/demo_local_endpoint_allowlist.out
fi

cp pki/ca/ca.pem "$PACKAGE_DIR/pki/ca.pem"
cp "pki/agents/${AGENT_ID}/current/agent.pem" "$PACKAGE_DIR/pki/agent.pem"
cp "pki/agents/${AGENT_ID}/current/agent-key.pem" "$PACKAGE_DIR/pki/agent-key.pem"

echo "[1/10] Stopping old repo-side processes"
pkill -f '/master-roe --config' 2>/dev/null || true
pkill -f '/master-roe-worker --config' 2>/dev/null || true
pkill -f 'go run -mod=vendor ./cmd/master-roe --config' 2>/dev/null || true
pkill -f 'go run -mod=vendor ./cmd/master-roe-worker --config' 2>/dev/null || true
pkill -f '/detector-v0 --config' 2>/dev/null || true
pkill -f 'go run -mod=vendor ./cmd/detector-v0 --config' 2>/dev/null || true
pkill -f '/collector-tail --config configs/collector.yaml' 2>/dev/null || true
pkill -f '/agent --config configs/agent.yaml' 2>/dev/null || true
sleep 2

echo "[2/10] Starting infrastructure"
./scripts/db_up.sh >/tmp/demo_local_endpoint_db_up.out
docker start rsiem-nats-lan >/dev/null 2>&1 || docker start nats >/dev/null 2>&1 || true

DB_DSN="$(sed -n 's/^DB_DSN=//p' /tmp/demo_local_endpoint_db_up.out | tail -n1)"
if [[ -z "$DB_DSN" ]]; then
  DB_DSN="postgres://rsiem:rsiem@127.0.0.1:5432/rsiem?sslmode=disable"
fi

MASTER_IP="$(hostname -I | awk '{print $1}')"
NATS_URL="nats://${MASTER_IP}:4222"

echo "MASTER_IP=$MASTER_IP"
echo "NATS_URL=$NATS_URL"
echo "DB_DSN=$DB_DSN"

echo "[3/10] Building DB-backed master config"
awk '
BEGIN { skip=0 }
{
  if (skip) {
    if ($0 ~ /^[A-Za-z0-9_][A-Za-z0-9_-]*:[[:space:]]*($|#)/) { skip=0 } else { next }
  }
  if (!skip && $0 ~ /^db:[[:space:]]*$/) { skip=1; next }
  print
}
' configs/master.yaml > tmp/master_lan_db.yaml

printf '\ndb:\n  enabled: true\n  dsn: "%s"\n  fail_closed: true\n  batch_size: 1\n  flush_interval_ms: 200\n' "$DB_DSN" >> tmp/master_lan_db.yaml

if [[ "$IDENTITY_DEMO_ROUTE" == "1" ]]; then
  echo "[3a/10] Switching local auth-abuse demo routing to PB-AUTH-ABUSE-CONTAIN"
  perl -0pe '
    s/( - id: "PB-QUARANTINE-ROLLBACK-DEMO"\n.*?selectors:\n\s+rule_ids:\s*)\["R-COLLECT-INVALID-USER"\]/${1}[]/s;
    s/( - id: "PB-AGENT-PING-LOCALHOST"\n.*?selectors:\n\s+rule_ids:\s*)\["R-COLLECT-INVALID-USER"\]/${1}[]/s;
    s/(
      \Q  - id: "PB-AUTH-ABUSE-CONTAIN"\E\n
      \Q    version: 1\E\n
      \Q    enabled: true\E\n
      \Q    selectors:\E\n
      \Q      rule_ids:\E\n
      \Q        - "R-AUTH-FAILED-PW-BURST-USER"\E\n
      \Q        - "R-AUTH-FAILED-PW-BURST-SRCIP"\E\n
      \Q        - "R-AUTH-USER-SRCIP-BURST"\E\n
    )/$1        - "R-COLLECT-INVALID-USER"\n/xs
      unless /PB-AUTH-ABUSE-CONTAIN[\s\S]*^\s*-\s+"R-COLLECT-INVALID-USER"$/m;
  ' tmp/master_lan_db.yaml > tmp/master_lan_db.identity.tmp
  mv tmp/master_lan_db.identity.tmp tmp/master_lan_db.yaml
  if [[ ! -s tmp/master_lan_db.yaml ]]; then
    echo "FAIL: generated demo master config is empty" >&2
    exit 1
  fi
  if ! rg -q 'PB-AUTH-ABUSE-CONTAIN' tmp/master_lan_db.yaml; then
    echo "FAIL: PB-AUTH-ABUSE-CONTAIN missing from generated demo master config" >&2
    exit 1
  fi
fi

echo "[4/10] Starting one master, one worker, one detector"
env GOCACHE="$ROOT_DIR/.cache/go-build" go run -mod=vendor ./cmd/master-roe --config tmp/master_lan_db.yaml >> logs/master-roe.log 2>&1 &
echo $! > .pids/master-roe.pid

env GOCACHE="$ROOT_DIR/.cache/go-build" go run -mod=vendor ./cmd/master-roe-worker --config tmp/master_lan_db.yaml --lane BOTH >> logs/worker.log 2>&1 &
echo $! > .pids/worker.pid

env GOCACHE="$ROOT_DIR/.cache/go-build" go run -mod=vendor ./cmd/detector-v0 --config configs/detector.yaml >> logs/detector.log 2>&1 &
echo $! > .pids/detector.pid

sleep 3
DB_SINK_LINE="$(rg -n '"msg":"db_sink_enabled"' logs/master-roe.log | tail -n 1 || true)"
if [[ -z "$DB_SINK_LINE" ]]; then
  echo "FAIL: db_sink_enabled not observed in logs/master-roe.log" >&2
  exit 1
fi
echo "$DB_SINK_LINE"
if [[ "$IDENTITY_DEMO_ROUTE" == "1" ]]; then
  echo "IDENTITY_DEMO_ROUTE=PB-AUTH-ABUSE-CONTAIN"
fi

echo "[5/10] Re-installing local endpoint against current LAN IP"
sudo ./scripts/deploy/linux/install_endpoint.sh \
  --master-ip "$MASTER_IP" \
  --agent-id "$AGENT_ID" \
  --nats-url "$NATS_URL" \
  --config-dir "$PACKAGE_DIR" >/tmp/demo_local_endpoint_install.out
tail -n 8 /tmp/demo_local_endpoint_install.out

echo "[6/10] Fixing known endpoint permissions"
sudo chown rsiem:rsiem /etc/rsiem/pki/ca.pem /etc/rsiem/pki/agent.pem /etc/rsiem/pki/agent-key.pem
sudo chmod 0644 /etc/rsiem/pki/ca.pem /etc/rsiem/pki/agent.pem
sudo chmod 0600 /etc/rsiem/pki/agent-key.pem
sudo usermod -a -G adm rsiem

echo "[7/10] Restarting installed local endpoint services"
sudo systemctl restart rsiem-agent
sudo systemctl restart rsiem-collector-tail
sleep 3

sudo systemctl status rsiem-agent -l --no-pager | sed -n '1,12p'
sudo systemctl status rsiem-collector-tail -l --no-pager | sed -n '1,12p'

echo "[8/10] Starting UI"
./scripts/ui_down.sh >/dev/null 2>&1 || true
UI_UP_OUT="$(UI_WEB_PORT="$UI_WEB_PORT" ./scripts/ui_up.sh)"
echo "$UI_UP_OUT"

echo "[9/10] Verifying service logs"
sudo tail -n 10 /var/log/rsiem/agent.log || true
sudo tail -n 15 /var/log/rsiem/collector-tail.log || true

if [[ "$INJECT_DEMO_EVENT" == "1" ]]; then
  echo "[10/10] Injecting one known-good local auth event"
  sudo bash -lc "printf \"%s %s sshd[12345]: Failed password for invalid user ${DEMO_USER} from ${DEMO_SRC_IP} port 51150 ssh2\\n\" \"\$(date \"+%b %e %H:%M:%S\")\" \"\$(hostname)\" >> /var/log/auth.log"
  sleep 3

  echo "--- collector evidence ---"
  sudo tail -n 20 /var/log/rsiem/collector-tail.log || true

  echo "--- detector/master evidence ---"
  rg "${DEMO_USER}|${DEMO_SRC_IP}|response_run_created|response_run_waiting_approval|db_insert_failed" logs/detector.log logs/master-roe.log | tail -n 30 || true

  echo "--- db evidence ---"
  docker exec -i rsiem-timescale psql -U rsiem -d rsiem -t -A -F '|' -c \
  "SELECT node_id, source_type, event_type, src_ip, user_name, recv_ts_unix_ms
   FROM normalized_events
   ORDER BY recv_ts_unix_ms DESC
   LIMIT 20;"
else
  echo "[10/10] Skipping demo event injection because INJECT_DEMO_EVENT=$INJECT_DEMO_EVENT"
fi

cat <<EOF
PASS: local endpoint clean start completed
NEXT:
1) Open UI: http://127.0.0.1:${UI_WEB_PORT}
2) Refresh the dashboard
3) Look for Active Endpoints > 0 and a FAST waiting incident if the demo event was injected
EOF
