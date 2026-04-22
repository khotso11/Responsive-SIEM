#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PACKAGE_DIR="${PACKAGE_DIR:-/tmp/rsiem-endpoint-package-local}"
AGENT_ID="${AGENT_ID:-$(hostname)}"
UI_WEB_PORT="${UI_WEB_PORT:-3100}"
REAL_SYSTEM="${REAL_SYSTEM:-0}"
INJECT_DEMO_EVENT_DEFAULT="1"
IDENTITY_DEMO_ROUTE_DEFAULT="1"
if [[ "$REAL_SYSTEM" == "1" ]]; then
  INJECT_DEMO_EVENT_DEFAULT="0"
  IDENTITY_DEMO_ROUTE_DEFAULT="0"
fi
INJECT_DEMO_EVENT="${INJECT_DEMO_EVENT:-$INJECT_DEMO_EVENT_DEFAULT}"
DEMO_USER="${DEMO_USER:-demo_local}"
DEMO_SRC_IP="${DEMO_SRC_IP:-10.99.1.31}"
IDENTITY_DEMO_ROUTE="${IDENTITY_DEMO_ROUTE:-$IDENTITY_DEMO_ROUTE_DEFAULT}"
START_INVESTIGATION_ENRICHER="${START_INVESTIGATION_ENRICHER:-1}"
START_HONEYPOT="${START_HONEYPOT:-0}"
HONEYPOT_HTTP_LISTEN="${HONEYPOT_HTTP_LISTEN:-127.0.0.1:18081}"
MODE_LABEL="demo_local_endpoint"
if [[ "$REAL_SYSTEM" == "1" ]]; then
  MODE_LABEL="real_local_endpoint"
fi

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "FAIL: missing command: $1" >&2
    exit 1
  }
}

HEALTH_FAILURES=0

health_ok() {
  echo "PASS: $1"
}

health_fail() {
  echo "FAIL: $1" >&2
  HEALTH_FAILURES=$((HEALTH_FAILURES + 1))
}

wait_for_log() {
  local pattern="$1"
  local file="$2"
  local timeout_s="${3:-15}"
  local elapsed=0
  while (( elapsed < timeout_s )); do
    if rg -n "$pattern" "$file" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  return 1
}

for cmd in awk curl docker go nohup pkill rg sed sudo; do
  need_cmd "$cmd"
done

start_repo_proc() {
  local name="$1"
  local pid_file="$2"
  local log_file="$3"
  shift 3

  nohup env GOCACHE="$ROOT_DIR/.cache/go-build" "$@" >> "$log_file" 2>&1 < /dev/null &
  local pid=$!
  echo "$pid" > "$pid_file"
  sleep 1
  if kill -0 "$pid" 2>/dev/null; then
    echo "$name started pid=$pid log=$log_file"
    return 0
  fi

  echo "FAIL: failed to start ${name} (see ${log_file})" >&2
  tail -n 40 "$log_file" >&2 || true
  exit 1
}

last_log_timestamp() {
  local log_file="$1"
  if [[ ! -f "$log_file" ]]; then
    printf 'missing-log'
    return 0
  fi
  if [[ ! -s "$log_file" ]]; then
    printf 'no-log-output-yet'
    return 0
  fi
  local ts
  ts="$(sed -n 's/.*"time":"\([^"]*\)".*/\1/p' "$log_file" 2>/dev/null | tail -n 1 || true)"
  if [[ -n "$ts" ]]; then
    printf '%s' "$ts"
    return 0
  fi
  ts="$(sed -n 's/^\([0-9T:+.-]\{19,\}\).*/\1/p' "$log_file" 2>/dev/null | tail -n 1 || true)"
  if [[ -n "$ts" ]]; then
    printf '%s' "$ts"
    return 0
  fi
  ts="$(sed -n 's/^\([0-9]\{4\}\/[0-9]\{2\}\/[0-9]\{2\} [0-9:]\{8\}\).*/\1/p' "$log_file" 2>/dev/null | tail -n 1 || true)"
  if [[ -n "$ts" ]]; then
    printf '%s' "$ts"
    return 0
  fi
  printf 'unparsed-log-ts'
}

report_repo_proc_health() {
  local name="$1"
  local pid_file="$2"
  local log_file="$3"
  if [[ ! -f "$pid_file" ]]; then
    health_fail "repo:$name missing pid file ($pid_file)"
    return
  fi
  local pid
  pid="$(tr -d '[:space:]' < "$pid_file")"
  if [[ -z "$pid" ]]; then
    health_fail "repo:$name empty pid file ($pid_file)"
    return
  fi
  if ! kill -0 "$pid" 2>/dev/null; then
    health_fail "repo:$name not running pid=$pid"
    tail -n 20 "$log_file" >&2 || true
    return
  fi
  health_ok "repo:$name pid=$pid log_ts=$(last_log_timestamp "$log_file")"
}

report_systemd_unit_health() {
  local unit="$1"
  if sudo systemctl is-active --quiet "$unit"; then
    health_ok "endpoint:$unit active"
    return
  fi
  health_fail "endpoint:$unit not active"
  sudo systemctl status "$unit" -l --no-pager | sed -n '1,12p' >&2 || true
}

wait_for_http_ready() {
  local name="$1"
  local url="$2"
  local tries="${3:-30}"
  for _ in $(seq 1 "$tries"); do
    if curl -fsS --max-time 2 "$url" >/dev/null 2>&1; then
      echo "PASS: ${name} ready at ${url}"
      return 0
    fi
    sleep 1
  done
  echo "FAIL: ${name} not ready at ${url}" >&2
  return 1
}

echo "MODE=${MODE_LABEL}"

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
pkill -f '/honeypot -config tmp/honeypot_demo.yaml' 2>/dev/null || true
pkill -f 'go run -mod=vendor ./cmd/honeypot -config tmp/honeypot_demo.yaml' 2>/dev/null || true
pkill -f '/investigation-enricher' 2>/dev/null || true
pkill -f 'go run ./cmd/investigation-enricher' 2>/dev/null || true
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

if ! wait_for_http_ready "nats-monitor" "http://127.0.0.1:8222/healthz" 30; then
  docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' >&2 || true
  exit 1
fi

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
mkdir -p logs .pids .cache/go-build
: > logs/master-roe.log
: > logs/worker.log
: > logs/detector.log

start_repo_proc "master-roe" ".pids/master-roe.pid" "logs/master-roe.log" \
  go run -mod=vendor ./cmd/master-roe --config tmp/master_lan_db.yaml

start_repo_proc "master-roe-worker" ".pids/worker.pid" "logs/worker.log" \
  go run -mod=vendor ./cmd/master-roe-worker --config tmp/master_lan_db.yaml --lane BOTH

start_repo_proc "detector-v0" ".pids/detector.pid" "logs/detector.log" \
  go run -mod=vendor ./cmd/detector-v0 --config configs/detector.yaml

if ! wait_for_log '"msg":"db_sink_enabled"' logs/master-roe.log 20; then
  echo "FAIL: db_sink_enabled not observed in logs/master-roe.log" >&2
  tail -n 80 logs/master-roe.log >&2 || true
  exit 1
fi
DB_SINK_LINE="$(rg -n '"msg":"db_sink_enabled"' logs/master-roe.log | tail -n 1 || true)"
echo "$DB_SINK_LINE"
if ! wait_for_log '"msg":"detector_started"' logs/detector.log 20; then
  echo "FAIL: detector_started not observed in logs/detector.log" >&2
  tail -n 80 logs/detector.log >&2 || true
  exit 1
fi
DETECTOR_STARTED_LINE="$(rg -n '"msg":"detector_started"' logs/detector.log | tail -n 1 || true)"
echo "$DETECTOR_STARTED_LINE"
if [[ "$IDENTITY_DEMO_ROUTE" == "1" ]]; then
  echo "IDENTITY_DEMO_ROUTE=PB-AUTH-ABUSE-CONTAIN"
fi

if [[ "$START_HONEYPOT" == "1" ]]; then
  cat > tmp/honeypot_demo.yaml <<EOF_HONEYPOT
log_level: info
node_id: honeypot-local
host: honeypot-local
response_target_agent_id: ${AGENT_ID}
jetstream:
  url: ${NATS_URL}
  stream: RSIEM_EVENTS
  subject: rsiem.events.raw
  spool_path: tmp/honeypot_demo.spool.jsonl
  spool_fsync: false
  retry_interval_ms: 1000
limits:
  read_timeout_ms: 2500
  write_timeout_ms: 2500
  max_payload_bytes: 2048
  max_concurrent: 16
services:
  - id: decoy-admin-http
    enabled: true
    protocol: http
    listen: ${HONEYPOT_HTTP_LISTEN}
    http_title: Restricted Administration Portal
    realm: Operations Console
EOF_HONEYPOT

  : > logs/honeypot.log
  start_repo_proc "honeypot" ".pids/honeypot.pid" "logs/honeypot.log" \
    go run -mod=vendor ./cmd/honeypot -config tmp/honeypot_demo.yaml
  if ! wait_for_log '"msg":"honeypot_service_listening"' logs/honeypot.log 20; then
    echo "FAIL: honeypot_service_listening not observed in logs/honeypot.log" >&2
    tail -n 80 logs/honeypot.log >&2 || true
    exit 1
  fi
  HONEYPOT_STARTED_LINE="$(rg -n '"msg":"honeypot_service_listening"' logs/honeypot.log | tail -n 1 || true)"
  echo "$HONEYPOT_STARTED_LINE"
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
for optional_unit in rsiem-collector-auditd rsiem-collector-inotify rsiem-collector-procnet rsiem-collector-dns; do
  if sudo systemctl list-unit-files "${optional_unit}.service" >/dev/null 2>&1; then
    sudo systemctl restart "${optional_unit}" || true
  fi
done
sleep 3

sudo systemctl status rsiem-agent -l --no-pager | sed -n '1,12p'
sudo systemctl status rsiem-collector-tail -l --no-pager | sed -n '1,12p'
for optional_unit in rsiem-collector-auditd rsiem-collector-inotify rsiem-collector-procnet rsiem-collector-dns; do
  if sudo systemctl is-enabled "${optional_unit}.service" >/dev/null 2>&1 || sudo systemctl is-active "${optional_unit}.service" >/dev/null 2>&1; then
    sudo systemctl status "${optional_unit}" -l --no-pager | sed -n '1,8p' || true
  fi
done

echo "[8/10] Starting UI"
./scripts/ui_down.sh >/dev/null 2>&1 || true
UI_UP_OUT="$(UI_WEB_PORT="$UI_WEB_PORT" ./scripts/ui_up.sh)"
echo "$UI_UP_OUT"

UI_API_URL="$(printf '%s\n' "$UI_UP_OUT" | sed -n 's/^UI_API_URL=//p' | tail -n1)"
if [[ -z "$UI_API_URL" ]]; then
  echo "FAIL: UI_API_URL missing from ui_up output" >&2
  exit 1
fi
for _ in $(seq 1 30); do
  if curl -sS --max-time 3 "${UI_API_URL}/api/health" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
if ! curl -sS --max-time 3 "${UI_API_URL}/api/health" >/dev/null 2>&1; then
  echo "FAIL: ui api not healthy at ${UI_API_URL}/api/health" >&2
  tail -n 40 logs/ui-api.log >&2 || true
  exit 1
fi

if [[ "$START_INVESTIGATION_ENRICHER" == "1" ]]; then
  echo "[8a/10] Starting investigation enricher"
  if [[ -x "./scripts/run_investigation_enricher.sh" && -f "./.env.investigation.local" ]]; then
    mkdir -p logs .pids
    : > logs/investigation-enricher.log
    start_repo_proc "investigation-enricher" ".pids/investigation-enricher.pid" "logs/investigation-enricher.log" \
      ./scripts/run_investigation_enricher.sh
  else
    echo "WARN: investigation-enricher not started (missing ./scripts/run_investigation_enricher.sh or ./.env.investigation.local)" >&2
  fi
fi

echo "[9/10] Health summary"
report_repo_proc_health "master-roe" ".pids/master-roe.pid" "logs/master-roe.log"
report_repo_proc_health "master-roe-worker" ".pids/worker.pid" "logs/worker.log"
report_repo_proc_health "detector-v0" ".pids/detector.pid" "logs/detector.log"
if [[ -f ".pids/investigation-enricher.pid" ]]; then
  report_repo_proc_health "investigation-enricher" ".pids/investigation-enricher.pid" "logs/investigation-enricher.log"
fi

report_systemd_unit_health "rsiem-agent"
report_systemd_unit_health "rsiem-collector-tail"
for optional_unit in rsiem-collector-auditd rsiem-collector-inotify rsiem-collector-procnet rsiem-collector-dns; do
  if sudo systemctl list-unit-files "${optional_unit}.service" >/dev/null 2>&1; then
    report_systemd_unit_health "${optional_unit}"
  fi
done

health_ok "ui-api health=${UI_API_URL}/api/health"

if [[ "$HEALTH_FAILURES" -ne 0 ]]; then
  echo "FAIL: health summary reported ${HEALTH_FAILURES} failure(s)" >&2
  exit 1
fi

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
3) Look for Active Endpoints > 0
4) If REAL_SYSTEM=1, generate real telemetry from this host and confirm new incidents appear
5) If INJECT_DEMO_EVENT=1, look for a FAST waiting incident from the injected auth event
EOF
