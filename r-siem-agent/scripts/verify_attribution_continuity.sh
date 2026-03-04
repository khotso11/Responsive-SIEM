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

for cmd in rg jq docker nats go; do
  need_cmd "$cmd"
done

DB_CONTAINER_NAME="${DB_CONTAINER_NAME:-rsiem-timescale}"
DB_USER="${DB_USER:-rsiem}"
DB_NAME="${DB_NAME:-rsiem}"

query_db() {
  local sql="$1"
  docker exec -i "$DB_CONTAINER_NAME" psql -U "$DB_USER" -d "$DB_NAME" -t -A -F '|' -c "$sql" | sed '/^[[:space:]]*$/d'
}

start_proc() {
  local name="$1"
  local pid_file="$2"
  local log_file="$3"
  shift 3
  env GOCACHE="$ROOT_DIR/.cache/go-build" "$@" >> "$log_file" 2>&1 &
  local pid=$!
  echo "$pid" > "$pid_file"
  sleep 1
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "FAIL: failed to start ${name} (see ${log_file})" >&2
    exit 1
  fi
}

collector_pid=""
cleanup() {
  if [[ -n "$collector_pid" ]] && kill -0 "$collector_pid" 2>/dev/null; then
    kill "$collector_pid" >/dev/null 2>&1 || true
    wait "$collector_pid" 2>/dev/null || true
  fi
  ./scripts/demo_down.sh >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "=== attribution continuity verification ==="
echo "[1/7] ensure db and prepare db-enabled master config"
./scripts/db_up.sh >/tmp/attribution_db_up.out
DB_DSN="$(sed -n 's/^DB_DSN=//p' /tmp/attribution_db_up.out | tail -n1)"
[[ -n "$DB_DSN" ]] || DB_DSN="postgres://rsiem:rsiem@127.0.0.1:5432/rsiem?sslmode=disable"

mkdir -p tmp logs .cache/go-build .pids demo_artifacts
TMP_MASTER_CFG="tmp/attribution_master.yaml"
awk '
BEGIN { skip = 0 }
{
  if (skip) {
    if ($0 ~ /^[A-Za-z0-9_][A-Za-z0-9_-]*:[[:space:]]*($|#)/) {
      skip = 0
    } else {
      next
    }
  }
  if (!skip && $0 ~ /^db:[[:space:]]*$/) {
    skip = 1
    next
  }
  print
}
' configs/master.yaml > "$TMP_MASTER_CFG"
cat >> "$TMP_MASTER_CFG" <<CFG

db:
  enabled: true
  dsn: "$DB_DSN"
  fail_closed: true
  batch_size: 1
  flush_interval_ms: 200
CFG

echo "[2/7] start clean stack"
./scripts/demo_down.sh >/dev/null 2>&1 || true
pkill -f 'cmd/master-roe --config' >/dev/null 2>&1 || true
pkill -f 'cmd/master-roe-worker --config' >/dev/null 2>&1 || true
pkill -f 'cmd/agent --config' >/dev/null 2>&1 || true
pkill -f 'cmd/detector-v0 --config' >/dev/null 2>&1 || true
pkill -f 'cmd/collector-tail --config' >/dev/null 2>&1 || true
pkill -f 'cmd/collector-syslog --config' >/dev/null 2>&1 || true
sleep 1

: > logs/master-roe.log
: > logs/worker.log
: > logs/agent.log
: > logs/detector.log
: > logs/collector.log
: > logs/collector-syslog.log

start_proc "master-roe" ".pids/master-roe.pid" "logs/master-roe.log" go run -mod=vendor ./cmd/master-roe --config "$TMP_MASTER_CFG"
start_proc "master-roe-worker" ".pids/worker.pid" "logs/worker.log" go run -mod=vendor ./cmd/master-roe-worker --config "$TMP_MASTER_CFG" --lane BOTH
start_proc "agent" ".pids/agent.pid" "logs/agent.log" go run -mod=vendor ./cmd/agent --config configs/agent.yaml
start_proc "detector-v0" ".pids/detector.pid" "logs/detector.log" go run -mod=vendor ./cmd/detector-v0 --config configs/detector.yaml
start_proc "collector-tail" ".pids/collector.pid" "logs/collector.log" go run -mod=vendor ./cmd/collector-tail --config configs/collector.yaml

echo "[3/7] start syslog collector and send deterministic event"
env GOCACHE="$ROOT_DIR/.cache/go-build" go run -mod=vendor ./cmd/collector-syslog --config configs/collector-syslog.yaml >> logs/collector-syslog.log 2>&1 &
collector_pid=$!
sleep 1
if ! kill -0 "$collector_pid" 2>/dev/null; then
  echo "FAIL: collector-syslog failed to start" >&2
  tail -n 80 logs/collector-syslog.log >&2 || true
  exit 1
fi

marker="attr_$(date -u +%Y%m%d%H%M%S)"
marker_user="${marker}_user"
event_ts_ms="$(date +%s%3N)"
msg="<14>Jan 01 00:00:00 demohost sshd[123]: Failed password for invalid user ${marker_user} from 10.77.77.7 port 22 ssh2 ts=${event_ts_ms}"
printf '%s\n' "$msg" > /dev/udp/127.0.0.1/5140

echo "[4/7] wait for detector evidence"
detector_line=""
for _ in $(seq 1 30); do
  detector_line="$(rg "\"msg\":\"detector_rule_matched\".*\"user\":\"${marker_user}\"" logs/detector.log | tail -n 1 || true)"
  if [[ -n "$detector_line" ]]; then
    break
  fi
  sleep 1
done
[[ -n "$detector_line" ]] || {
  echo "FAIL: detector did not emit detector_rule_matched for marker user ${marker_user}" >&2
  tail -n 120 logs/detector.log >&2 || true
  exit 1
}

echo "[5/7] wait for DB row and validate attribution fields"
row=""
for _ in $(seq 1 40); do
  row="$(query_db "SELECT node_id, source_type, event_type, COALESCE(host(src_ip), ''), COALESCE(user_name, '') FROM normalized_events WHERE user_name='${marker_user}' ORDER BY id DESC LIMIT 1;" | tail -n1)"
  if [[ -n "$row" ]]; then
    break
  fi
  sleep 1
done
[[ -n "$row" ]] || {
  echo "FAIL: no normalized_events row found for user_name=${marker_user}" >&2
  exit 1
}

IFS='|' read -r node_id source_type event_type src_ip user_name <<< "$row"
node_id="$(echo "$node_id" | xargs)"
source_type="$(echo "$source_type" | xargs)"
event_type="$(echo "$event_type" | xargs)"
src_ip="$(echo "$src_ip" | xargs)"
user_name="$(echo "$user_name" | xargs)"

[[ -n "$node_id" ]] || {
  echo "FAIL: node_id empty in normalized_events for marker user" >&2
  exit 1
}
[[ "$node_id" != "unknown" ]] || {
  echo "FAIL: node_id is unknown in normalized_events for marker user" >&2
  exit 1
}
[[ -n "$source_type" ]] || {
  echo "FAIL: source_type empty in normalized_events for marker user" >&2
  exit 1
}
case "$source_type" in
  syslog|tail|netflow_v5|snmp_trap) ;;
  *)
    echo "FAIL: unexpected source_type=${source_type}" >&2
    exit 1
    ;;
esac
[[ -n "$event_type" ]] || {
  echo "FAIL: event_type empty in normalized_events for marker user" >&2
  exit 1
}

echo "[6/7] write proof artifact"
ts="$(date -u +%Y%m%d_%H%M%S)"
art_dir="demo_artifacts/${ts}"
mkdir -p "$art_dir"
proof_json="${art_dir}/attribution_continuity_proof.json"
cat > "$proof_json" <<JSON
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "marker": "${marker}",
  "db": {
    "container": "${DB_CONTAINER_NAME}",
    "table": "normalized_events"
  },
  "row": {
    "node_id": "${node_id}",
    "source_type": "${source_type}",
    "event_type": "${event_type}",
    "src_ip": "${src_ip}",
    "user": "${user_name}"
  },
  "pass": true
}
JSON

echo "[7/7] done"
echo "PASS: attribution continuity proof completed"
echo "ATTRIBUTION_CONTINUITY_PROOF_JSON=${proof_json}"
