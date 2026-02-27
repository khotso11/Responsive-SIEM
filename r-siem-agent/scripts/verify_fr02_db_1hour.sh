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

need_cmd docker
need_cmd go
need_cmd rg
need_cmd python3

DB_CONTAINER_NAME="${DB_CONTAINER_NAME:-rsiem-timescale}"
DB_USER="${DB_USER:-rsiem}"
DB_NAME="${DB_NAME:-rsiem}"

query_db() {
  local sql="$1"
  docker exec -i "$DB_CONTAINER_NAME" psql -U "$DB_USER" -d "$DB_NAME" -t -A -c "$sql" | tr -d '[:space:]'
}

wait_db_ready() {
  local ready=0
  for _ in $(seq 1 120); do
    if docker exec "$DB_CONTAINER_NAME" pg_isready -U "$DB_USER" -d "$DB_NAME" >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done
  [[ "$ready" -eq 1 ]]
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

start_stack_mod_mode() {
  mkdir -p logs .pids .cache/go-build
  : > logs/master-roe.log
  : > logs/worker.log
  : > logs/agent.log
  : > logs/detector.log
  : > logs/collector.log

  start_proc "master-roe" ".pids/master-roe.pid" "logs/master-roe.log" go run -mod=mod ./cmd/master-roe --config "$1"
  start_proc "master-roe-worker" ".pids/worker.pid" "logs/worker.log" go run -mod=mod ./cmd/master-roe-worker --config "$1" --lane BOTH
  start_proc "agent" ".pids/agent.pid" "logs/agent.log" go run -mod=mod ./cmd/agent --config configs/agent.yaml
  start_proc "detector-v0" ".pids/detector.pid" "logs/detector.log" go run -mod=mod ./cmd/detector-v0 --config configs/detector.yaml
  start_proc "collector-tail" ".pids/collector.pid" "logs/collector.log" go run -mod=mod ./cmd/collector-tail --config configs/collector.yaml
}

echo "=== FR-02 DB 1-hour completeness verification ==="

./scripts/demo_down.sh >/dev/null 2>&1 || true
./scripts/db_up.sh >/tmp/fr02_db_up.out
DB_DSN="$(sed -n 's/^DB_DSN=//p' /tmp/fr02_db_up.out | tail -n1)"
[[ -n "$DB_DSN" ]] || DB_DSN="postgres://rsiem:rsiem@127.0.0.1:5432/rsiem?sslmode=disable"

TMP_MASTER_CFG="tmp/fr02_db_1hour_master.yaml"
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

if ./scripts/demo_up.sh >/tmp/fr02_db_demo_up.out 2>&1; then
  pkill -f 'cmd/master-roe-worker --config' >/dev/null 2>&1 || true
  pkill -f 'cmd/master-roe --config' >/dev/null 2>&1 || true
  sleep 1
  : > logs/master-roe.log
  : > logs/worker.log
  start_proc "master-roe" ".pids/master-roe.pid" "logs/master-roe.log" go run -mod=mod ./cmd/master-roe --config "$TMP_MASTER_CFG"
  start_proc "master-roe-worker" ".pids/worker.pid" "logs/worker.log" go run -mod=mod ./cmd/master-roe-worker --config "$TMP_MASTER_CFG" --lane BOTH
else
  start_stack_mod_mode "$TMP_MASTER_CFG"
fi

before_total="$(query_db 'SELECT count(*) FROM normalized_events;')"
before_total="${before_total:-0}"
before_max_id="$(query_db 'SELECT COALESCE(max(id),0) FROM normalized_events;')"
before_max_id="${before_max_id:-0}"

duration_seconds="${RSIEM_FR02_RUN_SECONDS:-3600}"
eps="${RSIEM_FR02_EPS:-5}"
if (( duration_seconds <= 0 )); then
  echo "FAIL: RSIEM_FR02_RUN_SECONDS must be > 0" >&2
  exit 1
fi
if (( eps <= 0 )); then
  echo "FAIL: RSIEM_FR02_EPS must be > 0" >&2
  exit 1
fi

restart_at=$((duration_seconds / 5))
if (( restart_at < 1 )); then
  restart_at=1
fi
restart_before_id=0
restart_time_rfc3339=""

base_ms="$(date +%s%3N)"
for ((sec=0; sec<duration_seconds; sec++)); do
  for ((i=1; i<=eps; i++)); do
    idx=$((sec * eps + i))
    node_id=$(printf 'node-%02d' $(( (idx - 1) % 15 + 1 )))
    src_ip=$(printf '10.90.%d.%d' $(( (idx / 250) % 250 )) $(( idx % 250 + 1 )))
    ts_ms=$((base_ms + idx))
    printf 'ALERT invalid user=fr02db_%05d src=%s node=%s ts=%s\n' "$idx" "$src_ip" "$node_id" "$ts_ms" >> tmp/demo.log
  done

  if (( sec == restart_at )); then
    restart_time_rfc3339="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    restart_before_id="$(query_db 'SELECT COALESCE(max(id),0) FROM normalized_events;')"
    docker restart "$DB_CONTAINER_NAME" >/dev/null
    if ! wait_db_ready; then
      echo "FAIL: database did not recover after restart" >&2
      exit 1
    fi
  fi
  sleep 1
done

sleep 5

after_total="$(query_db 'SELECT count(*) FROM normalized_events;')"
after_total="${after_total:-0}"
run_total="$(query_db "SELECT count(*) FROM normalized_events WHERE id > ${before_max_id};")"
run_total="${run_total:-0}"
required_ok="$(query_db "SELECT count(*) FROM normalized_events WHERE id > ${before_max_id} AND event_ts_unix_ms IS NOT NULL AND recv_ts_unix_ms IS NOT NULL AND node_id IS NOT NULL AND node_id <> '' AND source_type IS NOT NULL AND source_type <> '' AND event_type IS NOT NULL AND event_type <> '' AND event_idem_key IS NOT NULL AND event_idem_key <> '';")"
required_ok="${required_ok:-0}"

post_restart_rows=0
if [[ -n "$restart_time_rfc3339" ]] && (( restart_before_id > 0 )); then
  post_restart_rows="$(query_db "SELECT count(*) FROM normalized_events WHERE id > ${restart_before_id};")"
  post_restart_rows="${post_restart_rows:-0}"
fi

completeness_pct="$(python3 - "$run_total" "$required_ok" <<'PY'
import sys

total = int(sys.argv[1])
ok = int(sys.argv[2])
if total <= 0:
    print("0.00")
else:
    print(f"{(ok * 100.0) / total:.2f}")
PY
)"

python3 - "$run_total" "$required_ok" "$completeness_pct" "$post_restart_rows" <<'PY'
import sys

total = int(sys.argv[1])
ok = int(sys.argv[2])
pct = float(sys.argv[3])
post_restart_rows = int(sys.argv[4])

if total <= 0:
    raise SystemExit("FAIL: no rows inserted during verifier run")
if ok <= 0:
    raise SystemExit("FAIL: no rows with required normalized fields")
if pct <= 95.0:
    raise SystemExit(f"FAIL: completeness_pct={pct:.2f} expected > 95.0")
if post_restart_rows <= 0:
    raise SystemExit("FAIL: no inserts observed after DB restart")
PY

artifact_ts="$(date +%Y%m%d_%H%M%S)"
artifact_dir="demo_artifacts/${artifact_ts}"
mkdir -p "$artifact_dir"
proof_json="${artifact_dir}/fr02_db_1hour_proof.json"

cat > "$proof_json" <<JSON
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "duration_seconds": ${duration_seconds},
  "db": {
    "dsn": "${DB_DSN}",
    "container": "${DB_CONTAINER_NAME}"
  },
  "restart_test": {
    "performed": true,
    "restart_time_rfc3339": "${restart_time_rfc3339}",
    "post_restart_inserts_ok": $( [[ "$post_restart_rows" -gt 0 ]] && echo true || echo false )
  },
  "counts": {
    "total_rows": ${run_total},
    "rows_required_fields_ok": ${required_ok},
    "completeness_pct": ${completeness_pct}
  },
  "required_fields": [
    "event_ts_unix_ms",
    "recv_ts_unix_ms",
    "node_id",
    "source_type",
    "event_type",
    "event_idem_key"
  ],
  "pass": true
}
JSON

echo "PASS: FR-02 DB 1hour completeness completed"
echo "FR02_DB_1HOUR_PROOF_JSON=${proof_json}"
