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

for cmd in rg jq docker nats go python3; do
  need_cmd "$cmd"
done

DB_CONTAINER_NAME="${DB_CONTAINER_NAME:-rsiem-timescale}"
DB_USER="${DB_USER:-rsiem}"
DB_NAME="${DB_NAME:-rsiem}"

query_db() {
  local sql="$1"
  docker exec -i "$DB_CONTAINER_NAME" psql -U "$DB_USER" -d "$DB_NAME" -t -A -c "$sql" | sed '/^[[:space:]]*$/d'
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

start_stack_db_mode() {
  local master_cfg="$1"
  mkdir -p logs .pids .cache/go-build
  : > logs/master-roe.log
  : > logs/worker.log
  : > logs/agent.log
  : > logs/detector.log
  : > logs/collector.log

  start_proc "master-roe" ".pids/master-roe.pid" "logs/master-roe.log" go run -mod=vendor ./cmd/master-roe --config "$master_cfg"
  start_proc "master-roe-worker" ".pids/worker.pid" "logs/worker.log" go run -mod=vendor ./cmd/master-roe-worker --config "$master_cfg" --lane BOTH
  start_proc "agent" ".pids/agent.pid" "logs/agent.log" go run -mod=vendor ./cmd/agent --config configs/agent.yaml
  start_proc "detector-v0" ".pids/detector.pid" "logs/detector.log" go run -mod=vendor ./cmd/detector-v0 --config configs/detector.yaml
  start_proc "collector-tail" ".pids/collector.pid" "logs/collector.log" go run -mod=vendor ./cmd/collector-tail --config configs/collector.yaml
}

run_component_proof() {
  local script_path="$1"
  local key="$2"
  local out_file="$3"
  if [[ "$script_path" == *"verify_fr01_snmptrap.sh" ]]; then
    MIBS='' "$script_path" | tee "$out_file" >&2
  else
    "$script_path" | tee "$out_file" >&2
  fi
  local proof_path
  proof_path="$(rg -o "${key}=.*" "$out_file" | tail -n 1 | cut -d= -f2-)"
  [[ -n "$proof_path" ]] || {
    echo "FAIL: could not extract ${key} from ${script_path}" >&2
    exit 1
  }
  [[ -f "$proof_path" ]] || {
    echo "FAIL: proof file not found for ${key}: ${proof_path}" >&2
    exit 1
  }
  echo "$proof_path"
}

echo "=== FR-01 acceptance verification ==="
echo "[1/8] run component streaming proofs"
syslog_proof="$(run_component_proof ./scripts/verify_fr01_syslog.sh FR01_SYSLOG_PROOF_JSON /tmp/fr01_acceptance_syslog.out)"
netflow_proof="$(run_component_proof ./scripts/verify_fr01_netflowv5.sh FR01_NETFLOWV5_PROOF_JSON /tmp/fr01_acceptance_netflow.out)"
snmp_proof="$(run_component_proof ./scripts/verify_fr01_snmptrap.sh FR01_SNMPTRAP_PROOF_JSON /tmp/fr01_acceptance_snmp.out)"

for proof in "$syslog_proof" "$netflow_proof" "$snmp_proof"; do
  [[ "$(jq -r '.pass' "$proof")" == "true" ]] || {
    echo "FAIL: component proof not passing: ${proof}" >&2
    exit 1
  }
done

echo "[2/8] ensure database + stack"
./scripts/db_up.sh >/tmp/fr01_acceptance_db_up.out
DB_DSN="$(sed -n 's/^DB_DSN=//p' /tmp/fr01_acceptance_db_up.out | tail -n1)"
[[ -n "$DB_DSN" ]] || DB_DSN="postgres://rsiem:rsiem@127.0.0.1:5432/rsiem?sslmode=disable"

./scripts/demo_down.sh >/dev/null 2>&1 || true
# demo_down uses pidfiles; force-clean any orphaned Go-run demo processes to avoid split consumption.
pkill -f 'cmd/master-roe --config' >/dev/null 2>&1 || true
pkill -f 'cmd/master-roe-worker --config' >/dev/null 2>&1 || true
pkill -f 'cmd/agent --config' >/dev/null 2>&1 || true
pkill -f 'cmd/detector-v0 --config' >/dev/null 2>&1 || true
pkill -f 'cmd/collector-tail --config' >/dev/null 2>&1 || true
pkill -f 'master-roe --config' >/dev/null 2>&1 || true
pkill -f 'master-roe-worker --config' >/dev/null 2>&1 || true
pkill -f 'agent --config' >/dev/null 2>&1 || true
pkill -f 'detector-v0 --config' >/dev/null 2>&1 || true
pkill -f 'collector-tail --config' >/dev/null 2>&1 || true
sleep 1
mkdir -p tmp .cache/go-build
TMP_MASTER_CFG="tmp/fr01_acceptance_master.yaml"
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

start_stack_db_mode "$TMP_MASTER_CFG"

echo "[3/8] generate endpoint taxonomy lines in collector-tail input"
run_tag="fr01acc_$(date -u +%Y%m%d%H%M%S)"
base_ms="$(date +%s%3N)"
for i in $(seq 1 15); do
  node_id="$(printf 'node-%02d' "$i")"
  src_ip="10.77.0.$((40 + i))"
  auth_ts="$((base_ms + i))"
  proc_ts="$((base_ms + 100 + i))"
  file_ts="$((base_ms + 200 + i))"
  user_base="${run_tag}_${node_id}"
  printf 'FAILED login user=%s src=%s ts=%s node=%s\n' "${user_base}_auth" "$src_ip" "$auth_ts" "$node_id" >> tmp/demo.log
  printf 'PROC exec="/usr/bin/curl" user=%s src=%s ts=%s node=%s\n' "${user_base}_proc" "$src_ip" "$proc_ts" "$node_id" >> tmp/demo.log
  printf 'FILE path="/tmp/secret_%s.txt" action=modified user=%s src=%s ts=%s node=%s\n' "$node_id" "${user_base}_file" "$src_ip" "$file_ts" "$node_id" >> tmp/demo.log
done

echo "[4/8] publish deterministic trigger records for DB acceptance window"
before_max_id="$(query_db 'SELECT COALESCE(max(id),0) FROM normalized_events;' | tail -n1)"
before_max_id="${before_max_id:-0}"

publish_trigger() {
  local seq="$1"
  local source_type="$2"
  local event_type="$3"
  local node_id="$4"
  local src_ip="$5"
  local user_name="$6"
  local event_ts_ms="$7"
  local recv_ts_ms="$8"
  local lane="$9"
  local trigger_id="trig.fr01acc.${run_tag}.${seq}"
  local alert_key="A-FR01ACC-${run_tag}-${seq}"
  local payload
  payload="$(jq -nc \
    --arg trigger_id "$trigger_id" \
    --arg alert_key "$alert_key" \
    --arg rule_id "R-FR01-ACCEPTANCE" \
    --arg lane "$lane" \
    --arg source_type "$source_type" \
    --arg event_type "$event_type" \
    --arg src_ip "$src_ip" \
    --arg user "$user_name" \
    --arg node_id "$node_id" \
    --argjson event_ts_unix_ms "$event_ts_ms" \
    --argjson observed_at_unix_ms "$recv_ts_ms" \
    --argjson alert_ts_unix_ms "$recv_ts_ms" \
    --argjson latency_ms "$((recv_ts_ms - event_ts_ms))" \
    '{
      msg: "response_trigger",
      trigger_kind: "alert",
      trigger_idem_key: $trigger_id,
      alert_key: $alert_key,
      rule_id: $rule_id,
      severity: "high",
      lane: $lane,
      source_type: $source_type,
      event_type: $event_type,
      src_ip: $src_ip,
      user: $user,
      agent_id: $node_id,
      group_by: "src_ip",
      group_key: $src_ip,
      observed_at_unix_ms: $observed_at_unix_ms,
      event_ts_unix_ms: $event_ts_unix_ms,
      alert_ts_unix_ms: $alert_ts_unix_ms,
      latency_ms: $latency_ms
    }')"
  nats pub "rsiem.response.triggers.fast" "$payload" >/dev/null
}

seq=0
for i in $(seq 1 15); do
  node_id="$(printf 'node-%02d' "$i")"
  src_ip="10.88.0.$((20 + i))"
  for event_type in auth_failed process_exec file_change; do
    seq=$((seq + 1))
    event_ts_ms="$((base_ms + 500 + seq))"
    recv_ts_ms="$((event_ts_ms + 200))"
    publish_trigger "$seq" "tail" "$event_type" "$node_id" "$src_ip" "${run_tag}_${node_id}_${event_type}" "$event_ts_ms" "$recv_ts_ms" "FAST"
  done
done

seq=$((seq + 1)); publish_trigger "$seq" "syslog" "syslog" "node-01" "10.99.0.1" "${run_tag}_infra_syslog" "$((base_ms + 9001))" "$((base_ms + 9101))" "FAST"
seq=$((seq + 1)); publish_trigger "$seq" "netflow_v5" "netflow_flow" "node-02" "10.99.0.2" "${run_tag}_infra_netflow" "$((base_ms + 9002))" "$((base_ms + 9102))" "FAST"
seq=$((seq + 1)); publish_trigger "$seq" "snmp_trap" "snmp_trap" "node-03" "10.99.0.3" "${run_tag}_infra_snmp" "$((base_ms + 9003))" "$((base_ms + 9103))" "FAST"

expected_rows="$seq"

echo "[5/8] wait for DB rows"
observed_rows=0
for _ in $(seq 1 40); do
  observed_rows="$(query_db "SELECT count(*) FROM normalized_events WHERE id > ${before_max_id} AND user_name LIKE '${run_tag}_%';" | tail -n1)"
  observed_rows="${observed_rows:-0}"
  if (( observed_rows >= expected_rows )); then
    break
  fi
  sleep 1
done
if (( observed_rows < expected_rows )); then
  echo "FAIL: expected at least ${expected_rows} acceptance rows, observed ${observed_rows}" >&2
  exit 1
fi

echo "[6/8] query DB spot checks"
node_count="$(query_db "SELECT count(DISTINCT node_id) FROM normalized_events WHERE id > ${before_max_id} AND user_name LIKE '${run_tag}_%';" | tail -n1)"
node_count="${node_count:-0}"

source_types_raw="$(query_db "SELECT DISTINCT source_type FROM normalized_events WHERE id > ${before_max_id} AND user_name LIKE '${run_tag}_%' ORDER BY source_type;")"
source_types_json="$(printf '%s\n' "$source_types_raw" | jq -Rsc 'split("\n") | map(select(length>0))')"

event_types_raw="$(query_db "SELECT DISTINCT event_type FROM normalized_events WHERE id > ${before_max_id} AND user_name LIKE '${run_tag}_%' AND event_type IN ('auth_failed','process_exec','file_change') ORDER BY event_type;")"
event_types_json="$(printf '%s\n' "$event_types_raw" | jq -Rsc 'split("\n") | map(select(length>0))')"

latencies_file="$(mktemp /tmp/fr01_acceptance_latencies.XXXXXX)"
query_db "SELECT (recv_ts_unix_ms - event_ts_unix_ms) FROM normalized_events WHERE id > ${before_max_id} AND user_name LIKE '${run_tag}_%' AND event_type IN ('auth_failed','process_exec','file_change') ORDER BY 1;" > "$latencies_file"

latency_metrics="$(python3 - "$latencies_file" <<'PY'
import json
import math
import sys

path = sys.argv[1]
vals = []
with open(path, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        vals.append(int(line))

if not vals:
    print(json.dumps({"count": 0, "p50": 0, "p95": 0, "max": 0}))
    raise SystemExit(0)

vals.sort()
n = len(vals)

def percentile(p):
    idx = max(0, min(n - 1, math.ceil((p / 100.0) * n) - 1))
    return vals[idx]

print(json.dumps({
    "count": n,
    "p50": percentile(50),
    "p95": percentile(95),
    "max": vals[-1],
}))
PY
)"

lat_count="$(echo "$latency_metrics" | jq -r '.count')"
lat_p50="$(echo "$latency_metrics" | jq -r '.p50')"
lat_p95="$(echo "$latency_metrics" | jq -r '.p95')"
lat_max="$(echo "$latency_metrics" | jq -r '.max')"

echo "[7/8] validate acceptance constraints"
[[ "$node_count" =~ ^[0-9]+$ ]] || node_count=0
if (( node_count < 15 )); then
  echo "FAIL: observed_distinct_nodes=${node_count}, expected >=15" >&2
  exit 1
fi
for required_source in syslog netflow_v5 snmp_trap tail; do
  echo "$source_types_json" | jq -e --arg s "$required_source" 'index($s) != null' >/dev/null || {
    echo "FAIL: missing source_type=${required_source} in acceptance DB window" >&2
    exit 1
  }
done
for required_event in auth_failed process_exec file_change; do
  echo "$event_types_json" | jq -e --arg e "$required_event" 'index($e) != null' >/dev/null || {
    echo "FAIL: missing endpoint event_type=${required_event} in acceptance DB window" >&2
    exit 1
  }
done
if (( lat_count <= 0 )); then
  echo "FAIL: no endpoint latency rows found" >&2
  exit 1
fi
if (( lat_max > 5000 )); then
  echo "FAIL: endpoint latency max=${lat_max}ms exceeds 5000ms" >&2
  exit 1
fi

echo "[8/8] write acceptance artifacts"
artifact_ts="$(date -u +%Y%m%d_%H%M%S)"
artifact_dir="demo_artifacts/${artifact_ts}/fr01_acceptance"
mkdir -p "$artifact_dir"

sample_rows_file="${artifact_dir}/fr01_acceptance_db_rows_sample.jsonl"
query_db "SELECT row_to_json(t) FROM (SELECT id, ingest_ts, event_ts_unix_ms, recv_ts_unix_ms, node_id, source_type, event_type, src_ip::text AS src_ip, user_name, event_idem_key FROM normalized_events WHERE id > ${before_max_id} AND user_name LIKE '${run_tag}_%' ORDER BY id ASC LIMIT 10) t;" > "$sample_rows_file"

latency_json="${artifact_dir}/fr01_acceptance_db_latency.json"
cat > "$latency_json" <<JSON
{
  "count": ${lat_count},
  "p50": ${lat_p50},
  "p95": ${lat_p95},
  "max": ${lat_max},
  "threshold_ms": 5000
}
JSON

proof_json="${artifact_dir}/fr01_acceptance_proof.json"
jq -n \
  --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg db_container "$DB_CONTAINER_NAME" \
  --arg syslog_proof "$syslog_proof" \
  --arg netflow_proof "$netflow_proof" \
  --arg snmp_proof "$snmp_proof" \
  --argjson observed_nodes "$node_count" \
  --argjson source_types "$source_types_json" \
  --argjson event_types "$event_types_json" \
  --argjson lat_count "$lat_count" \
  --argjson lat_p50 "$lat_p50" \
  --argjson lat_p95 "$lat_p95" \
  --argjson lat_max "$lat_max" \
  '{
    timestamp: $timestamp,
    pass: true,
    db: { container: $db_container, table: "normalized_events" },
    node_count: { expected_max: 15, observed_distinct: $observed_nodes },
    spot_checks: {
      source_types_observed: $source_types,
      event_types_observed: $event_types
    },
    latency_ms: {
      count: $lat_count,
      p50: $lat_p50,
      p95: $lat_p95,
      max: $lat_max,
      threshold_ms: 5000
    },
    component_proofs: {
      syslog: $syslog_proof,
      netflowv5: $netflow_proof,
      snmptrap: $snmp_proof
    }
  }' > "$proof_json"

echo "PASS: FR-01 acceptance completed"
echo "FR01_ACCEPTANCE_PROOF_JSON=${proof_json}"
