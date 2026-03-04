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

line_count() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    echo 0
    return
  fi
  wc -l <"$file" | tr -d '[:space:]'
}

tail_from() {
  local file="$1"
  local base="$2"
  if [[ ! -f "$file" ]]; then
    return 0
  fi
  sed -n "$((base + 1)),\$p" "$file"
}

wait_new_match() {
  local file="$1"
  local base="$2"
  local pattern="$3"
  local timeout_secs="$4"
  local end_ts=$(( $(date +%s) + timeout_secs ))
  while (( $(date +%s) <= end_ts )); do
    if tail_from "$file" "$base" | rg "$pattern" >/dev/null 2>&1; then
      tail_from "$file" "$base" | rg "$pattern" | head -n 1
      return 0
    fi
    sleep 1
  done
  return 1
}

fail_with_context() {
  local message="$1"
  echo "FAIL: ${message}" >&2
  echo "Context: worker (last 80 lines):" >&2
  tail -n 80 logs/worker.log >&2 || true
  echo "Context: agent1 (last 80 lines):" >&2
  tail -n 80 logs/agent.log >&2 || true
  echo "Context: agent2 (last 80 lines):" >&2
  tail -n 80 logs/agent2.log >&2 || true
  exit 1
}

cleanup() {
  if [[ -n "${AGENT2_PID:-}" ]] && kill -0 "$AGENT2_PID" >/dev/null 2>&1; then
    kill "$AGENT2_PID" >/dev/null 2>&1 || true
    wait "$AGENT2_PID" 2>/dev/null || true
  fi
  rm -f .pids/agent2.pid
}
trap cleanup EXIT

need_cmd rg
need_cmd jq
need_cmd nats
need_cmd go
need_cmd sha256sum

mkdir -p logs tmp .cache/go-build .pids demo_artifacts data

./scripts/demo_down.sh >/dev/null 2>&1 || true
./scripts/demo_up.sh >/dev/null

agent_cfg_src="configs/agent.yaml"
agent2_cfg="tmp/agent_multi_2.yaml"
agent2_log="logs/agent2.log"

addr="$(sed -n 's/^  addr:[[:space:]]*//p' "$agent_cfg_src" | head -n1)"
ca_path="$(sed -n 's/^    ca:[[:space:]]*//p' "$agent_cfg_src" | head -n1)"
cert_path="$(sed -n 's/^    cert:[[:space:]]*//p' "$agent_cfg_src" | head -n1)"
key_path="$(sed -n 's/^    key:[[:space:]]*//p' "$agent_cfg_src" | head -n1)"
server_name="$(sed -n 's/^    server_name:[[:space:]]*//p' "$agent_cfg_src" | head -n1)"
pin_sha="$(sed -n 's/^    server_cert_pin_sha256:[[:space:]]*//p' "$agent_cfg_src" | head -n1)"

[[ -n "$addr" && -n "$ca_path" && -n "$cert_path" && -n "$key_path" && -n "$server_name" ]] || {
  fail_with_context "failed to parse transport tls fields from ${agent_cfg_src}"
}

cat > "$agent2_cfg" <<EOF
log:
  level: INFO
heartbeat:
  interval_seconds: 60
mock:
  interval_seconds: 1
agent:
  name: r-siem-agent
  instance_id: agent.two
  quarantine_root: tmp/quarantine
  quarantine_allowed_source_roots:
    - tmp
lanes:
  fast_buffer: 1000
  standard_buffer: 5000
wal:
  path: ./data/agent-two.wal
  fsync: true
batch:
  fast:
    max_size: 50
    max_latency_ms: 200
  standard:
    max_size: 200
    max_latency_ms: 500
transport:
  mode: grpc_mtls
  addr: ${addr}
  ack_delay_ms: 150
  ack_drop_rate: 0.0
  tls:
    ca: ${ca_path}
    cert: ${cert_path}
    key: ${key_path}
    server_name: ${server_name}
EOF
if [[ -n "$pin_sha" ]]; then
  cat >> "$agent2_cfg" <<EOF
    server_cert_pin_sha256: ${pin_sha}
EOF
fi

: > "$agent2_log"
base_agent2="$(line_count logs/agent2.log)"
env GOCACHE="$ROOT_DIR/.cache/go-build" go run -mod=vendor ./cmd/agent --config "$agent2_cfg" >> "$agent2_log" 2>&1 &
AGENT2_PID=$!
echo "$AGENT2_PID" > .pids/agent2.pid
sleep 1
kill -0 "$AGENT2_PID" >/dev/null 2>&1 || fail_with_context "failed to start second agent"

base_agent1="$(line_count logs/agent.log)"
base_worker="$(line_count logs/worker.log)"

wait_new_match "$agent2_log" "$base_agent2" '"msg":"agent_command_subscribe"' 25 >/dev/null || \
  fail_with_context "agent2 did not subscribe to command subjects"

target_agent_id="agent.two"
run_id="multiagent_$(date -u +%Y%m%d%H%M%S)"
step_id="$(printf '%s' "${run_id}:targeted-step" | sha256sum | awk '{print substr($1,1,16)}')"
step_idem_key="step.${step_id}"

payload="$(jq -cn \
  --arg run_id "$run_id" \
  --arg step_id "$step_id" \
  --arg step_idem_key "$step_idem_key" \
  --arg target_agent_id "$target_agent_id" \
  '{
    run_id: $run_id,
    step_id: $step_id,
    step_index: 0,
    action_type: "agent_command",
    lane: "FAST",
    step_idem_key: $step_idem_key,
    attempt: 0,
    target: "10.9.8.7",
    target_agent_id: $target_agent_id,
    params: {
      command: "contain_bruteforce_ip",
      marker_file: "multiagent_targeting.txt"
    }
  }')"

nats pub rsiem.response.steps.fast "$payload" >/dev/null

wait_new_match logs/worker.log "$base_worker" "\"msg\":\"agent_command_request\".*\"run_id\":\"${run_id}\".*\"step_id\":\"${step_id}\".*\"subject\":\"rsiem\\.agent\\.command\\.${target_agent_id}\"" 30 >/dev/null || \
  fail_with_context "worker did not publish request to per-agent subject"
wait_new_match "$agent2_log" "$base_agent2" "\"msg\":\"agent_command_exec_start\".*\"run_id\":\"${run_id}\".*\"step_id\":\"${step_id}\"" 30 >/dev/null || \
  fail_with_context "target agent did not execute targeted step"
wait_new_match logs/worker.log "$base_worker" "\"msg\":\"step_succeeded\".*\"run_id\":\"${run_id}\".*\"step_id\":\"${step_id}\"" 30 >/dev/null || \
  fail_with_context "worker did not record step_succeeded for targeted step"

agent1_exec_count="$({ tail_from logs/agent.log "$base_agent1" | rg -c "\"msg\":\"agent_command_exec_start\".*\"run_id\":\"${run_id}\".*\"step_id\":\"${step_id}\""; } || echo 0)"
agent2_exec_count="$({ tail_from "$agent2_log" "$base_agent2" | rg -c "\"msg\":\"agent_command_exec_start\".*\"run_id\":\"${run_id}\".*\"step_id\":\"${step_id}\""; } || echo 0)"

[[ "$agent1_exec_count" == "0" ]] || fail_with_context "non-targeted agent executed targeted step count=${agent1_exec_count}"
[[ "$agent2_exec_count" =~ ^[1-9][0-9]*$ ]] || fail_with_context "targeted agent execute count=${agent2_exec_count}, expected >=1"

ts="$(date -u +%Y%m%d_%H%M%S)"
artifact_dir="demo_artifacts/${ts}"
proof_json="${artifact_dir}/multiagent_targeting_proof.json"
mkdir -p "$artifact_dir"

jq -n \
  --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg target_agent_id "$target_agent_id" \
  --arg run_id "$run_id" \
  --arg step_id "$step_id" \
  --argjson agent_a_executed false \
  --argjson agent_b_executed true \
  '{
    timestamp: $timestamp,
    target_agent_id: $target_agent_id,
    run_id: $run_id,
    step_id: $step_id,
    agent_a_executed: $agent_a_executed,
    agent_b_executed: $agent_b_executed,
    pass: true
  }' > "$proof_json"

echo "PASS: multi-agent targeting proof completed"
echo "MULTIAGENT_TARGETING_PROOF_JSON=${proof_json}"
