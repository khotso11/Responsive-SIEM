#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

NATS_URL="${NATS_URL:-nats://127.0.0.1:4222}"
APPROVAL_ACTOR="${APPROVAL_ACTOR:-first_seen_proof}"
CONTROL_ROOT="${CONTROL_ROOT:-/var/lib/rsiem/containment_controls}"
PROCESS_WAIT_SECS="${PROCESS_WAIT_SECS:-6}"
NETWORK_WAIT_SECS="${NETWORK_WAIT_SECS:-8}"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "FAIL: missing required command: $1" >&2
    exit 1
  }
}

require_cmd rg
require_cmd nats
require_cmd sudo
require_cmd jq

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

sudo_line_count() {
  local file="$1"
  if sudo test -f "$file"; then
    sudo sh -c "wc -l < '$file'"
  else
    echo 0
  fi
}

extract_run_id() {
  sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p' | tail -n 1
}

approve_run() {
  local run_id="$1"
  nats --server "$NATS_URL" pub rsiem.response.approvals "{\"run_id\":\"${run_id}\",\"decision\":\"approve\",\"actor\":\"${APPROVAL_ACTOR}\"}" >/dev/null
}

print_run_summary() {
  local run_id="$1"
  rg "\"run_id\":\"${run_id}\"" logs/master-roe.log logs/worker.log | tail -n 20 || true
}

show_containment_record() {
  local run_id="$1"
  local path="${CONTROL_ROOT}/${run_id}.json"
  if sudo test -f "$path"; then
    echo "CONTAINMENT_RECORD=${path}"
    sudo cat "$path"
  else
    echo "FAIL: containment record missing for ${run_id}" >&2
    return 1
  fi
}

try_process_trigger() {
  local before_master="$1"
  local now_ms exec_path proof_user payload
  now_ms="$(date +%s%3N)"
  exec_path="/usr/bin/nmap"
  proof_user="proof_proc_${now_ms}"
  payload="$(
    jq -cn \
      --arg evt "evt.firstseen.proc.${now_ms}" \
      --arg now "$now_ms" \
      --arg node "$(hostname)" \
      --arg user "$proof_user" \
      --arg exec_path "$exec_path" \
      '{
        event_idem_key:$evt,
        observed_at_unix_ms:($now|tonumber),
        event_ts_unix_ms:($now|tonumber),
        recv_ts_unix_ms:($now|tonumber),
        message:("PROC exec=\"" + $exec_path + "\" comm=\"nmap\" cmdline=\"" + $exec_path + " --version\" user=" + $user + " src=127.0.0.1 ts=" + $now + " node=" + $node),
        raw_line:("PROC exec=\"" + $exec_path + "\""),
        host:$node,
        node_id:$node,
        group_key:$node,
        source:"first_seen_proof",
        source_type:"auditd_exec",
        event_type:"process_exec",
        src_ip:"127.0.0.1",
        user:$user,
        exec_path:$exec_path,
        comm:"nmap",
        cmdline:($exec_path + " --version"),
        exec_sha256:"proof-sha256",
        signer_hint:"unsigned"
      }'
  )"
  nats --server "$NATS_URL" pub rsiem.events.raw "$payload" >/dev/null
  sleep "$PROCESS_WAIT_SECS"
  new_lines logs/master-roe.log "$before_master" \
    | rg '"msg":"response_run_created".*"rule_id":"R-PROC-FIRST-SEEN-SUSPICIOUS"' \
    | extract_run_id
}

try_network_trigger() {
  local before_master="$1"
  local now_ms dst_ip payload
  now_ms="$(date +%s%3N)"
  dst_ip="93.184.216.$(( (now_ms % 100) + 10 ))"
  payload="$(
    jq -cn \
      --arg evt "evt.firstseen.net.${now_ms}" \
      --arg now "$now_ms" \
      --arg node "$(hostname)" \
      --arg dst_ip "$dst_ip" \
      '{
        event_idem_key:$evt,
        observed_at_unix_ms:($now|tonumber),
        event_ts_unix_ms:($now|tonumber),
        recv_ts_unix_ms:($now|tonumber),
        message:("NET src_ip=192.2.42.182 src_port=51000 dst_ip=" + $dst_ip + " dst_port=4444 state=established ts=" + $now + " node=" + $node),
        raw_line:("NET dst_ip=" + $dst_ip),
        host:$node,
        node_id:$node,
        group_key:"192.2.42.182",
        source:"first_seen_proof",
        source_type:"proc_net",
        event_type:"network_connection",
        src_ip:"192.2.42.182",
        dst_ip:$dst_ip,
        dst_port:4444,
        user:"unknown"
      }'
  )"
  nats --server "$NATS_URL" pub rsiem.events.raw "$payload" >/dev/null
  sleep "$NETWORK_WAIT_SECS"
  new_lines logs/master-roe.log "$before_master" \
    | rg '"msg":"response_run_created".*"rule_id":"R-NET-FIRST-SEEN-RISKY"' \
    | extract_run_id
}

echo "[1/6] Clean-starting the stack"
./scripts/demo_local_endpoint_clean_start.sh >/tmp/verify_first_seen_clean_start.out
tail -n 10 /tmp/verify_first_seen_clean_start.out

echo "[2/6] Restarting first-seen collectors"
sudo systemctl restart rsiem-collector-auditd rsiem-collector-procnet
sleep 3

echo "[3/6] Proving network first-seen containment"
before_master="$(line_count logs/master-roe.log)"
before_agent="$(sudo_line_count /var/log/rsiem/agent.log)"
net_run_id="$(try_network_trigger "$before_master" || true)"
if [ -z "${net_run_id}" ]; then
  echo "FAIL: did not observe R-NET-FIRST-SEEN-RISKY after trigger attempts" >&2
  exit 1
fi
echo "NET_RUN_ID=${net_run_id}"
approve_run "$net_run_id"
sleep "$NETWORK_WAIT_SECS"
print_run_summary "$net_run_id"
sudo tail -n +"$((before_agent + 1))" /var/log/rsiem/agent.log | rg "${net_run_id}|contain_destination_ip" | tail -n 20 || true
show_containment_record "$net_run_id"

echo "[4/6] Proving process first-seen containment"
before_master="$(line_count logs/master-roe.log)"
before_agent="$(sudo_line_count /var/log/rsiem/agent.log)"
proc_run_id="$(try_process_trigger "$before_master" || true)"
if [ -z "${proc_run_id}" ]; then
  echo "FAIL: did not observe R-PROC-FIRST-SEEN-SUSPICIOUS after trigger attempts" >&2
  exit 1
fi
echo "PROC_RUN_ID=${proc_run_id}"
approve_run "$proc_run_id"
sleep "$PROCESS_WAIT_SECS"
print_run_summary "$proc_run_id"
sudo tail -n +"$((before_agent + 1))" /var/log/rsiem/agent.log | rg "${proc_run_id}|contain_process_exec" | tail -n 20 || true
show_containment_record "$proc_run_id"

echo "[5/6] Fresh detector evidence"
new_lines logs/detector.log 0 | rg 'R-PROC-FIRST-SEEN-SUSPICIOUS|R-NET-FIRST-SEEN-RISKY' | tail -n 20 || true

echo "[6/6] PASS: first-seen containment paths verified"
