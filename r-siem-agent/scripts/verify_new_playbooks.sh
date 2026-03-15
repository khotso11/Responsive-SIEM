#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

LOG_MASTER="logs/master-roe.log"
LOG_AGENT="logs/agent.log"
LOG_WORKER="logs/worker.log"
EXPORT_RUNS="exports/roe_runs.jsonl"
EXPORT_STEPS="exports/roe_steps.jsonl"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "FAIL: missing command: $1" >&2
    exit 1
  }
}

json_escape() {
  local s="${1:-}"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/}"
  printf '%s' "$s"
}

json_or_null() {
  local s="${1:-}"
  if [[ -z "$s" ]]; then
    printf 'null'
  else
    printf '"%s"' "$(json_escape "$s")"
  fi
}

json_string_array_from_csv() {
  local csv="${1:-}"
  local out="["
  local first=1
  IFS=',' read -r -a values <<< "$csv"
  local value trimmed
  for value in "${values[@]}"; do
    trimmed="$(echo "$value" | xargs)"
    [[ -n "$trimmed" ]] || continue
    if [[ "$first" -eq 0 ]]; then
      out+=","
    fi
    out+="\"$(json_escape "$trimmed")\""
    first=0
  done
  out+="]"
  printf '%s' "$out"
}

line_count() {
  local file="$1"
  [[ -f "$file" ]] || { echo 0; return; }
  wc -l < "$file" | tr -d '[:space:]'
}

tail_from() {
  local file="$1"
  local base="$2"
  tail -n "+$((base + 1))" "$file" 2>/dev/null || true
}

wait_match_rg() {
  local file="$1"
  local base="$2"
  local pattern="$3"
  local timeout="${4:-30}"
  local i=0
  while (( i < timeout * 5 )); do
    local line
    line="$(tail_from "$file" "$base" | rg "$pattern" | head -n 1 || true)"
    if [[ -n "$line" ]]; then
      printf '%s\n' "$line"
      return 0
    fi
    sleep 0.2
    i=$((i + 1))
  done
  return 1
}

fail_with_context() {
  local msg="$1"
  echo "FAIL: ${msg}" >&2
  echo "Context: tail -n 60 ${LOG_MASTER}" >&2
  tail -n 60 "$LOG_MASTER" >&2 || true
  echo "Context: tail -n 60 ${LOG_AGENT}" >&2
  tail -n 60 "$LOG_AGENT" >&2 || true
  exit 1
}

publish_trigger() {
  local playbook_id="$1"
  local rule_id="$2"
  local lane="FAST"
  local now_ms
  now_ms="$(date +%s%3N)"
  local token
  token="$(date +%s%N 2>/dev/null || printf '%s000000000' "$(date +%s)")"
  local trigger_id="trig.manual.${rule_id}.${token}"
  local alert_key="A-MANUAL-${rule_id}-${token}"
  local payload
  payload="{\"msg\":\"response_trigger\",\"trigger_idem_key\":\"${trigger_id}\",\"alert_key\":\"${alert_key}\",\"rule_id\":\"${rule_id}\",\"severity\":\"high\",\"lane\":\"${lane}\",\"group_by\":\"src_ip\",\"group_key\":\"manual.${playbook_id}.${token}\",\"observed_at_unix_ms\":${now_ms}}"
  nats pub rsiem.response.triggers.fast "$payload" >/dev/null
}

publish_internal_scan_trigger() {
  local playbook_id="$1"
  local rule_id="$2"
  local protocol_family="$3"
  local dst_port="$4"
  local dst_ip="$5"
  local top_destinations_csv="$6"
  local lane="FAST"
  local now_ms
  now_ms="$(date +%s%3N)"
  local token
  token="$(date +%s%N 2>/dev/null || printf '%s000000000' "$(date +%s)")"
  local trigger_id="trig.manual.${rule_id}.${token}"
  local alert_key="A-MANUAL-${rule_id}-${token}"
  local top_destinations_json
  top_destinations_json="$(json_string_array_from_csv "$top_destinations_csv")"
  local scan_fanout
  scan_fanout="$(printf '%s\n' "$top_destinations_csv" | awk -F',' '{print NF}')"
  local payload
  payload="{\"msg\":\"response_trigger\",\"trigger_idem_key\":\"${trigger_id}\",\"alert_key\":\"${alert_key}\",\"rule_id\":\"${rule_id}\",\"severity\":\"high\",\"lane\":\"${lane}\",\"group_by\":\"host\",\"group_key\":\"manual.${playbook_id}.${token}\",\"observed_at_unix_ms\":${now_ms},\"event_type\":\"network_connection\",\"source_type\":\"auditd_connect\",\"node_id\":\"verify-new-playbooks-node\",\"user\":\"verify_new_playbooks\",\"dst_ip\":\"${dst_ip}\",\"dst_port\":${dst_port},\"protocol_family\":\"${protocol_family}\",\"scan_fanout\":${scan_fanout},\"top_destinations\":${top_destinations_json}}"
  nats pub rsiem.response.triggers.fast "$payload" >/dev/null
}

need_cmd rg
need_cmd nats
need_cmd date
need_cmd hostname

mkdir -p logs exports tmp demo_artifacts
: > tmp/demo.log
rm -f tmp/tail.checkpoint.json

./scripts/demo_down.sh >/dev/null 2>&1 || true
# Ensure no stale demo processes from prior runs remain subscribed.
pkill -f '/master-roe-worker --config' >/dev/null 2>&1 || true
pkill -f '/master-roe --config' >/dev/null 2>&1 || true
pkill -f '/agent --config' >/dev/null 2>&1 || true
pkill -f '/detector-v0 --config' >/dev/null 2>&1 || true
pkill -f '/collector-tail --config' >/dev/null 2>&1 || true
sleep 1
./scripts/demo_up.sh >/dev/null

[[ -f "$LOG_MASTER" ]] || fail_with_context "missing ${LOG_MASTER}"
[[ -f "$LOG_AGENT" ]] || fail_with_context "missing ${LOG_AGENT}"
[[ -f "$EXPORT_RUNS" ]] || fail_with_context "missing ${EXPORT_RUNS}"

playbooks=(
  "PB-BRUTEFORCE-IP-CONTAIN|R-PB-BRUTEFORCE-IP-CONTAIN|SUCCEEDED|contain_bruteforce_ip"
  "PB-PRIVESC-LOCKDOWN|R-PB-PRIVESC-LOCKDOWN|SUCCEEDED|lockdown_privesc"
  "PB-LATERAL-MOVEMENT-HALT|R-PB-LATERAL-MOVEMENT-HALT|SUCCEEDED|halt_lateral_movement"
  "PB-C2-BEACON-BLOCK|R-PB-C2-BEACON-BLOCK|SUCCEEDED|block_c2_beacon"
  "PB-RANSOMWARE-KILL-CHAIN-STOP|R-PB-RANSOMWARE-KILL-CHAIN-STOP|FAILED_SAFE|kill_chain_stage,kill_chain_stop"
  "PB-DATA-EXFIL-THROTTLE|R-PB-DATA-EXFIL-THROTTLE|SUCCEEDED|throttle_exfil"
  "PB-CRITICAL-SERVICE-ABUSE-RESPONSE|R-PB-CRITICAL-SERVICE-ABUSE-RESPONSE|FAILED_SAFE|protect_critical_service_stage,protect_critical_service"
  "PB-DETECTOR-HEALTH-SELF-PROTECT|R-PB-DETECTOR-HEALTH-SELF-PROTECT|SUCCEEDED|detector_self_protect"
)

timestamp="$(date +%Y%m%d_%H%M%S)"
artifact_dir="demo_artifacts/${timestamp}"
mkdir -p "$artifact_dir"
proof_json="${artifact_dir}/new_playbooks_proof.json"

entries_file="${artifact_dir}/playbook_entries.jsonl"
: > "$entries_file"

success_count=0
failed_safe_count=0

for item in "${playbooks[@]}"; do
  IFS='|' read -r playbook_id rule_id expected_status command_list <<< "$item"

  base_master="$(line_count "$LOG_MASTER")"
  base_agent="$(line_count "$LOG_AGENT")"
  base_runs="$(line_count "$EXPORT_RUNS")"

  publish_trigger "$playbook_id" "$rule_id"

  run_created_line="$(wait_match_rg "$LOG_MASTER" "$base_master" "\"msg\":\"response_run_created\".*\"rule_id\":\"${rule_id}\".*\"playbook_id\":\"${playbook_id}\"" 40 || true)"
  [[ -n "$run_created_line" ]] || fail_with_context "missing run_created for ${playbook_id}"

  run_id="$(printf '%s\n' "$run_created_line" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p' | head -n 1)"
  [[ -n "$run_id" ]] || fail_with_context "failed to parse run_id for ${playbook_id}"

  waiting_line="$(wait_match_rg "$LOG_MASTER" "$base_master" "\"msg\":\"response_run_waiting_approval\".*\"run_id\":\"${run_id}\"" 5 || true)"
  if [[ -n "$waiting_line" ]]; then
    nats pub rsiem.response.approvals "{\"run_id\":\"${run_id}\",\"decision\":\"approve\",\"actor\":\"verify_new_playbooks\"}" >/dev/null
  else
    approval_policy_line="$(wait_match_rg "$LOG_MASTER" "$base_master" "\"msg\":\"approval_policy_evaluated\".*\"run_id\":\"${run_id}\"" 10 || true)"
    [[ -n "$approval_policy_line" ]] || fail_with_context "missing approval policy line for ${playbook_id} run_id=${run_id}"
    printf '%s\n' "$approval_policy_line" | rg -q '"approval_required":false' \
      || fail_with_context "missing waiting_approval for ${playbook_id} run_id=${run_id}"
  fi

  run_updated_line="$(wait_match_rg "$LOG_MASTER" "$base_master" "\"msg\":\"response_run_updated\".*\"run_id\":\"${run_id}\".*\"status\":\"${expected_status}\"" 60 || true)"
  [[ -n "$run_updated_line" ]] || fail_with_context "missing terminal run_updated ${expected_status} for ${playbook_id} run_id=${run_id}"

  operator_action=""
  failed_safe_reason=""
  partial_line=""
  if [[ "$expected_status" == "FAILED_SAFE" ]]; then
    partial_line="$(wait_match_rg "$LOG_MASTER" "$base_master" "\"msg\":\"response_run_partial_completion\".*\"run_id\":\"${run_id}\"" 20 || true)"
    [[ -n "$partial_line" ]] || fail_with_context "missing partial completion line for ${playbook_id} run_id=${run_id}"
    operator_action="$(printf '%s\n' "$partial_line" | sed -n 's/.*"operator_action":"\([^"]*\)".*/\1/p' | tail -n 1)"
    [[ "$operator_action" == "manual_restore_check_recommended" ]] || fail_with_context "unexpected operator_action for ${playbook_id}: ${operator_action:-<empty>}"
    failed_safe_reason="$(printf '%s\n' "$run_updated_line" | sed -n 's/.*"failed_safe_reason":"\([^"]*\)".*/\1/p' | tail -n 1)"
    if [[ -z "$failed_safe_reason" ]]; then
      failed_safe_reason="$(printf '%s\n' "$partial_line" | sed -n 's/.*"failed_safe_reason":"\([^"]*\)".*/\1/p' | tail -n 1)"
    fi
    [[ -n "$failed_safe_reason" ]] || fail_with_context "missing failed_safe_reason for ${playbook_id} run_id=${run_id}"
    failed_safe_count=$((failed_safe_count + 1))
  else
    success_count=$((success_count + 1))
  fi

  IFS=',' read -r -a command_ids <<< "$command_list"
  agent_lines=()
  for command_id in "${command_ids[@]}"; do
    command_id="$(echo "$command_id" | xargs)"
    line="$(tail_from "$LOG_AGENT" "$base_agent" | rg "\"msg\":\"agent_command_exec_start\".*\"run_id\":\"${run_id}\".*\"command_id\":\"${command_id}\"" | tail -n 1 || true)"
    [[ -n "$line" ]] || fail_with_context "missing agent_command_exec_start for ${playbook_id} run_id=${run_id} command_id=${command_id}"
    agent_lines+=("$line")
  done

  export_run_line="$(tail_from "$EXPORT_RUNS" "$base_runs" | rg "\"run_id\":\"${run_id}\".*\"status\":\"${expected_status}\"" | tail -n 1 || true)"
  [[ -n "$export_run_line" ]] || fail_with_context "missing export run line for ${playbook_id} run_id=${run_id}"

  agent_lines_json="["
  for line in "${agent_lines[@]}"; do
    if [[ "$agent_lines_json" != "[" ]]; then
      agent_lines_json+=" ,"
    fi
    agent_lines_json+="\"$(json_escape "$line")\""
  done
  agent_lines_json+="]"

  printf '{"playbook_id":"%s","run_id":"%s","expected_status":"%s","operator_action":%s,"failed_safe_reason":%s,"evidence":{"run_created_line":"%s","run_updated_line":"%s","agent_exec_lines":%s,"exports_run_line":"%s"}}\n' \
    "$(json_escape "$playbook_id")" \
    "$(json_escape "$run_id")" \
    "$(json_escape "$expected_status")" \
    "$(json_or_null "$operator_action")" \
    "$(json_or_null "$failed_safe_reason")" \
    "$(json_escape "$run_created_line")" \
    "$(json_escape "$run_updated_line")" \
    "$agent_lines_json" \
    "$(json_escape "$export_run_line")" >> "$entries_file"

done

internal_scan_cases=(
  "PB-NET-INTERNAL-SCAN-CONTAIN|R-NET-INTERNAL-SSH-SCAN|ssh|22|172.30.50.13|172.30.50.13,172.30.50.12,172.30.50.11,172.30.50.14"
  "PB-NET-INTERNAL-SCAN-CONTAIN|R-NET-INTERNAL-RPC-SCAN|rpc|135|172.30.50.13|172.30.50.13,172.30.50.12,172.30.50.11,172.30.50.14"
  "PB-NET-INTERNAL-SCAN-CONTAIN|R-NET-INTERNAL-LDAP-SCAN|ldap|389|172.30.50.13|172.30.50.13,172.30.50.12,172.30.50.11,172.30.50.14"
  "PB-NET-INTERNAL-SCAN-CONTAIN|R-NET-INTERNAL-SMB-SCAN|smb|445|172.30.50.13|172.30.50.13,172.30.50.12,172.30.50.11,172.30.50.14"
  "PB-NET-INTERNAL-SCAN-CONTAIN|R-NET-INTERNAL-RDP-SCAN|rdp|3389|172.30.50.13|172.30.50.13,172.30.50.12,172.30.50.11,172.30.50.14"
  "PB-NET-INTERNAL-SCAN-CONTAIN|R-NET-INTERNAL-WINRM-SCAN|winrm|5985|172.30.50.13|172.30.50.13,172.30.50.12,172.30.50.11,172.30.50.14"
)

for item in "${internal_scan_cases[@]}"; do
  IFS='|' read -r playbook_id rule_id protocol_family dst_port dst_ip top_destinations_csv <<< "$item"

  base_master="$(line_count "$LOG_MASTER")"
  base_agent="$(line_count "$LOG_AGENT")"
  base_runs="$(line_count "$EXPORT_RUNS")"

  publish_internal_scan_trigger "$playbook_id" "$rule_id" "$protocol_family" "$dst_port" "$dst_ip" "$top_destinations_csv"

  run_created_line="$(wait_match_rg "$LOG_MASTER" "$base_master" "\"msg\":\"response_run_created\".*\"rule_id\":\"${rule_id}\".*\"playbook_id\":\"${playbook_id}\"" 40 || true)"
  [[ -n "$run_created_line" ]] || fail_with_context "missing run_created for ${playbook_id}/${rule_id}"

  run_id="$(printf '%s\n' "$run_created_line" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p' | head -n 1)"
  [[ -n "$run_id" ]] || fail_with_context "failed to parse run_id for ${playbook_id}/${rule_id}"

  printf '%s\n' "$run_created_line" | rg -q "\"dst_ip\":\"${dst_ip}\"" \
    || fail_with_context "missing dst_ip assertion for ${playbook_id}/${rule_id}"
  printf '%s\n' "$run_created_line" | rg -q "\"dst_port\":${dst_port}" \
    || fail_with_context "missing dst_port assertion for ${playbook_id}/${rule_id}"
  printf '%s\n' "$run_created_line" | rg -q "\"protocol_family\":\"${protocol_family}\"" \
    || fail_with_context "missing protocol_family assertion for ${playbook_id}/${rule_id}"
  printf '%s\n' "$run_created_line" | rg -q "\"scan_fanout\":4" \
    || fail_with_context "missing scan_fanout assertion for ${playbook_id}/${rule_id}"
  IFS=',' read -r -a top_destinations <<< "$top_destinations_csv"
  for destination in "${top_destinations[@]}"; do
    destination="$(echo "$destination" | xargs)"
    printf '%s\n' "$run_created_line" | rg -q "\"${destination}\"" \
      || fail_with_context "missing top_destination ${destination} for ${playbook_id}/${rule_id}"
  done

  approval_policy_line="$(wait_match_rg "$LOG_MASTER" "$base_master" "\"msg\":\"approval_policy_evaluated\".*\"run_id\":\"${run_id}\"" 10 || true)"
  [[ -n "$approval_policy_line" ]] || fail_with_context "missing approval policy line for ${playbook_id}/${rule_id} run_id=${run_id}"
  printf '%s\n' "$approval_policy_line" | rg -q '"approval_required":false' \
    || fail_with_context "expected auto approval for ${playbook_id}/${rule_id} run_id=${run_id}"

  run_updated_line="$(wait_match_rg "$LOG_MASTER" "$base_master" "\"msg\":\"response_run_updated\".*\"run_id\":\"${run_id}\".*\"status\":\"SUCCEEDED\"" 60 || true)"
  [[ -n "$run_updated_line" ]] || fail_with_context "missing terminal SUCCEEDED run_updated for ${playbook_id}/${rule_id} run_id=${run_id}"

  agent_line="$(tail_from "$LOG_AGENT" "$base_agent" | rg "\"msg\":\"agent_command_exec_start\".*\"run_id\":\"${run_id}\".*\"command_id\":\"halt_lateral_movement\"" | tail -n 1 || true)"
  [[ -n "$agent_line" ]] || fail_with_context "missing halt_lateral_movement agent command for ${playbook_id}/${rule_id} run_id=${run_id}"

  export_run_line="$(tail_from "$EXPORT_RUNS" "$base_runs" | rg "\"run_id\":\"${run_id}\".*\"status\":\"SUCCEEDED\"" | tail -n 1 || true)"
  [[ -n "$export_run_line" ]] || fail_with_context "missing export run line for ${playbook_id}/${rule_id} run_id=${run_id}"

  success_count=$((success_count + 1))

  printf '{"playbook_id":"%s","run_id":"%s","expected_status":"SUCCEEDED","operator_action":null,"failed_safe_reason":null,"evidence":{"run_created_line":"%s","run_updated_line":"%s","agent_exec_lines":["%s"],"exports_run_line":"%s"}}\n' \
    "$(json_escape "$playbook_id")" \
    "$(json_escape "$run_id")" \
    "$(json_escape "$run_created_line")" \
    "$(json_escape "$run_updated_line")" \
    "$(json_escape "$agent_line")" \
    "$(json_escape "$export_run_line")" >> "$entries_file"
done

entry_count="$(wc -l < "$entries_file" | tr -d '[:space:]')"
[[ "$entry_count" == "14" ]] || fail_with_context "expected 14 playbook entries, got ${entry_count}"
[[ "$success_count" == "12" ]] || fail_with_context "expected 12 SUCCEEDED playbooks, got ${success_count}"
[[ "$failed_safe_count" == "2" ]] || fail_with_context "expected 2 FAILED_SAFE playbooks, got ${failed_safe_count}"

generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
host_name="$(hostname)"

{
  echo "{"
  echo "  \"timestamp\": \"$(json_escape "$generated_at")\"," 
  echo "  \"hostname\": \"$(json_escape "$host_name")\"," 
  echo "  \"playbooks\": ["
  awk 'NR==1{printf "    %s", $0} NR>1{printf ",\n    %s", $0}' "$entries_file"
  echo
  echo "  ],"
  echo "  \"logs\": { \"master\": \"${LOG_MASTER}\", \"agent\": \"${LOG_AGENT}\", \"worker\": \"${LOG_WORKER}\" },"
  echo "  \"exports\": { \"runs\": \"${EXPORT_RUNS}\", \"steps\": \"${EXPORT_STEPS}\" }"
  echo "}"
} > "$proof_json"

echo "PASS: new playbooks verification completed"
echo "NEW_PLAYBOOKS_PROOF_JSON=${proof_json}"
