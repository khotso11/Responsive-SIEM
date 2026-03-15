#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CATALOG_PATH="$ROOT_DIR/scripts/adversary_emulation_catalog.json"
cd "$ROOT_DIR"

NATS_URL="${NATS_URL:-nats://127.0.0.1:4222}"
UI_BASE_URL="${UI_BASE_URL:-http://127.0.0.1:3100}"
APPROVAL_ACTOR="${APPROVAL_ACTOR:-adversary_harness}"
HOST_NODE_ID="${HOST_NODE_ID:-$(hostname)}"
ARTIFACTS_ROOT_DEFAULT="$ROOT_DIR/retained/reports/adversary_emulation"
ARTIFACTS_DIR=""
SCENARIO_SELECTION="all"
SKIP_CLEAN_START=0
LIST_ONLY=0
KEEP_GOING=0

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "FAIL: missing required command: $1" >&2
    exit 1
  }
}

for cmd in jq nats rg sed date mktemp; do
  require_cmd "$cmd"
done

usage() {
  cat <<'EOF'
Usage:
  ./scripts/adversary_emulation_harness.sh [options]

Options:
  --list                    List available ATT&CK-mapped scenarios and exit.
  --scenario <id>           Run one scenario from the catalog.
  --all                     Run all scenarios (default).
  --artifacts-dir <dir>     Write proof artifacts under this directory.
  --no-clean-start          Do not run demo_local_endpoint_clean_start.sh first.
  --keep-going              Continue after a failed scenario and report all results.
  -h, --help                Show this help text.

Environment:
  NATS_URL                  NATS endpoint. Default: nats://127.0.0.1:4222
  UI_BASE_URL               UI base URL recorded in artifacts.
  APPROVAL_ACTOR            Actor name for automatic approvals.
  HOST_NODE_ID              Node id used in injected scenarios. Default: hostname
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --list)
      LIST_ONLY=1
      shift
      ;;
    --scenario)
      SCENARIO_SELECTION="${2:-}"
      shift 2
      ;;
    --all)
      SCENARIO_SELECTION="all"
      shift
      ;;
    --artifacts-dir)
      ARTIFACTS_DIR="${2:-}"
      shift 2
      ;;
    --no-clean-start)
      SKIP_CLEAN_START=1
      shift
      ;;
    --keep-going)
      KEEP_GOING=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "FAIL: unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ ! -f "$CATALOG_PATH" ]]; then
  echo "FAIL: missing catalog: $CATALOG_PATH" >&2
  exit 1
fi

if [[ $LIST_ONLY -eq 1 ]]; then
  jq -r '.scenarios[] | "\(.id)\t\(.technique_id)\t\(.tactic)\t\(.expected_rule_id)\t\(.expected_playbook_id)\t\(.description)"' "$CATALOG_PATH"
  exit 0
fi

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-$ARTIFACTS_ROOT_DEFAULT/$TIMESTAMP}"
mkdir -p "$ARTIFACTS_DIR"

line_count() {
  local file="$1"
  if [[ -f "$file" ]]; then
    wc -l < "$file"
  else
    echo 0
  fi
}

new_lines() {
  local file="$1"
  local start_line="$2"
  if [[ ! -f "$file" ]]; then
    return 0
  fi
  tail -n +"$((start_line + 1))" "$file"
}

extract_run_id() {
  sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p' | tail -n 1
}

extract_json_field() {
  local json_line="$1"
  local field="$2"
  jq -r --arg field "$field" '.[$field] // empty' <<<"$json_line"
}

approve_run() {
  local run_id="$1"
  nats --server "$NATS_URL" pub rsiem.response.approvals "{\"run_id\":\"${run_id}\",\"decision\":\"approve\",\"actor\":\"${APPROVAL_ACTOR}\"}" >/dev/null
}

find_final_run_json() {
  local run_id="$1"
  if [[ -f "$ROOT_DIR/exports/roe_runs.jsonl" ]]; then
    rg "\"run_id\":\"${run_id}\"" "$ROOT_DIR/exports/roe_runs.jsonl" | tail -n 1 || true
  fi
}

wait_for_run_json() {
  local run_id="$1"
  local attempts="${2:-20}"
  local delay="${3:-1}"
  local line=""
  for ((i=0; i<attempts; i++)); do
    line="$(find_final_run_json "$run_id")"
    if [[ -n "$line" ]]; then
      printf '%s\n' "$line"
      return 0
    fi
    sleep "$delay"
  done
  return 1
}

check_artifact() {
  local kind="$1"
  local run_id="$2"
  local path=""
  case "$kind" in
    none)
      jq -n '{present:false}'
      ;;
    containment_control)
      path="/var/lib/rsiem/containment_controls/${run_id}.json"
      if sudo test -f "$path"; then
        sudo cat "$path" | jq --arg path "$path" '. + {present:true, path:$path}'
      else
        jq -n --arg path "$path" '{present:false, path:$path}'
      fi
      ;;
    auth_control)
      path="/var/lib/rsiem/auth_controls/${run_id}.json"
      if sudo test -f "$path"; then
        sudo cat "$path" | jq --arg path "$path" '. + {present:true, path:$path}'
      else
        jq -n --arg path "$path" '{present:false, path:$path}'
      fi
      ;;
    *)
      jq -n --arg kind "$kind" '{present:false, unsupported_kind:$kind}'
      ;;
  esac
}

scenario_publish_t1110_auth_abuse_burst() {
  local now_ms src_ip base_user payload event_ids=()
  now_ms="$(date +%s%3N)"
  src_ip="10.99.90.$(( (now_ms % 150) + 10 ))"
  base_user="proof_auth_${now_ms}"
  for i in $(seq 1 8); do
    payload="$(
      jq -cn \
        --arg evt "evt.emu.t1110.${now_ms}.${i}" \
        --arg now "$((now_ms + i))" \
        --arg node "$HOST_NODE_ID" \
        --arg src_ip "$src_ip" \
        --arg user "${base_user}_${i}" \
        '{
          event_idem_key:$evt,
          observed_at_unix_ms:($now|tonumber),
          event_ts_unix_ms:($now|tonumber),
          recv_ts_unix_ms:($now|tonumber),
          message:("Failed password for " + $user + " from " + $src_ip + " port 22 ssh2"),
          line:("Failed password for " + $user + " from " + $src_ip + " port 22 ssh2"),
          host:$node,
          node_id:$node,
          source_type:"host",
          event_type:"auth_failed",
          src_ip:$src_ip,
          user:$user,
          group_key:$src_ip,
          source:"adversary-emulation"
        }'
    )"
    nats --server "$NATS_URL" pub rsiem.events.raw "$payload" >/dev/null
    event_ids+=("\"evt.emu.t1110.${now_ms}.${i}\"")
  done
  printf '[%s]\n' "$(IFS=,; echo "${event_ids[*]}")"
}

scenario_publish_t1046_first_seen_process() {
  local now_ms payload
  now_ms="$(date +%s%3N)"
  payload="$(
    jq -cn \
      --arg evt "evt.emu.t1046.${now_ms}" \
      --arg now "$now_ms" \
      --arg node "$HOST_NODE_ID" \
      '{
        event_idem_key:$evt,
        observed_at_unix_ms:($now|tonumber),
        event_ts_unix_ms:($now|tonumber),
        recv_ts_unix_ms:($now|tonumber),
        message:"exec=/usr/bin/nmap user=alice",
        raw_line:"PROC exec=/usr/bin/nmap",
        host:$node,
        node_id:$node,
        source_type:"auditd_exec",
        event_type:"process_exec",
        src_ip:"127.0.0.1",
        user:"alice",
        exec_path:"/usr/bin/nmap",
        comm:"nmap",
        cmdline:"/usr/bin/nmap --version",
        exec_sha256:"proof-sha256",
        signer_hint:"unsigned",
        group_key:$node,
        source:"adversary-emulation"
      }'
  )"
  nats --server "$NATS_URL" pub rsiem.events.raw "$payload" >/dev/null
  printf '["evt.emu.t1046.%s"]\n' "$now_ms"
}

scenario_publish_t1071_004_dns_suspicious() {
  local now_ms payload
  now_ms="$(date +%s%3N)"
  payload="$(
    jq -cn \
      --arg evt "evt.emu.t1071_004.${now_ms}" \
      --arg now "$now_ms" \
      --arg node "$HOST_NODE_ID" \
      '{
        event_idem_key:$evt,
        observed_at_unix_ms:($now|tonumber),
        event_ts_unix_ms:($now|tonumber),
        recv_ts_unix_ms:($now|tonumber),
        message:"dns suspicious query beacon.top",
        host:$node,
        node_id:$node,
        source_type:"dns_packet",
        event_type:"dns_query",
        src_ip:"192.2.42.182",
        dst_ip:"192.2.42.1",
        user:"unknown",
        dns_name:"beacon.top",
        dns_type:"A",
        group_key:"beacon.top",
        source:"adversary-emulation"
      }'
  )"
  nats --server "$NATS_URL" pub rsiem.events.raw "$payload" >/dev/null
  printf '["evt.emu.t1071_004.%s"]\n' "$now_ms"
}

scenario_publish_t1565_001_sensitive_file_change() {
  local now_ms payload
  now_ms="$(date +%s%3N)"
  payload="$(
    jq -cn \
      --arg evt "evt.emu.t1565_001.${now_ms}" \
      --arg now "$now_ms" \
      --arg node "$HOST_NODE_ID" \
      '{
        event_idem_key:$evt,
        observed_at_unix_ms:($now|tonumber),
        event_ts_unix_ms:($now|tonumber),
        recv_ts_unix_ms:($now|tonumber),
        message:"FILE path=/etc/sudoers.d/rsiem-emulation action=modify",
        host:$node,
        node_id:$node,
        source_type:"inotify",
        event_type:"file_change",
        src_ip:"127.0.0.1",
        user:"khotso",
        file_path:"/etc/sudoers.d/rsiem-emulation",
        action:"modified",
        group_key:"/etc/sudoers.d/rsiem-emulation",
        source:"adversary-emulation"
      }'
  )"
  nats --server "$NATS_URL" pub rsiem.events.raw "$payload" >/dev/null
  printf '["evt.emu.t1565_001.%s"]\n' "$now_ms"
}

scenario_publish_t1071_001_first_seen_risky_destination() {
  local now_ms dst_ip payload
  now_ms="$(date +%s%3N)"
  dst_ip="93.184.216.$(( (now_ms % 50) + 20 ))"
  payload="$(
    jq -cn \
      --arg evt "evt.emu.t1071_001.${now_ms}" \
      --arg now "$now_ms" \
      --arg node "$HOST_NODE_ID" \
      --arg dst_ip "$dst_ip" \
      '{
        event_idem_key:$evt,
        observed_at_unix_ms:($now|tonumber),
        event_ts_unix_ms:($now|tonumber),
        recv_ts_unix_ms:($now|tonumber),
        message:("NET dst_ip=" + $dst_ip + " dst_port=4444"),
        host:$node,
        node_id:$node,
        source_type:"proc_net",
        event_type:"network_connection",
        src_ip:"192.2.42.182",
        dst_ip:$dst_ip,
        dst_port:4444,
        user:"unknown",
        group_key:$dst_ip,
        source:"adversary-emulation"
      }'
  )"
  nats --server "$NATS_URL" pub rsiem.events.raw "$payload" >/dev/null
  printf '["evt.emu.t1071_001.%s"]\n' "$now_ms"
}

publish_scenario() {
  local scenario_id="$1"
  case "$scenario_id" in
    t1110_auth_abuse_burst) scenario_publish_t1110_auth_abuse_burst ;;
    t1046_first_seen_process) scenario_publish_t1046_first_seen_process ;;
    t1071_004_dns_suspicious) scenario_publish_t1071_004_dns_suspicious ;;
    t1565_001_sensitive_file_change) scenario_publish_t1565_001_sensitive_file_change ;;
    t1071_001_first_seen_risky_destination) scenario_publish_t1071_001_first_seen_risky_destination ;;
    *)
      echo "FAIL: unknown scenario publisher: ${scenario_id}" >&2
      return 1
      ;;
  esac
}

write_scenario_artifact() {
  local output_path="$1"
  local scenario_meta="$2"
  local event_ids_json="$3"
  local detector_matched="$4"
  local run_created="$5"
  local observed_run_json="$6"
  local artifact_json="$7"

  local expected_rule_id expected_playbook_id expected_status artifact_kind
  expected_rule_id="$(jq -r '.expected_rule_id' <<<"$scenario_meta")"
  expected_playbook_id="$(jq -r '.expected_playbook_id' <<<"$scenario_meta")"
  expected_status="$(jq -r '.expected_terminal_status' <<<"$scenario_meta")"
  artifact_kind="$(jq -r '.artifact_kind' <<<"$scenario_meta")"

  local observed_rule_id observed_playbook_id observed_status run_id
  observed_rule_id="$(jq -r '.rule_id // empty' <<<"$observed_run_json")"
  observed_playbook_id="$(jq -r '.playbook_id // empty' <<<"$observed_run_json")"
  observed_status="$(jq -r '.status // empty' <<<"$observed_run_json")"
  run_id="$(jq -r '.run_id // empty' <<<"$observed_run_json")"

  local check_detector check_run check_playbook check_status check_artifact total passed percent
  check_detector=false
  check_run=false
  check_playbook=false
  check_status=false
  check_artifact=false
  [[ "$detector_matched" == "true" ]] && check_detector=true
  [[ "$run_created" == "true" ]] && check_run=true
  [[ -n "$run_id" && "$observed_playbook_id" == "$expected_playbook_id" && "$observed_rule_id" == "$expected_rule_id" ]] && check_playbook=true
  [[ "$observed_status" == "$expected_status" ]] && check_status=true
  if [[ "$artifact_kind" == "none" ]]; then
    check_artifact=true
  else
    [[ "$(jq -r '.present // false' <<<"$artifact_json")" == "true" ]] && check_artifact=true
  fi

  total=5
  passed=0
  [[ "$check_detector" == true ]] && passed=$((passed + 1))
  [[ "$check_run" == true ]] && passed=$((passed + 1))
  [[ "$check_playbook" == true ]] && passed=$((passed + 1))
  [[ "$check_status" == true ]] && passed=$((passed + 1))
  [[ "$check_artifact" == true ]] && passed=$((passed + 1))
  percent=$(( passed * 100 / total ))

  jq -n \
    --argjson scenario "$scenario_meta" \
    --argjson event_ids "$event_ids_json" \
    --argjson observed_run "$observed_run_json" \
    --argjson artifact "$artifact_json" \
    --arg detector_matched "$detector_matched" \
    --arg run_created "$run_created" \
    --argjson checks "$(jq -n \
      --argjson detector "$check_detector" \
      --argjson run "$check_run" \
      --argjson playbook "$check_playbook" \
      --argjson status "$check_status" \
      --argjson artifact "$check_artifact" \
      '{detector_match:$detector, run_created:$run, expected_mapping:$playbook, terminal_status:$status, artifact_present:$artifact}')" \
    --argjson score "$(jq -n --argjson passed "$passed" --argjson total "$total" --argjson percent "$percent" '{passed:$passed,total:$total,percent:$percent}')" \
    --arg ui_base_url "$UI_BASE_URL" \
    '{
      generated_at: (now | todateiso8601),
      scenario: $scenario,
      event_ids: $event_ids,
      observed_run: ($observed_run + {ui_url: ($ui_base_url + "/incidents/" + ($observed_run.run_id // ""))}),
      artifact: $artifact,
      checks: $checks,
      score: $score,
      pass: (($score.passed == $score.total))
    }' >"$output_path"
}

run_scenario() {
  local scenario_meta="$1"
  local scenario_id expected_rule_id auto_approve artifact_kind expected_status
  scenario_id="$(jq -r '.id' <<<"$scenario_meta")"
  expected_rule_id="$(jq -r '.expected_rule_id' <<<"$scenario_meta")"
  auto_approve="$(jq -r '.auto_approve' <<<"$scenario_meta")"
  artifact_kind="$(jq -r '.artifact_kind' <<<"$scenario_meta")"
  expected_status="$(jq -r '.expected_terminal_status' <<<"$scenario_meta")"

  local before_master before_detector before_worker
  before_master="$(line_count "$ROOT_DIR/logs/master-roe.log")"
  before_detector="$(line_count "$ROOT_DIR/logs/detector.log")"
  before_worker="$(line_count "$ROOT_DIR/logs/worker.log")"

  echo "SCENARIO=${scenario_id}"
  local event_ids_json
  event_ids_json="$(publish_scenario "$scenario_id")"
  sleep 2

  local detector_matched="false"
  if new_lines "$ROOT_DIR/logs/detector.log" "$before_detector" | rg -q "\"rule_id\":\"${expected_rule_id}\""; then
    detector_matched="true"
  fi

  local run_id=""
  run_id="$(new_lines "$ROOT_DIR/logs/master-roe.log" "$before_master" | rg "\"msg\":\"response_run_created\".*\"rule_id\":\"${expected_rule_id}\"" | extract_run_id || true)"
  local run_created="false"
  [[ -n "$run_id" ]] && run_created="true"

  if [[ -n "$run_id" && "$auto_approve" == "true" ]]; then
    if new_lines "$ROOT_DIR/logs/master-roe.log" "$before_master" | rg -q "\"msg\":\"response_run_waiting_approval\".*\"run_id\":\"${run_id}\""; then
      approve_run "$run_id"
      sleep 6
    else
      sleep 4
    fi
  else
    sleep 4
  fi

  local observed_run_json="{}"
  if [[ -n "$run_id" ]]; then
    local final_run_line
    final_run_line="$(wait_for_run_json "$run_id" 20 1 || true)"
    if [[ -n "$final_run_line" ]]; then
      observed_run_json="$final_run_line"
    else
      observed_run_json="$(jq -n --arg run_id "$run_id" --arg status "UNKNOWN" '{run_id:$run_id,status:$status}')"
    fi
  fi

  local artifact_json
  artifact_json="$(check_artifact "$artifact_kind" "$run_id")"

  local artifact_file="$ARTIFACTS_DIR/${scenario_id}.json"
  write_scenario_artifact "$artifact_file" "$scenario_meta" "$event_ids_json" "$detector_matched" "$run_created" "$observed_run_json" "$artifact_json"

  local pass
  pass="$(jq -r '.pass' "$artifact_file")"
  local observed_status
  observed_status="$(jq -r '.observed_run.status // empty' "$artifact_file")"
  echo "RUN_ID=${run_id:-}"
  echo "EXPECTED_STATUS=${expected_status}"
  echo "OBSERVED_STATUS=${observed_status:-}"
  echo "ARTIFACT=${artifact_file}"

  if [[ "$pass" != "true" ]]; then
    echo "FAIL: scenario ${scenario_id} did not meet expected checks" >&2
    return 1
  fi
  return 0
}

if [[ $SKIP_CLEAN_START -eq 0 ]]; then
  echo "[1/4] Clean-starting stack"
  "$ROOT_DIR/scripts/demo_local_endpoint_clean_start.sh" >"$ARTIFACTS_DIR/clean_start.log"
  tail -n 10 "$ARTIFACTS_DIR/clean_start.log" || true
else
  echo "[1/4] Skipping clean start"
fi

echo "[2/4] Loading scenario catalog"
if [[ "$SCENARIO_SELECTION" == "all" ]]; then
  mapfile -t SCENARIO_IDS < <(jq -r '.scenarios[].id' "$CATALOG_PATH")
else
  mapfile -t SCENARIO_IDS < <(jq -r --arg id "$SCENARIO_SELECTION" '.scenarios[] | select(.id == $id) | .id' "$CATALOG_PATH")
  if [[ ${#SCENARIO_IDS[@]} -eq 0 ]]; then
    echo "FAIL: scenario not found in catalog: ${SCENARIO_SELECTION}" >&2
    exit 1
  fi
fi

declare -a RESULT_FILES=()
failures=0

echo "[3/4] Executing scenarios"
for scenario_id in "${SCENARIO_IDS[@]}"; do
  scenario_meta="$(jq -c --arg id "$scenario_id" '.scenarios[] | select(.id == $id)' "$CATALOG_PATH")"
  if run_scenario "$scenario_meta"; then
    :
  else
    failures=$((failures + 1))
    if [[ $KEEP_GOING -ne 1 ]]; then
      break
    fi
  fi
  RESULT_FILES+=("$ARTIFACTS_DIR/${scenario_id}.json")
done

echo "[4/4] Writing summary"
jq -n \
  --arg catalog_path "$CATALOG_PATH" \
  --arg artifacts_dir "$ARTIFACTS_DIR" \
  --arg ui_base_url "$UI_BASE_URL" \
  --arg nats_url "$NATS_URL" \
  --argjson scenarios "$(jq -s '.' "${RESULT_FILES[@]}")" \
  '{
    generated_at: (now | todateiso8601),
    catalog_path: $catalog_path,
    artifacts_dir: $artifacts_dir,
    ui_base_url: $ui_base_url,
    nats_url: $nats_url,
    scenarios: $scenarios,
    totals: {
      count: ($scenarios | length),
      passed: ($scenarios | map(select(.pass == true)) | length),
      failed: ($scenarios | map(select(.pass != true)) | length)
    }
  }' >"$ARTIFACTS_DIR/summary.json"

SUMMARY_STATUS="PASS"
if [[ $failures -ne 0 ]]; then
  SUMMARY_STATUS="FAIL"
fi

echo "ARTIFACTS_DIR=$ARTIFACTS_DIR"
echo "SUMMARY_JSON=$ARTIFACTS_DIR/summary.json"
jq -r '.totals | "SCENARIOS=\(.count) PASSED=\(.passed) FAILED=\(.failed)"' "$ARTIFACTS_DIR/summary.json"

if [[ "$SUMMARY_STATUS" != "PASS" ]]; then
  exit 1
fi

echo "PASS: adversary emulation harness completed"
