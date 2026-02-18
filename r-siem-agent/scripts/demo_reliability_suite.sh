#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage: ./scripts/demo_reliability_suite.sh

Runs the demo reliability subset in order:
1) scripts/m63_worker_and_agent_down_combined_recovery_proof.sh
2) scripts/m66_worker_crash_after_step_succeeded_before_result_publish_proof.sh
3) scripts/m68_master_restart_mid_flight_no_missed_or_duplicate_results.sh

For each script:
- bash -n syntax check
- execute and tee output
- require its own PASS line
- print suite PASS/FAIL status
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

[[ -d scripts ]] || { echo "FAIL: run from repo root (missing scripts/ directory)"; exit 1; }

for tool in rg nats ps awk sed pkill kill go tee; do
  command -v "$tool" >/dev/null 2>&1 || { echo "FAIL: required command not found: $tool"; exit 1; }
done

AGENT_RE='((go[[:space:]]+run[^[:cntrl:]]*\./cmd/agent)|((cmd/agent|/agent)([^[:alnum:]_]|$))).*(-{1,2}config([=[:space:]])?configs/agent(2)?\.yaml)'
WORKER_RE='((go[[:space:]]+run[^[:cntrl:]]*\./cmd/master-roe-worker)|((cmd/master-roe-worker|/master-roe-worker)([^[:alnum:]_]|$))).*(-{1,2}config([=[:space:]])?configs/master\.yaml)'
MASTER_RE='((go[[:space:]]+run[^[:cntrl:]]*\./cmd/master-roe([^[:alnum:]_-]|$))|((cmd/master-roe|/master-roe)([^[:alnum:]_-]|$))).*(-{1,2}config([=[:space:]])?configs/master\.yaml)'
DETECTOR_RE='(go[[:space:]]+run[^[:cntrl:]]*\./cmd/detector-v0|(cmd/detector-v0|/detector-v0)([^[:alnum:]_]|$))'
COLLECTOR_RE='(go[[:space:]]+run[^[:cntrl:]]*\./cmd/collector-tail|(cmd/collector-tail|/collector-tail)([^[:alnum:]_]|$))'
TEE_RE='(^|[[:space:]])tee[[:space:]].*logs/(agent|worker|master-roe|detector|collector)([^[:alnum:]_]|$)'

SUITE_STARTED_AGENT=0
SUITE_STARTED_WORKER=0

declare -a TMP_FILES=()

line_count() { [[ -f "$1" ]] && wc -l < "$1" | tr -d ' ' || echo 0; }
tail_from() { tail -n "+$(( $2 + 1 ))" "$1" 2>/dev/null || true; }

ps_lines() {
  ps -eo pid=,args= | awk '
    {
      line=$0
      sub(/^[[:space:]]+/, "", line)
      if (line == "") next
      pid=line
      sub(/[[:space:]].*$/, "", pid)
      cmd=line
      sub(/^[0-9]+[[:space:]]+/, "", cmd)
      if (cmd ~ /(^|[[:space:]])(rg|grep|pgrep|awk|sed)([[:space:]]|$)/) next
      if (cmd ~ /demo_reliability_suite\.sh/) next
      print pid " " cmd
    }
  '
}

proc_lines() {
  local pattern="$1"
  ps_lines | rg -e "$pattern" || true
}

count_procs() {
  local pattern="$1"
  local c
  c="$(proc_lines "$pattern" | wc -l | tr -d '[:space:]')"
  [[ "$c" =~ ^[0-9]+$ ]] || c=0
  echo "$c"
}

kill_matching() {
  local pattern="$1"
  local sig="${2:-TERM}"
  local pids
  pids="$(proc_lines "$pattern" | awk '{print $1}' || true)"
  [[ -n "$pids" ]] || return 0
  while IFS= read -r pid; do
    [[ -n "$pid" ]] || continue
    kill -"$sig" "$pid" >/dev/null 2>&1 || true
  done <<< "$pids"
}

wait_down() {
  local pattern="$1"
  local timeout_s="${2:-20}"
  local start
  start="$(date +%s)"
  while :; do
    if [[ "$(count_procs "$pattern")" == "0" ]]; then
      return 0
    fi
    if (( "$(date +%s)" - start >= timeout_s )); then
      return 1
    fi
    sleep 0.2
  done
}

wait_up() {
  local pattern="$1"
  local timeout_s="${2:-20}"
  local start
  start="$(date +%s)"
  while :; do
    if (( "$(count_procs "$pattern")" > 0 )); then
      return 0
    fi
    if (( "$(date +%s)" - start >= timeout_s )); then
      return 1
    fi
    sleep 0.2
  done
}

require_up() {
  local label="$1"
  local pattern="$2"
  local c
  c="$(count_procs "$pattern")"
  (( c > 0 )) || { echo "FAIL: required process is not running: ${label}"; exit 1; }
}

require_down() {
  local label="$1"
  local pattern="$2"
  local c
  c="$(count_procs "$pattern")"
  (( c == 0 )) || {
    echo "FAIL: ${label} must be stopped before this milestone."
    proc_lines "$pattern" | awk '{print "  " $0}'
    exit 1
  }
}

stop_tee_helpers() {
  kill_matching "$TEE_RE" TERM
  sleep 0.2
  kill_matching "$TEE_RE" KILL
  wait_down "$TEE_RE" 5 || true
}

stop_agent_processes() {
  kill_matching "$AGENT_RE" TERM
  sleep 0.3
  kill_matching "$AGENT_RE" KILL
  stop_tee_helpers
  if ! wait_down "$AGENT_RE"; then
    echo "FAIL: unable to stop agent"
    proc_lines "$AGENT_RE" | awk '{print "  " $0}'
    exit 1
  fi
}

stop_worker_processes() {
  kill_matching "$WORKER_RE" TERM
  sleep 0.3
  kill_matching "$WORKER_RE" KILL
  stop_tee_helpers
  if ! wait_down "$WORKER_RE"; then
    echo "FAIL: unable to stop master-roe-worker"
    proc_lines "$WORKER_RE" | awk '{print "  " $0}'
    exit 1
  fi
}

stop_master_processes() {
  kill_matching "$MASTER_RE" TERM
  sleep 0.3
  kill_matching "$MASTER_RE" KILL
  stop_tee_helpers
  if ! wait_down "$MASTER_RE"; then
    echo "FAIL: unable to stop master-roe"
    proc_lines "$MASTER_RE" | awk '{print "  " $0}'
    exit 1
  fi
}

ensure_single_agent() {
  local c
  c="$(count_procs "$AGENT_RE")"
  [[ "$c" == "1" ]] || {
    echo "FAIL: expected exactly 1 active agent process, found ${c}"
    proc_lines "$AGENT_RE" | awk '{print "  " $0}'
    exit 1
  }
}

start_agent_if_needed() {
  if (( "$(count_procs "$AGENT_RE")" > 0 )); then
    ensure_single_agent
    return 0
  fi
  mkdir -p logs
  nohup go run -mod=vendor ./cmd/agent --config configs/agent.yaml >> logs/agent.log 2>&1 &
  SUITE_STARTED_AGENT=1
  if ! wait_up "$AGENT_RE" 30; then
    echo "FAIL: failed to start agent for suite"
    exit 1
  fi
  ensure_single_agent
}

start_worker_if_needed() {
  if (( "$(count_procs "$WORKER_RE")" > 0 )); then
    return 0
  fi
  mkdir -p logs
  nohup go run -mod=vendor ./cmd/master-roe-worker --config configs/master.yaml --lane BOTH >> logs/worker.log 2>&1 &
  SUITE_STARTED_WORKER=1
  if ! wait_up "$WORKER_RE" 30; then
    echo "FAIL: failed to start master-roe-worker for suite"
    exit 1
  fi
}

auto_start_worker_for_m63() {
  local out_file="$1"
  {
    local i=0
    while (( i < 300 )); do
      local action_line lane
      action_line="$(tail -n 80 "$out_file" 2>/dev/null | rg 'ACTION: start (FAST|STANDARD) worker now' | tail -n 1 || true)"
      if [[ -n "$action_line" ]]; then
        lane="FAST"
        if [[ "$action_line" == *"STANDARD"* ]]; then
          lane="STANDARD"
        fi
        if [[ "$(count_procs "$WORKER_RE")" == "0" ]]; then
          mkdir -p logs
          nohup go run -mod=vendor ./cmd/master-roe-worker --config configs/master.yaml -lane "$lane" >> "logs/worker-${lane,,}.log" 2>&1 &
          SUITE_STARTED_WORKER=1
        fi
        exit 0
      fi
      sleep 0.2
      i=$((i + 1))
    done
    exit 0
  } &
}

barrier_after_m63() {
  stop_worker_processes
  stop_agent_processes
}

barrier_after_m66() {
  stop_worker_processes
  stop_agent_processes
}

precheck_m63() {
  echo "Precheck M63: master/detector/collector up, worker down, agent down"
  require_up "master-roe" "$MASTER_RE"
  require_up "detector-v0" "$DETECTOR_RE"
  require_up "collector-tail" "$COLLECTOR_RE"
  stop_worker_processes
  stop_agent_processes
  require_down "master-roe-worker" "$WORKER_RE"
  require_down "agent" "$AGENT_RE"
}

precheck_m66() {
  echo "Precheck M66: master/detector/collector up, worker down, agent up"
  require_up "master-roe" "$MASTER_RE"
  require_up "detector-v0" "$DETECTOR_RE"
  require_up "collector-tail" "$COLLECTOR_RE"
  stop_worker_processes
  stop_agent_processes
  start_agent_if_needed
  require_down "master-roe-worker" "$WORKER_RE"
  require_up "agent" "$AGENT_RE"
}

precheck_m68() {
  echo "Precheck M68: detector/collector up, worker up, agent up, external master down"
  require_up "detector-v0" "$DETECTOR_RE"
  require_up "collector-tail" "$COLLECTOR_RE"
  stop_master_processes
  start_agent_if_needed
  start_worker_if_needed
  require_up "master-roe-worker" "$WORKER_RE"
  require_up "agent" "$AGENT_RE"
  require_down "master-roe" "$MASTER_RE"
}

cleanup() {
  local f
  for f in "${TMP_FILES[@]}"; do
    [[ -n "$f" && -f "$f" ]] && rm -f "$f"
  done
  stop_worker_processes || true
  stop_agent_processes || true
}
trap cleanup EXIT

run_milestone() {
  local code="$1"
  local desc="$2"
  local script="$3"

  [[ -f "$script" ]] || { echo "FAIL: missing script: $script"; exit 1; }
  bash -n "$script"

  local tmp_out
  tmp_out="$(mktemp)"
  TMP_FILES+=("$tmp_out")
  local rc=0

  if [[ "$code" == "M63" ]]; then
    local tmp_in
    tmp_in="$(mktemp)"
    TMP_FILES+=("$tmp_in")
    printf '\n' > "$tmp_in"
    auto_start_worker_for_m63 "$tmp_out"

    if [[ -x "$script" ]]; then
      set +e
      "$script" < "$tmp_in" \
        | tee "$tmp_out" \
        | sed -E 's/^ACTION: start .*worker now in another terminal:.*/INFO: worker auto-start handled by suite/'
      rc="${PIPESTATUS[0]}"
      set -e
    else
      set +e
      bash "$script" < "$tmp_in" \
        | tee "$tmp_out" \
        | sed -E 's/^ACTION: start .*worker now in another terminal:.*/INFO: worker auto-start handled by suite/'
      rc="${PIPESTATUS[0]}"
      set -e
    fi
  else
    if [[ -x "$script" ]]; then
      set +e
      "$script" | tee "$tmp_out"
      rc=$?
      set -e
    else
      set +e
      bash "$script" | tee "$tmp_out"
      rc=$?
      set -e
    fi
  fi

  if [[ "$rc" -ne 0 ]]; then
    echo "FAIL: ${code} failed (rc=${rc})"
    exit "$rc"
  fi

  local pass_line
  pass_line="$(rg '^PASS:' "$tmp_out" | tail -n 1 || true)"
  if [[ -z "$pass_line" ]]; then
    echo "FAIL: ${code} failed (rc=1)"
    exit 1
  fi

  echo "PASS: ${code} (${desc})"
  echo "$pass_line"
}

echo "=== DEMO RELIABILITY SUITE (M63 + M66 + M68) ==="
echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

precheck_m63
run_milestone "M63" "worker+agent combined recovery" "scripts/m63_worker_and_agent_down_combined_recovery_proof.sh"
barrier_after_m63

precheck_m66
run_milestone "M66" "worker crash before result publish recovery" "scripts/m66_worker_crash_after_step_succeeded_before_result_publish_proof.sh"
barrier_after_m66

precheck_m68
run_milestone "M68" "master restart mid-flight no missed/duplicate results" "scripts/m68_master_restart_mid_flight_no_missed_or_duplicate_results.sh"

echo "PASS: demo reliability suite completed"
exit 0
