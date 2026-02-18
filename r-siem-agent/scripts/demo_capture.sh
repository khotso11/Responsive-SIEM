#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

ARTIFACT_BASE="demo_artifacts"
MASTER_LOG="logs/master-roe.log"

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

extract_run_id() {
  local log_file="$1"
  [[ -f "$log_file" ]] || return 0
  local line
  line="$(grep -F '"msg":"response_run_created"' "$log_file" | tail -n 1 || true)"
  [[ -n "$line" ]] || return 0
  printf '%s\n' "$line" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p' | head -n 1
}

extract_step_line_for_run() {
  local log_file="$1" run_id="$2"
  [[ -f "$log_file" ]] || return 0
  if [[ -n "$run_id" ]]; then
    grep -F '"msg":"response_step_published"' "$log_file" | grep -F "\"run_id\":\"${run_id}\"" | tail -n 1 || true
  else
    grep -F '"msg":"response_step_published"' "$log_file" | tail -n 1 || true
  fi
}

extract_step_id_from_line() {
  local line="$1"
  printf '%s\n' "$line" | sed -n 's/.*"step_id":"\([^"]*\)".*/\1/p' | head -n 1
}

extract_lane_from_line() {
  local line="$1"
  if printf '%s\n' "$line" | grep -F '"step_subject":"' | grep -F '.fast"' >/dev/null 2>&1; then
    echo "FAST"
  elif printf '%s\n' "$line" | grep -F '"step_subject":"' | grep -F '.standard"' >/dev/null 2>&1; then
    echo "STANDARD"
  else
    echo "UNKNOWN"
  fi
}

extract_outcome() {
  local log_file="$1" run_id="$2" step_id="$3"
  [[ -f "$log_file" ]] || { echo "UNKNOWN"; return 0; }
  local lines
  lines="$(grep -F '"msg":"response_step_result_received"' "$log_file" || true)"
  [[ -n "$run_id" ]] && lines="$(printf '%s\n' "$lines" | grep -F "\"run_id\":\"${run_id}\"" || true)"
  [[ -n "$step_id" ]] && lines="$(printf '%s\n' "$lines" | grep -F "\"step_id\":\"${step_id}\"" || true)"
  if printf '%s\n' "$lines" | grep -F '"status":"SUCCEEDED"' >/dev/null 2>&1; then
    echo "SUCCEEDED"
  else
    echo "UNKNOWN"
  fi
}

unique_artifact_dir() {
  local base_ts="$1"
  local dir="${ARTIFACT_BASE}/${base_ts}"
  if [[ ! -e "$dir" ]]; then
    printf '%s\n' "$dir"
    return 0
  fi
  local i=1
  while :; do
    dir="${ARTIFACT_BASE}/${base_ts}_${i}"
    if [[ ! -e "$dir" ]]; then
      printf '%s\n' "$dir"
      return 0
    fi
    i=$((i + 1))
  done
}

mkdir -p "$ARTIFACT_BASE"
ts_dir="$(date +%Y%m%d_%H%M%S)"
artifact_dir="$(unique_artifact_dir "$ts_dir")"
logs_dir="${artifact_dir}/demo_logs"
exports_dir="${artifact_dir}/exports"
mkdir -p "$logs_dir"

# Copy canonical logs if present.
for f in logs/master-roe.log logs/worker.log logs/agent.log logs/detector.log logs/collector.log; do
  [[ -f "$f" ]] && cp -f "$f" "$logs_dir/"
done

# Copy any logs/*.log if present.
if [[ -d logs ]]; then
  for f in logs/*.log; do
    [[ -f "$f" ]] || continue
    cp -f "$f" "$logs_dir/"
  done
fi

# Copy exports/* if present.
if [[ -d exports ]]; then
  mkdir -p "$exports_dir"
  for f in exports/*; do
    [[ -e "$f" ]] || continue
    cp -Rf "$f" "$exports_dir/"
  done
fi

captured_at_unix="$(date +%s)"
captured_at_rfc3339="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

git_commit="unknown"
if command -v git >/dev/null 2>&1; then
  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
fi

run_id="${RUN_ID:-${1:-}}"
if [[ -z "$run_id" ]]; then
  run_id="$(extract_run_id "$MASTER_LOG")"
fi

step_line="$(extract_step_line_for_run "$MASTER_LOG" "$run_id")"
step_id=""
lane="UNKNOWN"
if [[ -n "$step_line" ]]; then
  step_id="$(extract_step_id_from_line "$step_line")"
  lane="$(extract_lane_from_line "$step_line")"
fi

outcome="$(extract_outcome "$MASTER_LOG" "$run_id" "$step_id")"

cat > "${artifact_dir}/demo_summary.json" <<EOF
{
  "captured_at_unix": ${captured_at_unix},
  "captured_at_rfc3339": "$(json_escape "$captured_at_rfc3339")",
  "git_commit": "$(json_escape "$git_commit")",
  "run_id": "$(json_escape "$run_id")",
  "step_id": "$(json_escape "$step_id")",
  "outcome": "$(json_escape "$outcome")",
  "lane": "$(json_escape "$lane")"
}
EOF

echo "ARTIFACT_DIR=${artifact_dir}"
echo "What to show:"
echo "  rg '\"msg\":\"collector_event_published\"' \"${artifact_dir}/demo_logs/collector.log\""
echo "  rg '\"msg\":\"detector_rule_matched\"' \"${artifact_dir}/demo_logs/detector.log\""
echo "  rg '\"msg\":\"response_run_created\"' \"${artifact_dir}/demo_logs/master-roe.log\""
echo "  rg '\"msg\":\"response_step_published\"' \"${artifact_dir}/demo_logs/master-roe.log\""
echo "  rg '\"msg\":\"step_received\"' \"${artifact_dir}/demo_logs/worker.log\""
echo "  rg '\"msg\":\"agent_command_exec_start\"' \"${artifact_dir}/demo_logs/agent.log\""
echo "  rg '\"msg\":\"response_step_result_received\".*\"status\":\"SUCCEEDED\"' \"${artifact_dir}/demo_logs/master-roe.log\""

exit 0
