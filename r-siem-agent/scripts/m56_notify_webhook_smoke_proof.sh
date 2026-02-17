#!/usr/bin/env bash
set -euo pipefail

LOG_COLLECTOR="logs/collector-tail.log"
LOG_DETECTOR="logs/detector-v0.log"
LOG_MASTER="logs/master-roe.log"
LOG_WORKER="logs/roe-worker.log"
NOTIFY_EXPORT="exports/notify.jsonl"
WEBHOOK_RECV="exports/m56_webhook_received.jsonl"
WEBHOOK_PORT=18080
WEBHOOK_PATH="/m56"
DEMO_LOG="tmp/demo.log"

require_log() {
  local file="$1"
  local label="$2"
  if [[ ! -s "$file" ]]; then
    echo "FAIL: missing or empty ${file}. Start ${label} first." >&2
    exit 2
  fi
}

line_count() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    echo 0
    return
  fi
  wc -l < "$file" | tr -d ' '
}

tail_from() {
  local file="$1"
  local base="$2"
  tail -n +"$((base + 1))" "$file" 2>/dev/null || true
}

wait_in_tail() {
  local pattern="$1"
  local file="$2"
  local baseline_count="$3"
  local max_wait="$4"
  local elapsed=0
  while (( elapsed < max_wait )); do
    local match
    match="$(tail_from "$file" "$baseline_count" | rg "$pattern" | head -n 1 || true)"
    if [[ -n "$match" ]]; then
      echo "$match"
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  return 1
}

debug_recent() {
  local pattern="$1"
  local file="$2"
  echo "Context: last 120 relevant lines from ${file}:" >&2
  rg "$pattern" "$file" | tail -n 120 >&2 || true
}

find_standard_worker_pids() {
  ps -eo pid=,args= | rg 'master-roe-worker' | rg '\-lane STANDARD' | awk '{print $1}' || true
}

echo "=== M56 notify webhook smoke proof ==="

require_log "$LOG_COLLECTOR" "Terminal H (collector-tail)"
require_log "$LOG_DETECTOR" "Terminal I (detector-v0)"
require_log "$LOG_MASTER" "Terminal E (master-roe)"
require_log "$LOG_WORKER" "Terminal F (roe-worker)"

mkdir -p tmp logs exports .cache/go-build
touch "$NOTIFY_EXPORT" "$WEBHOOK_RECV"

AUTO_STOPPED=0
AUTO_STARTED=0
STARTED_PID=""
WEBHOOK_PID=""

cleanup() {
  if [[ -n "$WEBHOOK_PID" ]] && kill -0 "$WEBHOOK_PID" 2>/dev/null; then
    kill "$WEBHOOK_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

python3 - <<'PY' &
import json
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timezone

path = os.environ.get("WEBHOOK_RECV", "exports/m56_webhook_received.jsonl")
port = int(os.environ.get("WEBHOOK_PORT", "18080"))

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('Content-Length', '0'))
        body = self.rfile.read(n).decode('utf-8', errors='replace')
        rec = {
            "time": datetime.now(timezone.utc).isoformat(),
            "path": self.path,
            "body": body,
            "content_type": self.headers.get('Content-Type', ''),
        }
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=True) + "\n")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")
    def log_message(self, format, *args):
        return

HTTPServer(("127.0.0.1", port), H).serve_forever()
PY
WEBHOOK_PID="$!"
sleep 1
if ! kill -0 "$WEBHOOK_PID" 2>/dev/null; then
  echo "FAIL: unable to start local webhook server on 127.0.0.1:${WEBHOOK_PORT}" >&2
  exit 1
fi

standard_pids="$(find_standard_worker_pids)"
if [[ -n "$standard_pids" ]]; then
  AUTO_STOPPED=1
  echo "Detected STANDARD worker process IDs: ${standard_pids}"
  echo "$standard_pids" | xargs -r kill
  sleep 1
  still_running="$(find_standard_worker_pids)"
  if [[ -n "$still_running" ]]; then
    echo "FAIL: unable to stop STANDARD worker PIDs: ${still_running}" >&2
    exit 1
  fi
else
  echo "No dedicated STANDARD worker process with '-lane STANDARD' detected."
  read -r -p "Ensure no other STANDARD-processing worker is active, then press Enter." _
fi

echo "Starting dedicated STANDARD worker with RSIEM_NOTIFY_WEBHOOK_URL=http://127.0.0.1:${WEBHOOK_PORT}${WEBHOOK_PATH}"
env GOCACHE="$(pwd)/.cache/go-build" RSIEM_NOTIFY_WEBHOOK_URL="http://127.0.0.1:${WEBHOOK_PORT}${WEBHOOK_PATH}" go run -mod=vendor ./cmd/master-roe-worker --config configs/master.yaml -lane STANDARD >> "$LOG_WORKER" 2>&1 &
STARTED_PID="$!"
AUTO_STARTED=1
sleep 1
if ! kill -0 "$STARTED_PID" 2>/dev/null; then
  AUTO_STARTED=0
  echo "FAIL: failed to start dedicated STANDARD worker with webhook URL env." >&2
  exit 1
fi

base_detector="$(line_count "$LOG_DETECTOR")"
base_master="$(line_count "$LOG_MASTER")"
base_worker="$(line_count "$LOG_WORKER")"
base_notify="$(line_count "$NOTIFY_EXPORT")"
base_webhook="$(line_count "$WEBHOOK_RECV")"

NOW="$(date +%s)"
HOST_ID="m56-${NOW}"
echo "M56 process count host=${HOST_ID} ts=${NOW} process_count=3" >> "$DEMO_LOG"

trigger_line="$(wait_in_tail "\"msg\":\"trigger_published\".*\"alert_key\":\"A-COUNT-PROCESS-HOST-" "$LOG_DETECTOR" "$base_detector" 60 || true)"
if [[ -z "$trigger_line" ]]; then
  echo "FAIL: timeout waiting for process-count trigger_published" >&2
  debug_recent '"msg":"rule_matched"|"msg":"trigger_published"' "$LOG_DETECTOR"
  exit 1
fi

run_line="$(wait_in_tail "\"msg\":\"response_run_created\".*\"rule_id\":\"R-COUNT-PROCESS-HOST\".*\"playbook_id\":\"PB-COUNT-PROCESS-HOST\"" "$LOG_MASTER" "$base_master" 60 || true)"
if [[ -z "$run_line" ]]; then
  echo "FAIL: timeout waiting for response_run_created for process-count run" >&2
  debug_recent '"msg":"response_run_created".*"R-COUNT-PROCESS-HOST"' "$LOG_MASTER"
  exit 1
fi
RUN_ID="$(printf "%s\n" "$run_line" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"
if [[ -z "$RUN_ID" ]]; then
  echo "FAIL: unable to extract run_id" >&2
  echo "$run_line" >&2
  exit 1
fi

elapsed=0
notify_written_count=0
notify_noop_count=0
webhook_run_posts=0
while (( elapsed < 60 )); do
  worker_slice="$(tail_from "$LOG_WORKER" "$base_worker")"
  notify_written_count="$(printf "%s\n" "$worker_slice" | rg -c "\"msg\":\"notify_file_written\".*\"run_id\":\"${RUN_ID}\"" || true)"
  notify_noop_count="$(printf "%s\n" "$worker_slice" | rg -c "\"msg\":\"notify_noop_missing_webhook\".*\"run_id\":\"${RUN_ID}\"" || true)"
  webhook_run_posts="$(tail_from "$WEBHOOK_RECV" "$base_webhook" | rg -c "\"body\":\".*\\\"run_id\\\":\\\"${RUN_ID}\\\"" || true)"
  if (( notify_written_count >= 2 )) && (( webhook_run_posts >= 1 )); then
    break
  fi
  sleep 1
  elapsed=$((elapsed + 1))
done

if (( notify_noop_count > 0 )); then
  echo "FAIL: notify_noop_missing_webhook observed for run_id=${RUN_ID}; expected real webhook delivery path." >&2
  debug_recent "\"msg\":\"notify_noop_missing_webhook\"|\"msg\":\"notify_webhook_attempt\"|\"msg\":\"notify_webhook_terminal\"|\"msg\":\"notify_file_written\"" "$LOG_WORKER"
  exit 1
fi

if (( notify_written_count < 2 )); then
  echo "FAIL: expected notify_file_written for both notify steps, got count=${notify_written_count}" >&2
  debug_recent "\"msg\":\"notify_webhook_attempt\"|\"msg\":\"notify_webhook_terminal\"|\"msg\":\"notify_file_written\"" "$LOG_WORKER"
  exit 1
fi

if (( webhook_run_posts < 1 )); then
  echo "FAIL: local webhook received no POSTs for run_id=${RUN_ID}" >&2
  tail_from "$WEBHOOK_RECV" "$base_webhook" | tail -n 40 >&2 || true
  debug_recent "\"msg\":\"notify_webhook_attempt\"|\"msg\":\"notify_webhook_terminal\"" "$LOG_WORKER"
  exit 1
fi

notify_slice="$(tail_from "$NOTIFY_EXPORT" "$base_notify" | rg "\"run_id\":\"${RUN_ID}\"" | rg '"\"action_type\":\"notify\"' || true)"
notify0_line="$(printf "%s\n" "$notify_slice" | rg '"\"step_index\":0' | head -n 1 || true)"
notify2_line="$(printf "%s\n" "$notify_slice" | rg '"\"step_index\":2' | head -n 1 || true)"
if [[ -z "$notify0_line" || -z "$notify2_line" ]]; then
  echo "FAIL: expected notify artifact rows (step_index 0 and 2) for run_id=${RUN_ID}" >&2
  printf "%s\n" "$notify_slice" | tail -n 40 >&2
  exit 1
fi

echo "$trigger_line"
echo "$run_line"
echo "$notify0_line"
echo "$notify2_line"
echo "PASS: M56 notify webhook smoke proof run_id=${RUN_ID} notify_file_written_count=${notify_written_count} webhook_posts_for_run=${webhook_run_posts}"

if [[ "$AUTO_STARTED" == "1" ]]; then
  echo "INFO: standard worker started with pid=${STARTED_PID}"
fi
