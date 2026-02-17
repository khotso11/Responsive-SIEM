#!/usr/bin/env bash
set -euo pipefail

LOG_MASTER="logs/master-roe.log"
LOG_WORKER="logs/roe-worker.log"
NOTIFY_EXPORT="exports/notify.jsonl"
WEBHOOK_RECV="exports/m56_webhook_received.jsonl"
DEMO_LOG="tmp/demo.log"
WEBHOOK_PORT=9999
WEBHOOK_URL="http://127.0.0.1:9999/"

mkdir -p logs exports tmp
touch "$WEBHOOK_RECV"

line_count() {
  local f="$1"
  [[ -f "$f" ]] || { echo 0; return; }
  wc -l < "$f" | tr -d ' '
}

tail_from() {
  local f="$1" base="$2"
  tail -n +"$((base + 1))" "$f" 2>/dev/null || true
}

wait_match() {
  local file="$1" base="$2" pattern="$3" timeout="$4"
  local i=0
  while (( i < timeout )); do
    local line
    line="$(tail_from "$file" "$base" | rg "$pattern" | head -n 1 || true)"
    if [[ -n "$line" ]]; then
      echo "$line"
      return 0
    fi
    sleep 1
    i=$((i + 1))
  done
  return 1
}

debug_fail() {
  local run_id="$1"
  echo "Context: master (last 120 relevant):" >&2
  rg "\"run_id\":\"${run_id}\"|response_run_created|response_step_published" "$LOG_MASTER" | tail -n 120 >&2 || true
  echo "Context: worker (last 120 relevant):" >&2
  rg "\"run_id\":\"${run_id}\"|notify_webhook|notify_file_written|notify_noop_missing_webhook|step_succeeded|step_failed_" "$LOG_WORKER" | tail -n 120 >&2 || true
  echo "Context: webhook recv (last 80):" >&2
  tail -n 80 "$WEBHOOK_RECV" >&2 || true
  echo "Context: notify export (last 80):" >&2
  tail -n 80 "$NOTIFY_EXPORT" >&2 || true
}

die() {
  local msg="$1"
  local run_id="${2:-}"
  echo "FAIL: $msg"
  [[ -n "$run_id" ]] && debug_fail "$run_id"
  exit 1
}

echo "=== M56 notify webhook proof ==="
echo "INFO: Ensure your active worker process was started with:"
echo "INFO: RSIEM_NOTIFY_WEBHOOK_URL=${WEBHOOK_URL}"

[[ -s "$LOG_MASTER" ]] || die "missing or empty $LOG_MASTER"
[[ -s "$LOG_WORKER" ]] || die "missing or empty $LOG_WORKER"
[[ -f "$NOTIFY_EXPORT" ]] || touch "$NOTIFY_EXPORT"
[[ -f "$DEMO_LOG" ]] || touch "$DEMO_LOG"

WEBHOOK_PID=""
cleanup() {
  if [[ -n "$WEBHOOK_PID" ]] && kill -0 "$WEBHOOK_PID" 2>/dev/null; then
    kill "$WEBHOOK_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

WEBHOOK_RECV="$WEBHOOK_RECV" WEBHOOK_PORT="$WEBHOOK_PORT" python3 - <<'PY' &
import json
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timezone

recv_path = os.environ["WEBHOOK_RECV"]
port = int(os.environ["WEBHOOK_PORT"])

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(n).decode("utf-8", errors="replace")
        run_id = ""
        step_id = ""
        try:
            payload = json.loads(raw)
            if isinstance(payload, dict):
                run_id = str(payload.get("run_id", ""))
                step_id = str(payload.get("step_id", ""))
        except Exception:
            pass
        rec = {
            "time": datetime.now(timezone.utc).isoformat(),
            "path": self.path,
            "run_id": run_id,
            "step_id": step_id,
            "body": raw,
        }
        os.makedirs(os.path.dirname(recv_path) or ".", exist_ok=True)
        with open(recv_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=True) + "\n")
            f.flush()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        return

HTTPServer(("127.0.0.1", port), Handler).serve_forever()
PY
WEBHOOK_PID="$!"
sleep 1
kill -0 "$WEBHOOK_PID" 2>/dev/null || die "failed to start local webhook server on 127.0.0.1:${WEBHOOK_PORT}"

base_master="$(line_count "$LOG_MASTER")"
base_worker="$(line_count "$LOG_WORKER")"
base_notify="$(line_count "$NOTIFY_EXPORT")"
base_webhook="$(line_count "$WEBHOOK_RECV")"

NOW="$(date +%s)"
echo "M56 process count host=m56-${NOW} ts=${NOW} process_count=3" >> "$DEMO_LOG"

run_line="$(wait_match "$LOG_MASTER" "$base_master" "\"msg\":\"response_run_created\".*\"rule_id\":\"R-COUNT-PROCESS-HOST\".*\"playbook_id\":\"PB-COUNT-PROCESS-HOST\"" 60 || true)"
[[ -n "$run_line" ]] || die "timeout waiting for response_run_created for process-count run"
RUN_ID="$(printf "%s\n" "$run_line" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')"
[[ -n "$RUN_ID" ]] || die "unable to parse run_id"

i=0
webhook_hits=0
notify_file_written_count=0
notify_artifact_count=0
while (( i < 15 )); do
  webhook_hits="$(tail_from "$WEBHOOK_RECV" "$base_webhook" | rg -c "\"run_id\":\"${RUN_ID}\"" || true)"
  notify_file_written_count="$(tail_from "$LOG_WORKER" "$base_worker" | rg -c "\"msg\":\"notify_file_written\".*\"run_id\":\"${RUN_ID}\"" || true)"
  notify_artifact_count="$(tail_from "$NOTIFY_EXPORT" "$base_notify" | rg -c "\"run_id\":\"${RUN_ID}\"" || true)"
  if (( webhook_hits >= 2 && (notify_file_written_count >= 2 || notify_artifact_count >= 2) )); then
    break
  fi
  sleep 1
  i=$((i + 1))
done

noop_count="$(tail_from "$LOG_WORKER" "$base_worker" | rg -c "\"msg\":\"notify_noop_missing_webhook\".*\"run_id\":\"${RUN_ID}\"" || true)"
if (( noop_count > 0 )); then
  die "notify_noop_missing_webhook seen for run_id=$RUN_ID (worker likely not started with RSIEM_NOTIFY_WEBHOOK_URL=$WEBHOOK_URL)" "$RUN_ID"
fi

(( webhook_hits >= 2 )) || die "expected >=2 webhook POSTs for run_id=$RUN_ID, got ${webhook_hits}" "$RUN_ID"
if (( notify_file_written_count < 2 && notify_artifact_count < 2 )); then
  die "missing notify artifact evidence for both notify steps run_id=$RUN_ID" "$RUN_ID"
fi

echo "$run_line"
echo "Webhook matches for run_id=${RUN_ID}:"
tail_from "$WEBHOOK_RECV" "$base_webhook" | rg "\"run_id\":\"${RUN_ID}\"" | tail -n 10 || true
echo "Counts: webhook_hits=${webhook_hits} notify_file_written=${notify_file_written_count} notify_artifact_rows=${notify_artifact_count}"
echo "PASS: M56 notify webhook proof run_id=${RUN_ID}"
exit 0
