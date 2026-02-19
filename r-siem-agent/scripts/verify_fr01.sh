#!/usr/bin/env bash
set -euo pipefail

cd ~/projects/r-siem-agent

on_error() {
  echo "FAIL: verify_fr01.sh failed" >&2
  ./scripts/demo_down.sh >/dev/null 2>&1 || true
}
trap on_error ERR

run_filtered() {
  "$@" 2> >(cat >&2) | awk '
    BEGIN { skip=0 }
    /^=== DEMO GUIDE ===$/ { skip=1; next }
    skip==1 {
      if ($0 ~ /^Stop everything started by this script:$/) { skip=2; next }
      next
    }
    skip==2 { skip=0; next }
    { print }
  '
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

checkpoint_offset() {
  local raw="${1:-}"
  local off
  off="$(printf '%s\n' "$raw" | sed -n 's/.*"offset":[[:space:]]*\([0-9]\+\).*/\1/p' | head -n 1)"
  if [[ -z "$off" ]]; then
    off=0
  fi
  printf '%s' "$off"
}

echo "=== FR-01 verification ==="

# 0) clean-ish runtime state
pkill -f 'cmd/collector-tail|/collector-tail' || true
pkill -f 'cmd/detector-v0|/detector-v0' || true
pkill -f 'cmd/master-roe-worker|/master-roe-worker' || true
pkill -f 'cmd/agent|/agent' || true
pkill -f 'cmd/master-roe([^[:alnum:]_-]|$)|/master-roe([^[:alnum:]_-]|$)' || true
sleep 1

echo "[1/4] tests"
GOCACHE="$(pwd)/.cache/go-build" go test ./internal/collector/tail ./cmd/collector-tail ./cmd/detector-v0

echo "[2/4] start stack"
run_filtered ./scripts/demo_up.sh

echo "[3/4] FR05 regression"
fr05_out="$(run_filtered ./scripts/demo_fr05.sh)"
printf '%s\n' "$fr05_out"

fr05_status="FAIL"
fr05_run_id_ok=""
fr05_run_id_fail=""
fr05_lane=""
if printf '%s\n' "$fr05_out" | rg -q '^PASS: FR05 completed \(safety \+ rollback \+ audit\)'; then
  fr05_status="PASS"
  fr05_run_id_ok="$(printf '%s\n' "$fr05_out" | sed -n 's/^PASS: FR05 completed (safety + rollback + audit) run_id_ok=\([^ ]*\) run_id_fail=\([^ ]*\)$/\1/p' | tail -n 1)"
  fr05_run_id_fail="$(printf '%s\n' "$fr05_out" | sed -n 's/^PASS: FR05 completed (safety + rollback + audit) run_id_ok=\([^ ]*\) run_id_fail=\([^ ]*\)$/\2/p' | tail -n 1)"
  fr05_lane="FAST"
fi

echo "[4/4] checkpoint + auth.log proof"

# checkpoint proof
collector_before_count="$(rg -c '"msg":"collector_event_published"' logs/collector.log || true)"
detector_before_count="$(rg -c '"msg":"detector_rule_matched"' logs/detector.log || true)"
base_ckpt="$(cat tmp/tail.checkpoint.json 2>/dev/null || echo '{"offset":0}')"
NOW="$(date +%s)"
SRC_IP="10.0.9.$(( (NOW % 180) + 20 ))"
echo "FAILED login user=khotso src=${SRC_IP} ts=${NOW}" >> tmp/demo.log

for _ in $(seq 1 10); do
  collector_after_count="$(rg -c '"msg":"collector_event_published"' logs/collector.log || true)"
  if [[ $collector_after_count -eq $((collector_before_count + 1)) ]]; then
    break
  fi
  sleep 1
done

collector_after_count="$(rg -c '"msg":"collector_event_published"' logs/collector.log || true)"
if [[ $collector_after_count -ne $((collector_before_count + 1)) ]]; then
  echo "FAIL: timeout waiting for exactly one additional collector_event_published" >&2
  exit 1
fi
detector_after_count="$(rg -c '"msg":"detector_rule_matched"' logs/detector.log || true)"
if (( detector_after_count < detector_before_count )); then
  detector_after_count="$detector_before_count"
fi

mid_ckpt="$(cat tmp/tail.checkpoint.json 2>/dev/null || echo '{"offset":0}')"

pkill -f 'cmd/collector-tail|/collector-tail' || true
sleep 1
run_filtered ./scripts/demo_up.sh >/tmp/fr01_demo_up_resume.out
for _ in $(seq 1 10); do
  resume_line="$(rg '"msg":"collector_tail_checkpoint_state".*"resumed_from_checkpoint":true' logs/collector.log | tail -n 1 || true)"
  [[ -n "$resume_line" ]] && break
  sleep 1
done

[[ -n "$resume_line" ]] || { echo "FAIL: no checkpoint state log after restart"; exit 1; }

# auth.log override proof: restart only collector-tail
pkill -f 'cmd/collector-tail|/collector-tail' || true
sleep 1
RSIEM_COLLECTOR_TAIL_PATH=/var/log/auth.log timeout 6s \
  go run -mod=vendor ./cmd/collector-tail --config configs/collector.yaml \
  > logs/collector-auth.log 2>&1 || test $? -eq 124

auth_override_line="$(rg '"msg":"collector_tail_input_path_resolved".*"source":"env_override"' logs/collector-auth.log | tail -n 1 || true)"
[[ -n "$auth_override_line" ]] || { echo "FAIL: no auth.log override resolution log found"; exit 1; }

# restore default collector-tail so the stack is not left degraded
run_filtered ./scripts/demo_up.sh >/tmp/fr01_demo_up_post_auth.out
collector_default_line="$(rg '"msg":"collector_tail_input_path_resolved"' logs/collector.log | tail -n 1 || true)"
collector_path_used="$(printf '%s\n' "$collector_default_line" | sed -n 's/.*"path":"\([^"]*\)".*/\1/p' | tail -n 1)"
[[ -n "$collector_path_used" ]] || collector_path_used="tmp/demo.log"
auth_override_path="$(printf '%s\n' "$auth_override_line" | sed -n 's/.*"path":"\([^"]*\)".*/\1/p' | tail -n 1)"

checkpoint_before_offset="$(checkpoint_offset "$base_ckpt")"
checkpoint_after_offset="$(checkpoint_offset "$mid_ckpt")"
published_delta=$((collector_after_count - collector_before_count))
detector_delta=$((detector_after_count - detector_before_count))

artifact_ts="$(date +%Y%m%d_%H%M%S)"
artifact_dir="demo_artifacts/${artifact_ts}"
summary_json="${artifact_dir}/demo_summary.json"
mkdir -p "$artifact_dir"
generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
host_name="$(hostname)"

cat > "$summary_json" <<EOF
{
  "generated_at": "$(json_escape "$generated_at")",
  "hostname": "$(json_escape "$host_name")",
  "fr01": {
    "status": "PASS",
    "collector_path": "$(json_escape "$collector_path_used")",
    "checkpoint_before": ${checkpoint_before_offset},
    "checkpoint_after": ${checkpoint_after_offset},
    "published_before": ${collector_before_count},
    "published_after": ${collector_after_count},
    "published_delta": ${published_delta},
    "evidence": {
      "collector_log": "logs/collector.log",
      "detector_log": "logs/detector.log",
      "master_log": "logs/master-roe.log",
      "proof_commands": [
        "rg collector_tail_checkpoint_state logs/collector.log | tail -n 1",
        "rg collector_event_published logs/collector.log | tail -n 5",
        "cat tmp/tail.checkpoint.json",
        "rg collector_tail_input_path_resolved logs/collector-auth.log | tail -n 1"
      ]
    }
  },
  "fr05": {
    "status": "${fr05_status}",
    "run_id_ok": $(json_or_null "$fr05_run_id_ok"),
    "run_id_fail": $(json_or_null "$fr05_run_id_fail"),
    "lane": $(json_or_null "$fr05_lane"),
    "evidence": {
      "proof_commands": [
        "rg PB-QUARANTINE-ROLLBACK-DEMO logs/master-roe.log | tail -n 20",
        "rg response_run_updated logs/master-roe.log | tail -n 20",
        "rg quarantine_move logs/agent.log | tail -n 10",
        "rg quarantine_restore logs/agent.log | tail -n 10"
      ]
    }
  }
}
EOF

trap - ERR
echo "=== FR-01 SUMMARY ==="
echo "input_source_used=${collector_path_used}"
echo "checkpoint_before=${checkpoint_before_offset}"
echo "checkpoint_after=${checkpoint_after_offset}"
echo "events_published_delta=${published_delta}"
echo "detector_rule_matches_delta=${detector_delta}"
echo "fr01_status=PASS"
echo "fr05_status=${fr05_status}"
echo "PASS: FR-01 local verification completed"
echo "PROOF_CHECKPOINT: checkpoint_before=${base_ckpt} checkpoint_after=${mid_ckpt} resume_log=${resume_line}"
echo "PROOF_AUTHLOG_OVERRIDE: ${auth_override_line}"
echo "DEMO_SUMMARY_JSON: ${summary_json}"
