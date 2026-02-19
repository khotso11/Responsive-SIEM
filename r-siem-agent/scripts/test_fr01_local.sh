#!/usr/bin/env bash
set -euo pipefail

cd ~/projects/r-siem-agent

echo "=== FR-01 local verification ==="

# 0) clean-ish runtime state
pkill -f 'cmd/collector-tail|/collector-tail' || true
pkill -f 'cmd/detector-v0|/detector-v0' || true
pkill -f 'cmd/master-roe-worker|/master-roe-worker' || true
pkill -f 'cmd/agent|/agent' || true
pkill -f 'cmd/master-roe([^[:alnum:]_-]|$)|/master-roe([^[:alnum:]_-]|$)' || true
sleep 1

# 1) unit tests
echo "[1/5] running collector parser tests"
GOCACHE="$(pwd)/.cache/go-build" go test ./internal/collector/tail ./cmd/collector-tail ./cmd/detector-v0

# 2) start stack default mode + run known demo flow
echo "[2/5] starting default demo stack"
./scripts/demo_up.sh

echo "[3/5] running default FR05 demo (regression check)"
./scripts/demo_fr05.sh
echo "default_demo_rc=$?"

# 3) checkpoint/resume proof for collector-tail
echo "[4/5] checkpoint/resume proof"
base_pub="$(rg -c '"msg":"collector_event_published"' logs/collector.log || true)"
base_ckpt="$(cat tmp/tail.checkpoint.json 2>/dev/null || echo '{"offset":0}')"

NOW="$(date +%s)"
echo "FAILED login user=khotso src=10.0.9.9 ts=${NOW}" >> tmp/demo.log
sleep 2

mid_pub="$(rg -c '"msg":"collector_event_published"' logs/collector.log || true)"
mid_ckpt="$(cat tmp/tail.checkpoint.json 2>/dev/null || echo '{"offset":0}')"

pkill -f 'cmd/collector-tail|/collector-tail' || true
sleep 1
./scripts/demo_up.sh >/tmp/fr01_demo_up_resume.out 2>&1
sleep 2

post_ckpt_log="$(rg '"msg":"collector_tail_checkpoint_state"' logs/collector.log | tail -n 1 || true)"
[[ -n "$post_ckpt_log" ]] || { echo "FAIL: no checkpoint state log after restart"; exit 1; }

echo "checkpoint_before=${base_ckpt}"
echo "checkpoint_after_event=${mid_ckpt}"
echo "checkpoint_resume_log=${post_ckpt_log}"
echo "collector_published_before=${base_pub} after_event=${mid_pub}"

# 4) auth.log override startup check (no crash)
echo "[5/5] auth.log override startup check"
RSIEM_COLLECTOR_TAIL_PATH=/var/log/auth.log timeout 6s \
  go run -mod=vendor ./cmd/collector-tail --config configs/collector.yaml \
  > logs/collector-auth.log 2>&1 || test $? -eq 124

auth_override_line="$(rg '"msg":"collector_tail_input_path_resolved".*"source":"env_override"' logs/collector-auth.log | tail -n 1 || true)"
[[ -n "$auth_override_line" ]] || { echo "FAIL: no auth.log override resolution log found"; exit 1; }

echo "PASS: FR-01 local verification completed"
echo "PROOF_CHECKPOINT: checkpoint_before=${base_ckpt} checkpoint_after=${mid_ckpt} resume_log=${post_ckpt_log}"
echo "PROOF_AUTHLOG_OVERRIDE: ${auth_override_line}"
