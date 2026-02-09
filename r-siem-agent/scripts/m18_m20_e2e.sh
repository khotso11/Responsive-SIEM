#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

mkdir -p logs tmp

DET_CONFIG="configs/detector.yaml"
TEST_DET_CONFIG="tmp/detector-test.yaml"
cp "$DET_CONFIG" "$TEST_DET_CONFIG"
if rg -q "^cooldown_ms:" "$TEST_DET_CONFIG"; then
  sed -i 's/^cooldown_ms:.*/cooldown_ms: 2000/' "$TEST_DET_CONFIG"
else
  echo "cooldown_ms: 2000" >> "$TEST_DET_CONFIG"
fi

echo "Starting detector-v0 (creates RSIEM_EVENTS + RSIEM_DETECT_DEDUPE + RSIEM_DETECT_COOLDOWN if missing)..."
go run -mod=vendor ./cmd/detector-v0 -config "$TEST_DET_CONFIG" > logs/detector-v0.log 2>&1 &
DET_PID=$!

echo "Starting collector-tail (tails tmp/demo.log)..."
go run -mod=vendor ./cmd/collector-tail -config configs/collector.yaml > logs/collector-tail.log 2>&1 &
COL_PID=$!

echo "detector-v0 PID: ${DET_PID}"
echo "collector-tail PID: ${COL_PID}"

sleep 1
echo "Feb 2 invalid user test from 10.0.0.77" >> tmp/demo.log

cat <<'EOF'

Manual approval step:
1) Find RUN_ID in logs/master-roe.log:
   tail -n 200 logs/master-roe.log | rg "A-COLLECT-INVALID-USER|approval_request_published|response_run_waiting_approval" | tail -n 20
2) Approve:
   RUN=<paste>
   go run -mod=vendor ./cmd/master-roe-approve -config configs/master.yaml -run_id "$RUN" -decision approve -actor khotso -reason "lab approval"

Verify logs:
  rg "event_published" logs/collector-tail.log | tail -n 20
  rg "trigger_published" logs/detector-v0.log | tail -n 20
  rg "\"run_id\":\"$RUN\"" logs/master-roe.log | rg "response_run_created|response_run_waiting_approval|response_run_updated" | tail -n 200
  rg "\"run_id\":\"$RUN\"" logs/worker-f.log | rg "step_succeeded|step_failed" | tail -n 200
  rg "\"run_id\":\"$RUN\"" logs/agent.log | rg "agent_command_exec_start" | tail -n 20

Restart safety check:
  kill ${DET_PID}
  echo "Feb 2 invalid user test from 10.0.0.77" >> tmp/demo.log
  echo "Feb 2 invalid user test from 10.0.0.88" >> tmp/demo.log
  go run -mod=vendor ./cmd/detector-v0 -config "$TEST_DET_CONFIG" > logs/detector-v0-restart.log 2>&1 &
  rg "detect_dedup_hit" logs/detector-v0-restart.log | tail -n 20

Cooldown + group_key parsing:
  echo "Feb 2 invalid user test from 10.0.0.77" >> tmp/demo.log
  echo "Feb 2 invalid user test from 10.0.0.77" >> tmp/demo.log
  rg "cooldown_hit" logs/detector-v0-restart.log | tail -n 20
  sleep 3
  echo "Feb 2 invalid user test from 10.0.0.77" >> tmp/demo.log
  rg "trigger_published" logs/detector-v0-restart.log | tail -n 20
  echo "Feb 2 invalid user test from 10.0.0.88" >> tmp/demo.log
  echo "Feb 2 invalid user test from 10.0.0.99" >> tmp/demo.log
  rg "rule_matched" logs/detector-v0-restart.log | tail -n 20
EOF
