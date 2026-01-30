# M17 Crash Between Persist and Publish

Milestone: **Worker exits after persistTerminalResult and before publish, then replay drains on restart**

## Preconditions

Must be running:
- NATS
- master-consume
- master-roe
- collector-tail
- agent

Worker should be stopped before the failpoint run.

## Steps

Trigger a FAST-lane response that requires approval:

```bash
go run -mod=vendor ./cmd/master-roe-pubtrigger \
  -config configs/master.yaml \
  -alert-key A-M17-CRASH \
  -rule-id R-COLLECT-INVALID-USER \
  -severity high \
  -group-key 10.0.0.58 \
  -lane FAST
```

Extract RUN_ID from the waiting-approval log:

```bash
RUN_ID=$(rg -n "response_run_waiting_approval" logs/master-roe.log | tail -n 1 \
  | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')
```

Approve the run:

```bash
go run -mod=vendor ./cmd/master-roe-approve \
  -config configs/master.yaml \
  -run_id "$RUN_ID" \
  -decision approve \
  -actor khotso \
  -reason "M17 crash between persist and publish"
```

Capture STEP_ID from the published step:

```bash
STEP_ID=$(rg -n "response_step_published" logs/master-roe.log | tail -n 1 \
  | sed -n 's/.*"step_id":"\([^"]*\)".*/\1/p')
```

Start worker with failpoint scoped to RUN_ID/STEP_ID:

```bash
export RSIEM_WORKER_FAILPOINT=after_persist_terminal
export RSIEM_WORKER_FAILPOINT_RUN_ID="$RUN_ID"
export RSIEM_WORKER_FAILPOINT_STEP_ID="$STEP_ID"
export RSIEM_WORKER_FAILPOINT_ONCE=1
mkdir -p logs
(go run -mod=vendor ./cmd/master-roe-worker --config configs/master.yaml | tee -a logs/worker-f.log) || true
```

Verify the worker exits after persist and logs the failpoint:

```bash
rg -n "roe_failpoint_triggered" logs/worker-f.log | rg -n "$RUN_ID|$STEP_ID|after_persist_terminal"
```

Restart worker normally (no failpoint env):

```bash
unset RSIEM_WORKER_FAILPOINT RSIEM_WORKER_FAILPOINT_RUN_ID RSIEM_WORKER_FAILPOINT_STEP_ID RSIEM_WORKER_FAILPOINT_ONCE
(go run -mod=vendor ./cmd/master-roe-worker --config configs/master.yaml | tee -a logs/worker-f.log)
```

Confirm replay path and no new agent execution for that run/step:

```bash
rg -n "worker_result_replay" logs/worker-f.log | rg -n "$RUN_ID|$STEP_ID"
rg -n "step_duplicate_succeeded" logs/worker-f.log | rg -n "$RUN_ID|$STEP_ID"
rg -n "agent_command_exec_start" logs/agent.log | rg -n "$RUN_ID|$STEP_ID" || echo "OK: no new agent exec start"
```

Verify master-roe reaches SUCCEEDED:

```bash
rg -n "response_result_applied" logs/master-roe.log | rg -n "$RUN_ID|SUCCEEDED"
rg -n "response_run_updated" logs/master-roe.log | rg -n "$RUN_ID|SUCCEEDED"
```
