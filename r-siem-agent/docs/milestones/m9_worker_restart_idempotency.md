# M9 Worker Restart Idempotency (Redelivery Replay)

Milestone: **Worker restart does not re-execute a step if result.<run_id>.<step_id> already exists**

## Preconditions

Must be running:
- NATS
- master-consume
- master-roe
- collector-tail
- agent
- worker (logs/worker-f.log)

## Steps

Publish a FAST-lane trigger so we get a single agent_command step.

```bash
go run -mod=vendor ./cmd/master-roe-pubtrigger \
  -config configs/master.yaml \
  -alert-key A-M9-REDRIVE \
  -rule-id R-COLLECT-INVALID-USER \
  -severity high \
  -group-key 10.0.0.55 \
  -lane FAST
```

Confirm waiting approval and extract RUN_ID.

```bash
rg -n "response_run_waiting_approval" logs/master-roe.log
RUN_ID=$(rg -n "response_run_waiting_approval" logs/master-roe.log | tail -n 1 \
  | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')
```

Approve the run.

```bash
go run -mod=vendor ./cmd/master-roe-approve \
  -config configs/master.yaml \
  -run_id "$RUN_ID" \
  -decision approve \
  -actor khotso \
  -reason "M9 worker restart idempotency"
```

Capture STEP_ID from the published step.

```bash
STEP_ID=$(rg -n "response_step_published" logs/master-roe.log | tail -n 1 \
  | sed -n 's/.*"step_id":"\([^"]*\)".*/\1/p')
```

Verify the first execution succeeded and result_key was written.

```bash
rg -n "step_succeeded" logs/worker-f.log | rg -n "$RUN_ID|$STEP_ID"
rg -n "response_result_applied" logs/master-roe.log | rg -n "$RUN_ID|$STEP_ID"
rg -n "\"result_key\":\"result\.$RUN_ID\.$STEP_ID\"" logs/master-roe.log
```

Stop the worker process, then re-publish the exact same step while it is down.

```bash
go run -mod=vendor ./cmd/master-roe-pubstep \
  -config configs/master.yaml \
  -run-id "$RUN_ID" \
  -step-id "$STEP_ID" \
  -step-index 0 \
  -action-type agent_command \
  -lane FAST \
  -attempt 1
```

Start the worker again and confirm replay (no re-execution).

```bash
rg -n "worker_result_replay" logs/worker-f.log | rg -n "$RUN_ID|$STEP_ID"
rg -n "step_duplicate_succeeded" logs/worker-f.log | rg -n "$RUN_ID|$STEP_ID"
rg -n "agent_command_exec_start" logs/agent.log | rg -n "$RUN_ID|$STEP_ID" | tail -n 5
```

## Expected log messages (exact names)

- step_received
- worker_result_replay
- step_duplicate_succeeded
- response_step_result_received
- response_result_applied
- response_run_updated
