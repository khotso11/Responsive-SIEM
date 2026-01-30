# M11 STANDARD Lane Restart Gate

Milestone: **Prove STANDARD lane routing, subject, and worker lane**

## Preconditions

Must be running:
- NATS
- master-consume
- master-roe
- collector-tail
- agent
- worker (STANDARD or BOTH)

## Steps

Publish a STANDARD-lane trigger.

```bash
go run -mod=vendor ./cmd/master-roe-pubtrigger \
  -config configs/master.yaml \
  -alert-key A-M11-STANDARD \
  -rule-id R-COLLECT-INVALID-USER \
  -severity high \
  -group-key 10.0.0.57 \
  -lane STANDARD
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
  -reason "M11 STANDARD lane proof"
```

Verify the step was published to the STANDARD subject.

```bash
rg -n "response_step_published" logs/master-roe.log | rg -n "$RUN_ID|rsiem.response.steps.standard"
```

Verify the worker consumed the STANDARD lane step.

```bash
rg -n "step_received" logs/worker-f.log | rg -n "$RUN_ID|STANDARD"
```

Verify execution and run completion.

```bash
rg -n "agent_command_exec_start" logs/agent.log | rg -n "$RUN_ID"
rg -n "agent_command_exec_done" logs/agent.log | rg -n "$RUN_ID"
rg -n "response_result_applied" logs/master-roe.log | rg -n "$RUN_ID|SUCCEEDED"
rg -n "response_run_updated" logs/master-roe.log | rg -n "$RUN_ID|SUCCEEDED"
```

## Expected log messages (exact names)

- response_step_published
- step_received
- agent_command_exec_start
- agent_command_exec_done
- response_result_applied
- response_run_updated
