# M10 Agent Restart Safety (Retry Success)

Milestone: **Agent down causes FAILED_TRANSIENT + retry; agent returns within budget and run reaches SUCCEEDED**

## Preconditions

Must be running:
- NATS
- master-consume
- master-roe
- collector-tail
- worker (logs/worker-f.log)

Must be stopped:
- agent

## Steps

Publish a FAST-lane trigger for an agent_command step.

```bash
go run -mod=vendor ./cmd/master-roe-pubtrigger \
  -config configs/master.yaml \
  -alert-key A-M10-AGENT-DOWN \
  -rule-id R-COLLECT-INVALID-USER \
  -severity high \
  -group-key 10.0.0.56 \
  -lane FAST
```

Confirm waiting approval and extract RUN_ID.

```bash
rg -n "response_run_waiting_approval" logs/master-roe.log
RUN_ID=$(rg -n "response_run_waiting_approval" logs/master-roe.log | tail -n 1 \
  | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')
```

Approve while the agent is still down.

```bash
go run -mod=vendor ./cmd/master-roe-approve \
  -config configs/master.yaml \
  -run_id "$RUN_ID" \
  -decision approve \
  -actor khotso \
  -reason "M10 agent restart retry success"
```

Verify transient failure + retry while the agent is down (retry window is derived from timeout_ms, so keep downtime within that budget).

```bash
rg -n "agent_command_terminal" logs/worker-f.log | rg -n "$RUN_ID"
rg -n "roe_connector_retry" logs/worker-f.log | rg -n "$RUN_ID"
rg -n "step_failed_transient" logs/worker-f.log | rg -n "$RUN_ID"
rg -n "response_step_result_received" logs/master-roe.log | rg -n "$RUN_ID|FAILED_TRANSIENT"
rg -n "response_result_applied" logs/master-roe.log | rg -n "$RUN_ID|FAILED_TRANSIENT"
```

Start the agent, verify subscription, and let the retry succeed.

```bash
rg -n "agent_command_subscribed" logs/agent.log
rg -n "agent_command_reply" logs/worker-f.log | rg -n "$RUN_ID"
rg -n "agent_command_exec_start" logs/agent.log | rg -n "$RUN_ID"
rg -n "agent_command_exec_done" logs/agent.log | rg -n "$RUN_ID"
rg -n "step_succeeded" logs/worker-f.log | rg -n "$RUN_ID"
```

Verify deterministic reply envelope fields on agent_command_reply.

```bash
rg -n "agent_command_reply" logs/worker-f.log | rg -n "$RUN_ID|exit_code|duration_ms|truncated_stdout|truncated_stderr|error_class"
```

Confirm the run reaches SUCCEEDED and never hits FAILED_SAFE.

```bash
rg -n "response_result_applied" logs/master-roe.log | rg -n "$RUN_ID|SUCCEEDED"
rg -n "response_run_updated" logs/master-roe.log | rg -n "$RUN_ID|SUCCEEDED"
rg -n "\"status\":\"FAILED_SAFE\"" logs/master-roe.log | rg -n "$RUN_ID" || echo "OK: no FAILED_SAFE for run"
```

## Expected log messages (exact names)

- agent_command_terminal
- roe_connector_retry
- step_failed_transient
- agent_command_reply
- agent_command_exec_start
- agent_command_exec_done
- step_succeeded
- response_step_result_received
- response_result_applied
- response_run_updated
