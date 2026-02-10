# R-SIEM Endpoint Agent

## What is R-SIEM / Responsive SIEM
R-SIEM combines detection with automated response orchestration. It is not only log collection; it executes response playbooks through ROE and an allowlisted agent executor. Collection is the next milestone, and the ROE execution path is already working.

## Working convention
Always run commands from the module root:

```
cd ~/projects/r-siem-agent
```

## Requirements
- Go 1.22+ (set `GOTOOLCHAIN=go1.24.11` for local runs)
- Docker for local NATS JetStream

## Components / Commands
- `cmd/master-roe`: Orchestrator. Consumes triggers, compiles response plans from playbooks, and enforces policy gates (approvals, allowlists).
- `cmd/master-roe-worker`: Executes step messages via connectors (FAST/STD worker pools).
- `cmd/master-consume`: Consumer/processing side for stream subscriptions (operational service).
- `cmd/agent`: Real allowlisted command executor.
- `cmd/agent-sim`: Agent simulator.
- `cmd/master-roe-pubtrigger`: Publishes response triggers (manual testing entry point).
- `cmd/master-roe-approve`: Approves or denies response runs when approvals are required.
- `cmd/master-smoke`: Smoke driver.

## Quick Start (Local Lab)
Assume separate terminals.

Terminal A - NATS JetStream:

```
docker run --rm --name rsiem-nats -p 4222:4222 -p 8222:8222 nats:2.10 -js
```

Terminal B - Consume + RCE + Incidents:

```
export GOTOOLCHAIN=go1.24.11
go run -mod=vendor ./cmd/master-consume --config configs/master.yaml | tee logs/master-consume.log
```

Terminal C - ROE (triggers -> runs -> plans -> results consumer):

```
export GOTOOLCHAIN=go1.24.11
go run -mod=vendor ./cmd/master-roe --config configs/master.yaml | tee logs/master-roe.log
```

Terminal D - ROE worker (executes steps -> publishes results):

```
export GOTOOLCHAIN=go1.24.11
go run -mod=vendor ./cmd/master-roe-worker --config configs/master.yaml | tee logs/worker-f.log
```

Terminal E - Agent (allowlisted executor):

```
export GOTOOLCHAIN=go1.24.11
go run -mod=vendor ./cmd/agent --config configs/agent.yaml | tee logs/agent.log
```

## Approval timeout
`policies.approvals.timeout_ms` is now `300000` (5 minutes).

## E2E Proof: network_block dry-run

A) Pubtrigger:

```
go run -mod=vendor ./cmd/master-roe-pubtrigger -config configs/master.yaml -alert-key A-SEQ-DRYRUN-X -rule-id R-SEQ-PROCESS-TO-NET -severity high -group-key 10.0.0.10 -lane FAST
```

B) Find run_id:

```
tail -n 200 logs/master-roe.log | rg "A-SEQ-DRYRUN-X|approval_request_published|response_run_waiting_approval" | tail -n 20
```

C) Approve:

```
RUN=<paste>
go run -mod=vendor ./cmd/master-roe-approve -config configs/master.yaml -run_id "$RUN" -decision approve -actor khotso -reason "lab approval"
```

D) Grep proof:

```
rg "\"run_id\":\"$RUN\"" logs/master-roe.log | rg "approval_(received|approved)|response_step_published|response_run_updated" | tail -n 200
rg "\"run_id\":\"$RUN\"" logs/worker-f.log | rg "network_block_(request|reply|terminal)|step_failed_|step_succeeded" | tail -n 200
rg "$RUN" exports/roe_steps.jsonl | rg "receipt|message|dry_run" | tail -n 50
```

E) Expected output:
- `response_run_updated` status `SUCCEEDED`
- `exports` receipt.message contains: `dry_run: network_block target=10.0.0.10`

## E2E Proof: network_rate_limit dry-run

A) Pubtrigger:

```
go run -mod=vendor ./cmd/master-roe-pubtrigger -config configs/master.yaml -alert-key A-JOIN-DRYRUN-X -rule-id R-JOIN-HIGH-NET -severity high -group-key 10.0.0.55 -lane FAST
```

B) Find run_id:

```
tail -n 200 logs/master-roe.log | rg "A-JOIN-DRYRUN-X|approval_request_published|response_run_waiting_approval" | tail -n 20
```

C) Approve:

```
RUN=<paste>
go run -mod=vendor ./cmd/master-roe-approve -config configs/master.yaml -run_id "$RUN" -decision approve -actor khotso -reason "lab approval"
```

D) Grep proof:

```
rg "\"run_id\":\"$RUN\"" logs/master-roe.log | rg "approval_(received|approved)|response_step_published|response_run_updated" | tail -n 200
rg "\"run_id\":\"$RUN\"" logs/worker-f.log | rg "network_rate_limit_(request|reply|terminal)|step_failed_|step_succeeded" | tail -n 200
rg "$RUN" exports/roe_steps.jsonl | rg "receipt|message|dry_run" | tail -n 50
```

E) Expected output:
- `response_run_updated` status `SUCCEEDED`
- `exports` receipt.message contains: `dry_run: network_rate_limit target=10.0.0.55`

## M18–M23 runbook

Start the collector + detector (assumes NATS, master-roe, worker, and agent are already running):

```
mkdir -p logs
go run -mod=vendor ./cmd/collector-tail -config configs/collector.yaml | tee logs/collector-tail.log
go run -mod=vendor ./cmd/detector-v0 -config configs/detector.yaml | tee logs/detector-v0.log
```

Append a matching line:

```
echo "Feb 2 invalid user test from 10.0.0.77" >> tmp/demo.log
```

Find run_id + approve (manual):

```
tail -n 200 logs/master-roe.log | rg "A-COLLECT-INVALID-USER|approval_request_published|response_run_waiting_approval" | tail -n 20
RUN=<paste>
go run -mod=vendor ./cmd/master-roe-approve -config configs/master.yaml -run_id "$RUN" -decision approve -actor khotso -reason "lab approval"
```

Verify logs:

```
rg "event_published" logs/collector-tail.log | tail -n 20
rg "trigger_published" logs/detector-v0.log | tail -n 20
rg "\"run_id\":\"$RUN\"" logs/master-roe.log | rg "response_run_created|response_run_waiting_approval|response_run_updated" | tail -n 200
rg "\"run_id\":\"$RUN\"" logs/worker-f.log | rg "step_succeeded|step_failed" | tail -n 200
rg "\"run_id\":\"$RUN\"" logs/agent.log | rg "agent_command_exec_start" | tail -n 20
```

Restart safety (dedupe) quick check:

```
pkill -f ./cmd/detector-v0 || true
echo "Feb 2 invalid user test from 10.0.0.77" >> tmp/demo.log
echo "Feb 2 invalid user test from 10.0.0.88" >> tmp/demo.log
go run -mod=vendor ./cmd/detector-v0 -config configs/detector.yaml | tee logs/detector-v0-restart.log
rg "detect_dedup_hit" logs/detector-v0-restart.log | tail -n 20
```

Cooldown + group_key parsing checks:

```
# For a faster cooldown test, temporarily set cooldown_ms: 2000 in configs/detector.yaml
echo "Feb 2 invalid user test from 10.0.0.77" >> tmp/demo.log
echo "Feb 2 invalid user test from 10.0.0.77" >> tmp/demo.log
rg "cooldown_hit" logs/detector-v0.log | tail -n 20

# Wait for cooldown to expire (60s by default if not overridden)
sleep 65
echo "Feb 2 invalid user test from 10.0.0.77" >> tmp/demo.log
rg "trigger_published" logs/detector-v0.log | tail -n 20

# Two different IPs should show different group_key values
echo "Feb 2 invalid user test from 10.0.0.88" >> tmp/demo.log
echo "Feb 2 invalid user test from 10.0.0.99" >> tmp/demo.log
rg "rule_matched" logs/detector-v0.log | tail -n 20
```

## M24 Restart-safety proof (worker down during approval)

Canonical terminal order (A–I): A NATS, B master, C master-consume, D smoke (one-shot scripts/greps only), E master-roe, F roe-worker, G agent, H collector-tail, I detector-v0.

Ensure E/F/G/H/I are running and teeing to the canonical log paths:

```
go run -mod=vendor ./cmd/master-roe --config configs/master.yaml | tee logs/master-roe.log
go run -mod=vendor ./cmd/master-roe-worker --config configs/master.yaml | tee logs/roe-worker.log
go run -mod=vendor ./cmd/agent --config configs/agent.yaml | tee logs/agent.log
go run -mod=vendor ./cmd/collector-tail --config configs/collector.yaml | tee logs/collector-tail.log
go run -mod=vendor ./cmd/detector-v0 --config configs/detector.yaml | tee logs/detector-v0.log
```

Terminal D (one-shot) script:

```
./scripts/m24_restart_safety.sh
```

Manual approval + restart steps (if not using the script prompts):

```
# Stop Terminal F: Ctrl+C
go run -mod=vendor ./cmd/master-roe-worker --config configs/master.yaml | tee logs/roe-worker.log

RUN=<paste>
go run -mod=vendor ./cmd/master-roe-approve -config configs/master.yaml -run_id "$RUN" -decision approve -actor khotso -reason "lab approval"
```

Grep evidence:

```
rg "\"run_id\":\"$RUN\"" logs/roe-worker.log | rg "step_received|step_succeeded|worker_result_replay|step_duplicate_succeeded" | tail -n 200
rg "\"run_id\":\"$RUN\"" logs/agent.log | rg "agent_command_exec_start|agent_command_exec_done" | tail -n 200
```

## M25 Replay/idempotency proof (no double exec)

Canonical terminal order (A–I): A NATS, B master, C master-consume, D smoke (one-shot scripts/greps only), E master-roe, F roe-worker, G agent, H collector-tail, I detector-v0.

Manual steps:

```
# Stop Terminal F: Ctrl+C
RUN=<paste>
go run -mod=vendor ./cmd/master-roe-approve -config configs/master.yaml -run_id "$RUN" -decision approve -actor khotso -reason "lab approval"

# Start Terminal F again (re-run command)
go run -mod=vendor ./cmd/master-roe-worker --config configs/master.yaml | tee logs/roe-worker.log

# After first success, induce replay by stopping F again (Ctrl+C) and restarting it
go run -mod=vendor ./cmd/master-roe-worker --config configs/master.yaml | tee logs/roe-worker.log
```

Evidence greps + expected outcomes:

```
rg "\"run_id\":\"$RUN\"" logs/roe-worker.log | rg "step_received|step_succeeded|worker_result_replay|step_duplicate_succeeded" | tail -n 200
rg "\"run_id\":\"$RUN\"" logs/agent.log | rg "agent_command_exec_start|agent_command_exec_done" | tail -n 200
```

Expected:
- Worker shows initial `step_received` and `step_succeeded`.
- Replay shows `worker_result_replay` or `step_duplicate_succeeded`.
- Agent has exactly one `agent_command_exec_start` for the run across replay.

Terminal D (one-shot) script:

```
./scripts/m25_replay_no_double_exec.sh
```

## M26–M27 Detector proofs (negative cases + cooldown by group_key)

Canonical terminal order (A–I): A NATS, B master, C master-consume, D smoke (one-shot scripts/greps only), E master-roe, F Worker, G agent, H collector-tail, I detector-v0.

Manual steps + expected outcomes:

```
# M26 negative case (missing "from <ipv4>")
echo "M26 invalid user ts=$(date +%s)" >> tmp/demo.log
rg "missing_group_key" logs/detector-v0.log | tail -n 5
rg "trigger_published" logs/detector-v0.log | tail -n 5
rg "response_run_waiting_approval" logs/master-roe.log | tail -n 5
# Expected: missing_group_key appears; no new trigger_published or response_run_waiting_approval

# M27 cooldown by group_key
echo "M27 invalid user from 10.0.0.77 ts=$(date +%s)" >> tmp/demo.log
rg "trigger_published" logs/detector-v0.log | tail -n 5
rg "response_run_waiting_approval" logs/master-roe.log | tail -n 5
# Expected: trigger_published + new response_run_waiting_approval

echo "M27 invalid user from 10.0.0.77 ts=$(date +%s)" >> tmp/demo.log
rg "cooldown_hit" logs/detector-v0.log | tail -n 5
rg "response_run_waiting_approval" logs/master-roe.log | tail -n 5
# Expected: cooldown_hit; no new response_run_waiting_approval

echo "M27 invalid user from 10.0.0.88 ts=$(date +%s)" >> tmp/demo.log
rg "trigger_published" logs/detector-v0.log | tail -n 5
rg "response_run_waiting_approval" logs/master-roe.log | tail -n 5
# Expected: trigger_published + new response_run_waiting_approval (different group_key)
```

Terminal D (one-shot) script:

```
./scripts/m26_m27_detector_proofs.sh
```

## M28–M30 Proofs (dedupe + approval timeout)

Canonical terminal order (A–I): A NATS, B master, C master-consume, D smoke (one-shot scripts/greps only), E master-roe, F Worker, G agent, H collector-tail, I detector-v0.

Manual steps + expected outcomes:

```
# M28 detector strict dedupe (same event_idem_key twice)
# Publish the same raw event twice (same event_idem_key + Nats-Msg-Id).
EID="evt.m28.$(date +%s)"
LINE="M28 invalid user from 10.0.0.77 ts=$(date +%s)"
go run -mod=vendor ./cmd/master-pubevent -config configs/master.yaml -event_idem_key "$EID" -line "$LINE"
go run -mod=vendor ./cmd/master-pubevent -config configs/master.yaml -event_idem_key "$EID" -line "$LINE"
# Expected: first publish => trigger_published + new response_run_waiting_approval.
#           second publish => detect_dedup_hit + NO new response_run_waiting_approval.
rg "trigger_published" logs/detector-v0.log | tail -n 5
rg "detect_dedup_hit" logs/detector-v0.log | tail -n 5
rg "response_run_waiting_approval" logs/master-roe.log | tail -n 5

# M30 approval timeout (no approval provided)
# Expected: response_run_waiting_approval includes timeout_ms, then approval_timed_out for same run_id.
rg "response_run_waiting_approval" logs/master-roe.log | tail -n 5
rg "approval_timed_out" logs/master-roe.log | tail -n 5
```

Terminal D (one-shot) scripts:

```
./scripts/m28_detector_dedupe_proof.sh
./scripts/m30_approval_timeout_proof.sh
```

## M32 Standard lane end-to-end

Canonical terminal order (A–I): A NATS, B master, C master-consume, D smoke (one-shot scripts/greps only), E master-roe, F roe-worker, G agent, H collector-tail, I detector-v0.

Manual steps + expected outcomes:

```
# Publish STANDARD lane trigger
go run -mod=vendor ./cmd/master-roe-pubtrigger -config configs/master.yaml -alert-key A-M32-STD-X -rule-id R-SEQ-PROCESS-TO-NET -severity high -group-key 10.0.0.77 -lane STANDARD

# Wait for run_id and approve (or use the script)
rg "response_trigger_received" logs/master-roe.log | rg "STANDARD" | tail -n 5
rg "response_run_waiting_approval" logs/master-roe.log | tail -n 5
RUN=<paste>
go run -mod=vendor ./cmd/master-roe-approve -config configs/master.yaml -run_id "$RUN" -decision approve -actor khotso -reason "lab approval"

# Expected: response_trigger_received lane STANDARD, then worker step_received + step_succeeded and agent_command_exec_start once
rg "\"run_id\":\"$RUN\"" logs/roe-worker.log | rg "step_received|step_succeeded" | tail -n 200
rg "\"run_id\":\"$RUN\"" logs/agent.log | rg "agent_command_exec_start" | tail -n 20

# Note: the M32 script fails fast if approval times out or the run becomes FAILED_SAFE.
```

Terminal D (one-shot) script:

```
./scripts/m32_standard_lane_e2e_proof.sh
```

## M33 Cooldown persists across detector restart

Canonical terminal order (A–I): A NATS, B master, C master-consume, D smoke (one-shot scripts/greps only), E master-roe, F roe-worker, G agent, H collector-tail, I detector-v0.

Manual steps + expected outcomes:

```
# Trigger once for group_key 10.0.0.77
echo "M33 invalid user from 10.0.0.77 ts=$(date +%s)" >> tmp/demo.log
rg "trigger_published" logs/detector-v0.log | tail -n 5
rg "response_run_waiting_approval" logs/master-roe.log | tail -n 5

# Restart detector (Terminal I), then trigger again within cooldown
echo "M33 invalid user from 10.0.0.77 ts=$(date +%s)" >> tmp/demo.log
rg "cooldown_hit" logs/detector-v0.log | tail -n 5
rg "trigger_published" logs/detector-v0.log | tail -n 5
rg "response_run_waiting_approval" logs/master-roe.log | tail -n 5

# Expected: cooldown_hit and no new trigger/run after restart for same IP within cooldown
```

Terminal D (one-shot) script:

```
./scripts/m33_cooldown_persist_restart.sh
```

## M34 Collector checkpoint restart safety

Canonical terminal order (A–I): A NATS, B master, C master-consume, D smoke (one-shot scripts/greps only), E master-roe, F roe-worker, G agent, H collector-tail, I detector-v0.

Manual steps + expected outcomes:

```
# Append a line and wait for event_published
echo "M34 collector line 1 ts=$(date +%s)" >> tmp/demo.log
rg "event_published" logs/collector-tail.log | tail -n 5

# Restart collector (Terminal H), append another line
echo "M34 collector line 2 ts=$(date +%s)" >> tmp/demo.log
rg "event_published" logs/collector-tail.log | tail -n 5

# Expected: post-restart offset > pre-restart offset; no duplicate event_idem_key
```

Terminal D (one-shot) script:

```
./scripts/m34_collector_checkpoint_restart.sh
```

## M35 Detector restart replay safety (no duplicate triggers/runs)

Canonical terminal order (A–I): A NATS, B master, C master-consume, D smoke (one-shot scripts/greps only), E master-roe, F roe-worker, G agent, H collector-tail, I detector-v0.

Manual steps + expected outcomes:

```
# Publish a single raw event (event_idem_key) and wait for trigger/run
EID="evt.m35.$(date +%s)"
LINE="M35 invalid user from 10.0.0.77 ts=$(date +%s)"
go run -mod=vendor ./cmd/master-pubevent -config configs/master.yaml -event_idem_key "$EID" -line "$LINE"
rg "trigger_published" logs/detector-v0.log | tail -n 5
rg "response_run_waiting_approval" logs/master-roe.log | tail -n 5

# Restart detector (Terminal I) and publish the same event_idem_key again
go run -mod=vendor ./cmd/master-pubevent -config configs/master.yaml -event_idem_key "$EID" -line "$LINE"
rg "detect_dedup_hit" logs/detector-v0.log | tail -n 5
rg "response_run_waiting_approval" logs/master-roe.log | tail -n 5

# Expected: detect_dedup_hit and no second trigger/run for same event_idem_key
```

Terminal D (one-shot) script:

```
./scripts/m35_detector_restart_replay_safety.sh
```

Optional M36 fail-safe proof (approval timeout):

```
./scripts/m36_approval_timeout_fail_safe_proof.sh
```

Agent proofs:

```
./scripts/m37_agent_command_e2e_proof.sh
./scripts/m38_agent_allowlist_denied_proof.sh
```

Notes:
- `PB-COUNT-PROCESS-HOST` includes an `agent_command` step without `params.command` or `params.name`.
- That intentionally yields `missing_command` and `agent_command_exec_denied`, proving the deny path.
- `PB-AGENT-PING-LOCALHOST` sets `params.command=ping` and `params.target=127.0.0.1`.
- With approval, that playbook produces `agent_command_exec_start` and `agent_command_exec_done`.

## Demo (Sprint C)

Start the services in the usual A–I terminal order as documented above. Then run:

```
DEMO_EVIDENCE_LOG="logs/demo_$(date +%Y%m%d_%H%M%S).log"
chmod +x scripts/demo_runner_sprint_c.sh
DEMO_EVIDENCE_LOG="$DEMO_EVIDENCE_LOG" ./scripts/demo_runner_sprint_c.sh |& tee "$DEMO_EVIDENCE_LOG"
```

The demo orchestrates M40 → M41 → M37-style success → M42 in sequence. Evidence logs land in `logs/demo_YYYYMMDD_HHMMSS.log`.

## Configuration

Configuration lives in `configs/agent.yaml` and currently supports:

```yaml
log:
  level: INFO # DEBUG, INFO, WARN, ERROR
heartbeat:
  interval_seconds: 60
mock:
  interval_seconds: 1 # emits an event each second
```

## Running

```
go run ./cmd/agent --config configs/agent.yaml
```

The agent logs a startup banner, a safe configuration summary, emits heartbeat messages on the configured cadence, and logs normalized mock events generated by the builtin collector. Press `CTRL+C` to shut it down; shutdown should complete within a few seconds.

### Mock master servers

The legacy TCP mock remains available:

```
go run ./cmd/master-mock --addr 127.0.0.1:7777 --ack-delay-ms 150 --ack-drop-rate 0.0
```

For the gRPC+mTLS transport, start the new mock master:

```
go run ./cmd/master-mock-grpc \
  --addr 127.0.0.1:7777 \
  --ca configs/certs/ca.pem \
  --cert configs/certs/master.pem \
  --key configs/certs/master-key.pem \
  --ack-delay-ms 150 \
  --ack-drop-rate 0.0
```

Then set `transport.mode: grpc_mtls` in `configs/agent.yaml` and run the agent:

```
go run ./cmd/agent --config configs/agent.yaml
```

## Testing

```
cd ~/projects/r-siem-agent
go test ./internal/... ./cmd/...
```
