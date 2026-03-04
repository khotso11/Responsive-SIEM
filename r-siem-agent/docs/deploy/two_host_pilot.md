# Two-Host Pilot (Deterministic Checklist)

Goal: prove one remote endpoint can ingest telemetry and execute a targeted action through the master.

- Host A: MASTER
- Host B: ENDPOINT (`linux-endpoint-01` example)

## Runtime Variables

Use runtime discovery (do this in every new shell on Host A):

```bash
MASTER_IP="$(hostname -I | awk '{print $1}')"
NATS_URL="nats://${MASTER_IP}:4222"
MASTER_ADDR="${MASTER_IP}:7777"
echo "MASTER_IP=$MASTER_IP"
echo "NATS_URL=$NATS_URL"
echo "MASTER_ADDR=$MASTER_ADDR"
```

## 1) Master Start

On Host A:

```bash
cd /path/to/r-siem-agent
./scripts/deploy/master/master_up_lan.sh
```

Expected:
- NATS reachable on `$NATS_URL`
- master transport on `$MASTER_ADDR`
- ROE/worker/detector logs active

## 2) Endpoint Install and Start

On Host B (Linux example):

```bash
# Use values printed by Host A ./scripts/deploy/master/master_up_lan.sh
MASTER_IP="<MASTER_IP_FROM_HOST_A>"
NATS_URL="nats://${MASTER_IP}:4222"
sudo ./scripts/deploy/linux/install_endpoint.sh \
  --master-ip "$MASTER_IP" \
  --agent-id linux-endpoint-01 \
  --nats-url "$NATS_URL" \
  --config-dir /tmp/rsiem-endpoint-package
```

Expected:
- `rsiem-agent` and `rsiem-collector-tail` are active

## 3) Generate Endpoint Telemetry

On Host B, append a deterministic marker event:

```bash
MARKER="pilot_user_$(date -u +%Y%m%d%H%M%S)"
TS_MS=$(date +%s%3N)
SIM_SRC_IP="<SIMULATED_SRC_IP>"
echo "FAILED login user=${MARKER} src=${SIM_SRC_IP} ts=${TS_MS} node=linux-endpoint-01" | sudo tee -a /var/log/auth.log
echo "$MARKER"
```

Expected:
- The marker appears in detector/master pipeline within a few seconds

## 4) Evidence Commands

Run these on Host A.

DB row attribution for endpoint marker:

```bash
MARKER="paste_marker_here"
docker exec -i rsiem-timescale psql -U rsiem -d rsiem -t -A -F '|' -c \
"SELECT node_id, source_type, event_type, src_ip, user_name, recv_ts_unix_ms
 FROM normalized_events
 WHERE user_name='${MARKER}'
 ORDER BY recv_ts_unix_ms DESC
 LIMIT 1;"
```

Detector/master logs for marker:

```bash
MARKER="paste_marker_here"
rg "\"msg\":\"detector_rule_matched\".*\"user\":\"${MARKER}\"" logs/detector.log
rg "\"msg\":\"response_run_created\"|\"msg\":\"response_step_published\"|\"msg\":\"response_step_result_received\"" logs/master-roe.log
```

Targeted step publish (per-agent routing via `target_agent_id`, subject `rsiem.response.steps.fast`):

```bash
RUN_ID="pilot_target_$(date -u +%Y%m%d%H%M%S)"
STEP_ID="pilot_step_01"
TARGET_AGENT_ID="linux-endpoint-01"
TARGET_VALUE="<TARGET_IP_OR_HOST>"
nats --server "$NATS_URL" pub rsiem.response.steps.fast "$(jq -nc \
  --arg run_id "$RUN_ID" \
  --arg step_id "$STEP_ID" \
  --arg target_agent_id "$TARGET_AGENT_ID" \
  --arg target_value "$TARGET_VALUE" \
  '{run_id:$run_id,step_id:$step_id,step_index:0,action_type:"agent_command",lane:"FAST",step_idem_key:("step."+$run_id+"."+$step_id),attempt:0,target:$target_value,target_agent_id:$target_agent_id,params:{command:"contain_bruteforce_ip",marker_file:"pilot_targeting.txt"}}')"
echo "RUN_ID=$RUN_ID STEP_ID=$STEP_ID TARGET_AGENT_ID=$TARGET_AGENT_ID"
```

Worker/agent execution evidence:

```bash
rg "\"run_id\":\"${RUN_ID}\"" logs/worker.log | rg "rsiem\\.agent\\.command\\.${TARGET_AGENT_ID}" | tail -n 20
sudo journalctl -u rsiem-agent -n 400 --no-pager | rg "${RUN_ID}" | rg "agent_command_exec_start" || true
```

Expected:
- DB row shows `node_id=linux-endpoint-01` and non-empty `source_type`/`event_type`
- Worker requests `rsiem.agent.command.linux-endpoint-01`
- Endpoint agent logs one execution for the targeted run

## 5) Shutdown

On Host A:

```bash
./scripts/deploy/master/master_down.sh
```
