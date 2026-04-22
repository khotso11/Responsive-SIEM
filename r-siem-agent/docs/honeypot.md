# Honeypot Service

R-SIEM now includes a live deception service at `cmd/honeypot/main.go`.

## What It Does

The service exposes decoy listeners and publishes real interaction events into the existing JetStream raw-event subject (`rsiem.events.raw`). Those events carry the existing FR-03 deception marker `attack=deception_tripwire`, so they flow through the current detector and ROE path without requiring a separate ingestion plane.

## Default Decoy Services

The default config in `configs/honeypot.yaml` enables:

- `decoy-admin-http` on `127.0.0.1:18081`
- `decoy-ssh` on `127.0.0.1:2222`
- `decoy-telnet` on `127.0.0.1:2323`

All defaults bind to loopback to keep the demo safe by default. Change `listen` addresses explicitly if you want remote reachability in a lab.

## Published Event Shape

The honeypot publishes raw events with these key fields:

- `event_idem_key`
- `observed_at_unix_ms`
- `event_ts_unix_ms`
- `recv_ts_unix_ms`
- `message`
- `raw_line`
- `line`
- `host`
- `node_id`
- `source`
- `source_type=deception`
- `event_type=auth_failed`
- `group_key`
- `src_ip`
- `dst_ip`
- `dst_port`
- `protocol_family`
- `user`
- `session_id`
- `target_agent_id`

The detector matches on the message marker and emits:

- `R-FR03-DECEPTION-TRIPWIRE` for the initial tripwire event
- `R-DECEPTION-HONEYPOT-PROBE-BURST-SRCIP` when the same `src_ip` trips the honeypot repeatedly inside the escalation window

## ROE Mapping

`configs/master.yaml` now maps:

- `R-FR03-DECEPTION-TRIPWIRE` -> `PB-DECEPTION-HONEYPOT-TRIAGE`
- `R-DECEPTION-HONEYPOT-PROBE-BURST-SRCIP` -> `PB-DECEPTION-HONEYPOT-SOURCE-CONTAIN`

Current behavior:

- lane: `FAST`
- tripwire playbook approval mode: `required_for_critical`
- tripwire step set: one `notify` step after approval
- repeated-source escalation approval mode: `required_for_critical`
- repeated-source escalation step set:
  - `network_block` on the repeated probe `src_ip` with ingress direction
  - `notify`
- manual response actions become operable in the UI when `response_target_agent_id` points at a real enrolled agent

## Response Targeting

`configs/honeypot.yaml` supports:

- `response_target_agent_id`

This value is copied into each deception event as `target_agent_id`, which lets the incident/action layer target a real agent for manual containment from `/honeypot`, `/incidents`, or `/actions`.

The local demo script writes this field automatically to the active local endpoint agent ID.

## Running It

Direct run:

```bash
cd ~/projects/r-siem-agent
GOCACHE=$PWD/.cache/go-build go run -mod=vendor ./cmd/honeypot -config configs/honeypot.yaml
```

Optional integration with the local endpoint demo start:

```bash
cd ~/projects/r-siem-agent
START_HONEYPOT=1 REAL_SYSTEM=1 UI_WEB_PORT=3100 ./scripts/demo_local_endpoint_clean_start.sh
```

## Verifying It

`./scripts/verify_fr04.sh` now starts the live honeypot, generates a real HTTP interaction, captures PCAP evidence, and checks for:

- detector evidence for `R-FR03-DECEPTION-TRIPWIRE`
- ROE evidence for the deception playbook path
- chain-of-custody JSON and proof JSON under `demo_artifacts/<timestamp>/fr04/`

`./scripts/verify_honeypot_burst.sh` starts the live honeypot, sends repeated probes from the same `src_ip`, and checks for:

- detector evidence for `R-DECEPTION-HONEYPOT-PROBE-BURST-SRCIP`
- ROE evidence for `PB-DECEPTION-HONEYPOT-SOURCE-CONTAIN`
- proof JSON under `demo_artifacts/<timestamp>/honeypot_burst/`

## Test-Safe Source Override

For deterministic verifier runs, the HTTP service accepts `X-RSIEM-Source-IP` and `X-Forwarded-For`. If a valid IP is present, that value becomes the published `src_ip`. This is used to avoid detector cooldown collisions during repeated localhost-based test runs.
