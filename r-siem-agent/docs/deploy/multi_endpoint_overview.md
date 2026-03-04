# Multi-Endpoint Deployment Overview

This deployment pack supports one **MASTER** host and multiple **ENDPOINT** hosts without changing runtime behavior.

- MASTER host runs: NATS JetStream, `master-roe`, `master-roe-worker`, `detector-v0`, and TimescaleDB (`rsiem-timescale`).
- ENDPOINT hosts run: `agent` and selected collectors (`collector-tail` minimum, plus `collector-syslog` / `collector-netflowv5` / `collector-snmptrap` where needed).
- Command targeting uses existing Hybrid Option A behavior:
  - legacy subject: `rsiem.agent.command`
  - deterministic per-agent subject: `rsiem.agent.command.<agent_id>`

## Architecture

```text
ENDPOINTS
  collector-tail / collector-syslog / collector-netflowv5 / collector-snmptrap
       |
       v
  NATS subject: rsiem.events.raw  ->  stream: RSIEM_EVENTS
       |
       v
  detector-v0 (master)
       |
       v
  NATS subjects: rsiem.response.triggers.fast|standard  ->  stream: RSIEM_RESPONSE
       |
       v
  master-roe (run/approval orchestration)
       |
       +--> approvals: rsiem.response.approvals
       |
       +--> steps: rsiem.response.steps.fast|standard
                    |
                    v
              master-roe-worker
                    |
                    v
              agent command bus:
                - rsiem.agent.command
                - rsiem.agent.command.<agent_id>
                    |
                    v
                endpoint agent(s)
                    |
                    v
              step results -> rsiem.response.results.fast|standard

Data outputs:
  - exports/roe_runs.jsonl
  - exports/roe_steps.jsonl
  - retained/*.jsonl
  - Timescale table: normalized_events
```

## Control Plane Placement

MASTER-only services:
- NATS JetStream
- `master-roe`
- `master-roe-worker`
- `detector-v0`
- TimescaleDB

ENDPOINT services:
- `agent`
- one or more collectors

## Network Paths and Ports

Required endpoint -> master paths:
- TCP `4222`: NATS client connectivity.
- TCP `7777` (default from `configs/master.yaml`): gRPC mTLS transport to master.

Optional local-only on master:
- TCP `5432`: TimescaleDB (can stay restricted to localhost).

Recommended network policy:
- Allow outbound from endpoints to master only.
- Avoid inbound listeners on endpoints.

## Per-Endpoint Identity Requirements

Each endpoint must have unique values:
- `agent.instance_id` (used for per-agent command subject and cert identity).
- collector `node_id` (use same value as `agent.instance_id` unless there is a reason to separate).
- WAL/log paths must be endpoint-local and unique per service.

## Per-Endpoint Configuration Matrix

| Endpoint | agent.instance_id | collector node_id | NATS URL | Master gRPC mTLS addr | Cert paths | WAL path | Collector source path |
|---|---|---|---|---|---|---|---|
| Linux endpoint 1 | `linux-endpoint-01` | `linux-endpoint-01` | `nats://<MASTER_IP>:4222` | `<MASTER_IP>:7777` | `/etc/rsiem/pki/{ca.pem,agent.pem,agent-key.pem}` | `/var/lib/rsiem/agent.wal` | `/var/log/auth.log` (or chosen file) |
| Linux endpoint 2 | `linux-endpoint-02` | `linux-endpoint-02` | `nats://<MASTER_IP>:4222` | `<MASTER_IP>:7777` | `/etc/rsiem/pki/{ca.pem,agent.pem,agent-key.pem}` | `/var/lib/rsiem/agent.wal` | endpoint-specific tail file |
| Windows endpoint 1 | `win-endpoint-01` | `win-endpoint-01` | `nats://<MASTER_IP>:4222` | `<MASTER_IP>:7777` | `C:\\ProgramData\\rsiem\\pki\\{ca.pem,agent.pem,agent-key.pem}` | `C:\\ProgramData\\rsiem\\wal\\agent.wal` | `C:\\ProgramData\\rsiem\\logs\\endpoint.log` |

## Store Boundary for Submission Evidence

Current store boundaries in this repo:
- `normalized_events` (TimescaleDB, used by FR-01/FR-02 acceptance proofs).
- `exports/roe_runs.jsonl` and `exports/roe_steps.jsonl` (ROE result exports).
- `retained/*.jsonl` (retention subsystem output).

## Deployment Pack Files

- Master: `scripts/deploy/master/master_up_lan.sh`, `scripts/deploy/master/master_down.sh`
- Linux endpoints: `scripts/deploy/linux/install_endpoint.sh` + systemd units
- Windows endpoints: `scripts/deploy/windows/install_endpoint.ps1`, `scripts/deploy/windows/uninstall_endpoint.ps1`
- Onboarding and pilot runbooks:
  - `docs/deploy/certs_allowlist_onboarding.md`
  - `docs/deploy/master_setup.md`
  - `docs/deploy/linux_endpoint_setup.md`
  - `docs/deploy/windows_endpoint_setup.md`
  - `docs/deploy/two_host_pilot.md`
