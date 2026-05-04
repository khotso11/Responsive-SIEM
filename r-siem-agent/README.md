# R-SIEM

## Project Overview
R-SIEM is a response-capable SIEM pipeline built around deterministic ingestion, detection, approval-gated response orchestration, and proof-driven verification. This repository is evidence-first: delivery is validated by running canonical verifier scripts, checking required `PASS:` lines, and collecting machine-readable proof artifacts under `demo_artifacts/<timestamp>/...`.

The current implementation includes:

- telemetry collectors for tail, syslog, NetFlow v5, SNMP trap, auditd, inotify, `/proc/net`, and DNS
- endpoint agent transport with batching, WAL durability, and gRPC mTLS delivery
- detector rules, incident creation, and response orchestration
- analyst and admin UI workflows through `cmd/ui-api` and `ui/`
- retention, export, signing, rotation, and evidence-backed verifier scripts

## Core Manuals

For consolidated operational documentation, use:

- `docs/system_manual.md`
- `docs/system_testing_manual.md`

These two documents are the recommended starting point for:

- system setup and daily operation
- live-demo preparation
- functional verification and evidence capture

Additional public-facing references:

- `docs/deploy/master_setup.md`
- `docs/deploy/linux_endpoint_setup.md`
- `docs/deploy/windows_endpoint_setup.md`
- `docs/fr06_ui.md`

## High-Level Architecture & Data Flow
```text
collector-tail / collector-syslog / collector-netflowv5 / collector-snmptrap
        -> rsiem.events.raw (RSIEM_EVENTS stream)
        -> detector-v0
        -> ROE master (master-roe)
        -> approval (rsiem.response.approvals)
        -> ROE worker (master-roe-worker)
        -> agent
        -> response results + exports (exports/roe_*.jsonl)
        -> retention store (retained/*.jsonl) + retention-query
        -> optional DB sink (Timescale/Postgres: normalized_events)
```

Key components:
- `cmd/collector-tail`
- `cmd/collector-syslog`
- `cmd/collector-netflowv5`
- `cmd/collector-snmptrap`
- `cmd/collector-auditd`
- `cmd/collector-inotify`
- `cmd/collector-procnet`
- `cmd/collector-dns`
- `cmd/detector-v0`
- `cmd/master`
- `cmd/master-consume`
- `cmd/master-roe`
- `cmd/master-roe-worker`
- `cmd/agent`
- `cmd/ui-api`
- `ui/`
- `cmd/retention-query`
- `scripts/db_up.sh` / `scripts/db_down.sh` (Timescale Docker for DB proofs)

Evidence locations:
- Runtime logs: `logs/*.log`
- Response exports: `exports/roe_runs.jsonl`, `exports/roe_steps.jsonl`
- Retention store: `retained/*.jsonl`
- Proof artifacts: `demo_artifacts/<timestamp>/...`

## Quick Start
### Prerequisites
- `go`
- `docker`
- `nats` CLI
- `rg`
- `jq`
- `openssl` (FR-02 TLS proof)
- `tcpdump` (FR-04 and FR-02 TLS pcap proof)
- `systemd` for Linux endpoint service flows

Optional but commonly used for live endpoint and demo proofs:

- `nmap`
- `openssh-server`

### Start/Stop Stack
```bash
cd ~/projects/r-siem-agent
./scripts/demo_up.sh
./scripts/demo_down.sh
```

Notes:
- `demo_up.sh` expects NATS reachable on `127.0.0.1:4222`.
- Proof scripts write logs and artifacts deterministically; do not delete active artifacts mid-run.

### Start/Stop UI

```bash
./scripts/ui_up.sh
./scripts/ui_down.sh
```

Expected startup output:

```text
PASS: FR-06 UI services started
UI_WEB_URL=http://127.0.0.1:3200
UI_API_URL=http://127.0.0.1:8090
```

## Proof-Driven Workflow
Definition of done for each FR proof:
1. Run canonical script.
2. Confirm required `PASS:` line(s).
3. Capture printed proof pointer key(s), e.g. `FR03_PROOF_JSON=...`.
4. Verify referenced artifact file exists under `demo_artifacts/<timestamp>/...`.

Timestamped artifact dirs are part of reproducibility and auditability. Keep the exact path strings from script output in reports.

## Functional Requirements (FR) Matrix
### FR-01 — Telemetry Ingestion + Normalization + Streaming (COMPLETE)
What this proves:
- Distinct nodes observed up to 15 (`node-01..node-15`)
- Source types present and decoded (`tail`, `syslog`, `netflow_v5`, `snmp_trap`)
- Endpoint event taxonomy present (`auth_failed`, `process_exec`, `file_change`)
- Store boundary latency verified against DB (`normalized_events`) with threshold `<= 5000 ms`

Run:
```bash
./scripts/verify_fr01_acceptance.sh
```

Expected PASS lines:
```text
PASS: FR-01 acceptance completed
FR01_ACCEPTANCE_PROOF_JSON=demo_artifacts/.../fr01_acceptance/fr01_acceptance_proof.json
```

Proof artifact key(s):
- `FR01_ACCEPTANCE_PROOF_JSON=...`

Supporting streaming proofs:
```bash
./scripts/verify_fr01_streaming_phase1.sh
./scripts/verify_fr01_snmptrap.sh
```
Keys:
- `FR01_STREAMING_PHASE1_PROOF_JSON=...`
- `FR01_SNMPTRAP_PROOF_JSON=...`

Store used by acceptance:
- Timescale/Postgres `normalized_events` (started via `scripts/db_up.sh`).

### FR-02 — Secure Transport + Hardening + DB Completeness (COMPLETE)
Run core suite:
```bash
./scripts/verify_fr02_full.sh
```

Expected PASS lines:
```text
PASS: FR-02 full suite completed
PASS: FR-02 ROTATION REHEARSAL completed
PASS: FR-02 REVOCATION WORKFLOW completed
```

Proof artifact key(s) from suite:
- `FR02_PROOF_JSON=...` (mTLS proof)
- `FR02_ROTATION_PROOF_JSON=...`
- `FR02_REVOCATION_PROOF_JSON=...`

TLS 1.3 packet-capture proof:
```bash
./scripts/verify_fr02_tls13_pcap.sh
```
Expected lines:
```text
PASS: FR-02 TLS1.3 pcap completed
FR02_TLS13_PCAP_PROOF_JSON=demo_artifacts/.../fr02_tls13_proof.json
```

DB 1-hour completeness proof:
```bash
./scripts/verify_fr02_db_1hour.sh
```
Expected lines:
```text
PASS: FR-02 DB 1hour completeness completed
FR02_DB_1HOUR_PROOF_JSON=demo_artifacts/.../fr02_db_1hour_proof.json
```

### FR-03 — Correlation + Severity + Latency (COMPLETE)
Run:
```bash
./scripts/verify_fr03.sh
```

Expected lines:
```text
PASS: FR-03 correlation+severity+latency completed
FR03_PROOF_JSON=demo_artifacts/.../fr03_latency_proof.json
```

Proof artifact key(s):
- `FR03_PROOF_JSON=...`

### FR-04 — Deception + PCAP + Chain of Custody (COMPLETE)
Run:
```bash
./scripts/verify_fr04.sh
```

Expected lines:
```text
PASS: FR-04 live honeypot+pcap+chain_of_custody completed
FR04_PROOF_JSON=demo_artifacts/.../fr04/fr04_proof.json
```

Proof artifact key(s):
- `FR04_PROOF_JSON=...`

Required FR-04 artifacts in same directory:
- `capture.pcap`
- `chain_of_custody.json`
- `fr04_proof.json`

### FR-05 — Response Safety (Rollback + FAILED_SAFE + Audit Fields + Tests) (COMPLETE)
Run workflow proof:
```bash
./scripts/verify_fr05_full.sh
```

Expected lines:
```text
PASS: FR-05 full suite completed
FR05_SUCCESS_PROOF_JSON=demo_artifacts/.../fr05_success_proof.json
FR05_FAILED_SAFE_PROOF_JSON=demo_artifacts/.../fr05_failed_safe_proof.json
```

Proof artifact key(s):
- `FR05_SUCCESS_PROOF_JSON=...`
- `FR05_FAILED_SAFE_PROOF_JSON=...`

Acceptance proof (audit fields + tests):
```bash
./scripts/verify_fr05_acceptance.sh
```
Expected lines:
```text
PASS: FR-05 acceptance completed
FR05_ACCEPTANCE_PROOF_JSON=demo_artifacts/.../fr05_acceptance_proof.json
```

Verifier behavior note:
- FR05 success path uses deterministic step-level evidence to avoid run-status timing flake; run-level SUCCEEDED is best-effort and may log a warning without failing when step evidence is complete.

### FR-07 — Signing/Verification + Rotation (COMPLETE)
Run:
```bash
./scripts/verify_fr07_full.sh
```

Expected lines:
```text
PASS: FR-07 signing+verification completed
FR07_SIGNING_PROOF_JSON=demo_artifacts/.../fr07_signing_proof.json
PASS: FR-07 rotation completed
FR07_ROTATION_PROOF_JSON=demo_artifacts/.../fr07_rotation_proof.json
PASS: FR-07 full suite completed
```

Proof artifact key(s):
- `FR07_SIGNING_PROOF_JSON=...`
- `FR07_ROTATION_PROOF_JSON=...`

### FR-08 — Retention + Query + Export (COMPLETE)
Retention/query/export base proof:
```bash
./scripts/verify_fr08_retention.sh
```
Expected lines:
```text
PASS: FR-08 retention+query+export completed
FR08_PROOF_JSON=demo_artifacts/.../fr08_retention_proof.json
```

Acceptance proof:
```bash
./scripts/verify_fr08_acceptance.sh
```
Expected lines:
```text
PASS: FR-08 acceptance completed
FR08_ACCEPTANCE_PROOF_JSON=demo_artifacts/.../fr08_acceptance_proof.json
```

Proof artifact key(s):
- `FR08_PROOF_JSON=...`
- `FR08_ACCEPTANCE_PROOF_JSON=...`

Example retention query:
```bash
go run -mod=vendor ./cmd/retention-query query --type runs --status FAILED_SAFE --format jsonl
```

### FR-06 — SOC UI + API (COMPLETE)
Run:
```bash
./scripts/ui_up.sh
./scripts/verify_fr06_ui_smoke.sh
```

Expected lines:
```text
PASS: FR-06 UI services started
PASS: FR-06 UI smoke completed
FR06_UI_PROOF_JSON=demo_artifacts/.../fr06_ui/fr06_ui_proof.json
```

Proof artifact key(s):
- `FR06_UI_PROOF_JSON=...`

UI/API reference:
- `cmd/ui-api`
- `ui/`
- `docs/fr06_ui.md`

## Full End-to-End Demo (One Command)
Run:
```bash
./scripts/verify_full_demo_suite.sh
```

Expected final line:
```text
PASS: full demo suite completed
```

This wrapper executes multiple proof stages and prints artifact pointers such as:
- `FR02_ROTATION_PROOF_JSON=...`
- `FR02_REVOCATION_PROOF_JSON=...`
- `FR05_SUCCESS_PROOF_JSON=...`
- `FR05_FAILED_SAFE_PROOF_JSON=...`
- `NEW_PLAYBOOKS_PROOF_JSON=...`
- `FR03_PROOF_JSON=...`
- `FR04_PROOF_JSON=...`

Stability check:
```bash
./scripts/verify_full_demo_suite.sh
./scripts/verify_full_demo_suite.sh
```

## Troubleshooting
### NATS not reachable
```bash
nats --server nats://127.0.0.1:4222 pub rsiem.health.check '{"ping":1}'
```
If missing:
```bash
docker rm -f nats >/dev/null 2>&1 || true
docker run -d --name nats --network host nats:2 -js
```

### Docker name conflicts
If `docker run --name nats ...` fails with conflict:
```bash
docker rm -f nats
docker run -d --name nats --network host nats:2 -js
```

### Timescale container issues (`rsiem-timescale`)
```bash
./scripts/db_down.sh
./scripts/db_up.sh
```

### TLS/PCAP permissions (`verify_fr02_tls13_pcap.sh`, `verify_fr04.sh`)
- If capture fails due permissions, run with `sudo` and verify artifact ownership/permissions afterward.

### Ports busy / stale processes
```bash
./scripts/demo_down.sh
pkill -f 'master-roe|master-roe-worker|detector-v0|collector-tail|agent' || true
./scripts/demo_up.sh
```

### Safe cleanup guidance
- Do not remove active `demo_artifacts/<timestamp>/...` during a running proof.
- Prefer creating new runs and preserving prior artifacts for audit traceability.

### UI ports
- The current default UI web port is `3200`.
- The current default UI API address is `127.0.0.1:8090`.

## Repo Navigation
- Commands/binaries: `cmd/*`
- Internal logic: `internal/*`
- Runtime scripts: `scripts/*`
- Configs: `configs/*`
- Logs: `logs/*`
- Exports: `exports/*`
- Retained data: `retained/*`
- Proof artifacts: `demo_artifacts/<timestamp>/*`
