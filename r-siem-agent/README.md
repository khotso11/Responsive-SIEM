# R-SIEM Agent (Current Runbook)

This README is the current operator guide for running and proving the local R-SIEM stack.

## What You Can Prove Right Now

- **FR-01 (Minimal telemetry slice)**: collector tail + detector + response path with checkpoint/resume and auth.log override proof.
- **FR-02 (mTLS hardening)**: agent↔master mTLS enforcement, cert identity source, and fingerprint allowlist acceptance/rejection proofs.
- **FR-05 (quarantine rollback demos)**: successful rollback and partial-failure audit path.

## Repository Root

Always run from:

```bash
cd ~/projects/r-siem-agent
```

## Prerequisites

- Go (project uses `go run` / `go build` with vendored deps)
- `rg` (ripgrep)
- `nats` CLI (required by `scripts/demo_up.sh` precheck)
- `openssl` (required by `scripts/verify_fr02_mtls.sh`)
- A running NATS JetStream server on `127.0.0.1:4222`

## Start NATS (Local)

If not already running:

```bash
docker run --rm --name nats --network host nats:2 -js
```

If container name conflicts:

```bash
docker rm -f nats
```

## Fastest End-to-End Path

### 1) Start full demo stack (master-roe + worker + agent + detector + collector)

```bash
./scripts/demo_up.sh
```

### 2) Run FR-05 supervisor demo

```bash
./scripts/demo_fr05.sh
```

Expected ending line:

```text
PASS: FR05 completed (safety + rollback + audit) run_id_ok=... run_id_fail=...
```

### 3) Run FR-01 verification artifact

```bash
./scripts/verify_fr01.sh
```

Expected ending lines include:

```text
PASS: FR-01 local verification completed
PROOF_CHECKPOINT: ...
PROOF_AUTHLOG_OVERRIDE: ...
DEMO_SUMMARY_JSON: demo_artifacts/.../demo_summary.json
```

### 4) Run FR-02 mTLS verification artifact

```bash
./scripts/verify_fr02_mtls.sh
```

Expected summary:

```text
=== FR-02 mTLS SUMMARY ===
server_started=PASS
t1=PASS
t2=PASS
t3=PASS
t4=PASS
t5=PASS
t6=PASS
t7=PASS
fr02_status=PASS
agent_instance_id=...
agent_id_source=cert_san|cert_cn
proof_log=demo_artifacts/.../fr02_mtls_proof.json
```

### 5) Stop stack started by `demo_up.sh`

```bash
./scripts/demo_down.sh
```

## Key Scripts (Current)

- `scripts/demo_up.sh`: start core services and print live demo guide
- `scripts/demo_down.sh`: stop services started by `demo_up.sh`
- `scripts/demo_fr05.sh`: FR-05 success + partial-failure proof flow
- `scripts/verify_fr01.sh`: FR-01 verification + JSON summary artifact
- `scripts/verify_fr02_mtls.sh`: FR-02 mTLS hardening verification + JSON proof
- `scripts/mf05_quarantine_rollback_proof.sh`: FR-05 success proof only
- `scripts/mf05_quarantine_partial_failure_proof.sh`: FR-05 partial-failure proof only

## Proof Artifacts and Logs

### Artifacts

- `demo_artifacts/<timestamp>/demo_summary.json` (FR-01)
- `demo_artifacts/<timestamp>/fr02_mtls_proof.json` (FR-02)

### Runtime logs

- `logs/master-roe.log`
- `logs/worker.log`
- `logs/agent.log`
- `logs/detector.log`
- `logs/collector.log`

### Export evidence

- `exports/roe_steps.jsonl`
- `exports/roe_runs.jsonl`

## Troubleshooting

### 1) `FAIL: master did not start with mTLS`

Usually port/process conflict from previous FR-02 runs. Clean and retry:

```bash
pkill -f 'tmp/fr02_mtls/master' || true
pkill -f 'tmp/fr02_mtls/agent' || true
./scripts/verify_fr02_mtls.sh
```

### 2) NATS precheck failure in `demo_up.sh`

You need NATS on `127.0.0.1:4222` and working `nats` CLI.

### 3) Confirm FR-02 cleanup state

```bash
pgrep -fa 'tmp/fr02_mtls/(master|agent)\.ya?ml|tmp/fr02_mtls/(master|agent)\.ok\.yaml' || true
ss -ltnp | rg '127.0.0.1:(2787[7-9]|2788[0-9])' || true
```

No output means clean.

## mTLS Lifecycle Note

See:

- `docs/fr02_mtls_lifecycle.md`

This includes CA signing model, rotation strategy, and compromise response steps.
