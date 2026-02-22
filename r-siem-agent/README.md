# R-SIEM Agent (Current Runbook)

This README is the current operator guide for running and proving the local R-SIEM stack.

## What You Can Prove Right Now

- **FR-01**: minimal telemetry slice with checkpoint/resume and auth.log override proof.
- **FR-02**: mTLS hardening, cert-derived identity, allowlist accept/reject, rotation rehearsal, and revocation workflow proofs.
- **FR-05**: rollback success + safe partial-failure operator guidance proofs.
- **FR-08**: bounded retention + query + export proof over retained local records.

## Repository Root

```bash
cd ~/projects/r-siem-agent
```

## Prerequisites

- Go (project uses `go run` / `go build` with vendored deps)
- `rg` (ripgrep)
- `nats` CLI (required by `scripts/demo_up.sh` precheck)
- `openssl` (required by FR-02 verification scripts)
- NATS JetStream reachable on `127.0.0.1:4222`

## Start NATS (Local)

```bash
docker rm -f nats >/dev/null 2>&1 || true
docker run -d --name nats --network host nats:2 -js
```

## Current Proof Flow

### Fast full suite

```bash
./scripts/verify_full_demo_suite.sh
```

Expected final line:

```text
PASS: full demo suite completed
```

### FR-08 proof (retention + query + export)

```bash
./scripts/verify_fr08_retention.sh
```

Expected final lines:

```text
PASS: FR-08 retention+query+export completed
FR08_PROOF_JSON=demo_artifacts/.../fr08_retention_proof.json
```

### Focused sequence (5 minutes)

```bash
./scripts/verify_fr01.sh
./scripts/verify_fr02_full.sh
./scripts/verify_fr05_full.sh
./scripts/verify_fr08_retention.sh
```

## Key Scripts (Current)

- `scripts/demo_up.sh`: start core services and print live demo guide
- `scripts/demo_down.sh`: stop services started by `demo_up.sh`
- `scripts/verify_fr01.sh`: FR-01 verification + `demo_summary.json`
- `scripts/verify_fr02_mtls.sh`: FR-02 mTLS checks (t1..t7)
- `scripts/verify_fr02_rotation.sh`: FR-02 cert rotation rehearsal proof
- `scripts/verify_fr02_revocation.sh`: FR-02 allowlist revocation proof
- `scripts/verify_fr02_full.sh`: FR-02 wrapper
- `scripts/verify_fr05_full.sh`: FR-05 wrapper
- `scripts/verify_new_playbooks.sh`: additional playbook proof batch
- `scripts/verify_full_demo_suite.sh`: one-command combined suite
- `scripts/verify_fr08_retention.sh`: FR-08 retention/query/export proof

## Proof Artifacts To Present

- `demo_artifacts/<timestamp>/demo_summary.json`
- `demo_artifacts/<timestamp>/fr02_mtls_proof.json`
- `demo_artifacts/<timestamp>/fr02_rotation_proof.json`
- `demo_artifacts/<timestamp>/fr02_revocation_proof.json`
- `demo_artifacts/<timestamp>/fr05_success_proof.json`
- `demo_artifacts/<timestamp>/fr05_failed_safe_proof.json`
- `demo_artifacts/<timestamp>/new_playbooks_proof.json`
- `demo_artifacts/<timestamp>/fr08_retention_proof.json`

## Runtime Evidence Sources

- Logs: `logs/master-roe.log`, `logs/worker.log`, `logs/agent.log`, `logs/detector.log`, `logs/collector.log`
- Exports: `exports/roe_steps.jsonl`, `exports/roe_runs.jsonl`
- Retained local store: `retained/*.jsonl`

## Troubleshooting

### NATS precheck fails in `demo_up.sh`

Ensure NATS is reachable:

```bash
nats pub rsiem.demo.precheck "{\"ts\":$(date +%s)}"
```

### FR-02 process/port conflicts

```bash
pkill -f 'tmp/fr02_mtls/master' || true
pkill -f 'tmp/fr02_mtls/agent' || true
./scripts/verify_fr02_mtls.sh
```

### Verify only script-level outcome quickly

```bash
LATEST_DIR="$(ls -1dt /tmp/rsiem-proof-* 2>/dev/null | head -n1)"
rg -n '^FAIL:|^PASS:' "$LATEST_DIR"/*.log
```

## Related Docs

- `docs/fr02_mtls_runbook.md`
- `docs/presentations/2026-02-19-supervisor/README.md`
- `docs/presentations/2026-02-19-supervisor/NARRATIVE_REPORT.md`
