# Supervisor Presentation Pack (2026-02-19)

This pack contains the supervisor-facing narrative, evidence index, and screenshot mapping for the currently proven R-SIEM scope.

## Contents

- `NARRATIVE_REPORT.md` - FR-by-FR narrative and current implementation status
- `EVIDENCE_INDEX.md` - strict E01..E08 screenshot-to-claim map
- `screenshots/` - copied screenshot files used in presentation proofs

## Current Proof Commands

- `./scripts/verify_fr01.sh`
- `./scripts/verify_fr02_full.sh`
- `./scripts/verify_fr05_full.sh`
- `./scripts/verify_new_playbooks.sh`
- `./scripts/verify_full_demo_suite.sh`
- `./scripts/verify_fr08_retention.sh`

Optional manual approval command (when running focused/manual slices):

- `nats pub rsiem.response.approvals '{"run_id":"<RUN_ID>","decision":"approve","actor":"khotso"}'`

## JSON Artifacts To Show

- `demo_artifacts/<latest>/demo_summary.json` (FR-01 summary artifact)
- `demo_artifacts/<latest>/fr02_mtls_proof.json` (FR-02 mTLS + negatives + allowlist checks)
- `demo_artifacts/<latest>/fr02_rotation_proof.json` (FR-02 cert rotation rehearsal)
- `demo_artifacts/<latest>/fr02_revocation_proof.json` (FR-02 allowlist-based revoke/re-allow proof)
- `demo_artifacts/<latest>/fr05_success_proof.json` (FR-05 rollback success)
- `demo_artifacts/<latest>/fr05_failed_safe_proof.json` (FR-05 safe partial failure)
- `demo_artifacts/<latest>/new_playbooks_proof.json` (new playbooks batch proof)
- `demo_artifacts/<latest>/fr08_retention_proof.json` (FR-08 retention/query/export proof)

## Screenshot Folder

- Target folder: `docs/presentations/2026-02-19-supervisor/screenshots/`
- Expected files:
`01_FR01_verify_summary.png`, `02_FR01_checkpoint_authlog.png`, `03_FR08_demo_summary_json.png`, `04_FR02_mtls_summary.png`, `05_FR02_mtls_negative_tests.png`, `06_FR02_allowlist_reject.png`, `07_FR05_rollback_success.png`, `08_FR05_partial_failure_safe.png`

## Live Demo Checklist

- Ensure NATS is up on `127.0.0.1:4222`.
- Run `./scripts/verify_full_demo_suite.sh`.
- Confirm final line: `PASS: full demo suite completed`.
- Run `./scripts/verify_fr08_retention.sh`.
- Confirm final lines:
`PASS: FR-08 retention+query+export completed` and `FR08_PROOF_JSON=...`
- Open `EVIDENCE_INDEX.md` and map each screenshot to the claim shown in terminal output.

## Minimal 5-Minute Path

```bash
cd ~/projects/r-siem-agent
./scripts/verify_fr01.sh
./scripts/verify_fr02_full.sh
./scripts/verify_fr05_full.sh
./scripts/verify_fr08_retention.sh
```
