# Supervisor Presentation Pack (2026-02-19)

This pack contains the supervisor-facing narrative and strict evidence mapping for today’s proven demo scope.

## Contents

- `NARRATIVE_REPORT.md` - requirement-by-requirement status and implementation narrative
- `EVIDENCE_INDEX.md` - strict E01..E08 map from screenshot to proof claim
- `screenshots/` - copied screenshot files (PNG), when present in repo scan

## Scripts Used Today

- `./scripts/demo_up.sh`
- `./scripts/verify_fr01.sh`
- `./scripts/verify_fr02_mtls.sh`
- Optional manual approval command:
  - `nats pub rsiem.response.approvals '{"run_id":"<RUN_ID>","decision":"approve","actor":"khotso"}'`

## JSON Artifacts To Show

- `demo_artifacts/<latest>/demo_summary.json` (FR-01 / FR-08)
- `demo_artifacts/<latest>/fr02_mtls_proof.json` (FR-02)

## Screenshot Folder

- Target folder: `docs/presentations/2026-02-19-supervisor/screenshots/`
- Auto-copy rule: search by exact filename from repo root and copy if found.

Expected screenshot filenames:

- `01_FR01_verify_summary.png`
- `02_FR01_checkpoint_authlog.png`
- `03_FR08_demo_summary_json.png`
- `04_FR02_mtls_summary.png`
- `05_FR02_mtls_negative_tests.png`
- `06_FR02_allowlist_reject.png`
- `07_FR05_rollback_success.png`
- `08_FR05_partial_failure_safe.png`

## Live Demo Checklist

- Confirm NATS is up (`127.0.0.1:4222`).
- Run `./scripts/demo_up.sh`.
- Run `./scripts/verify_fr01.sh` and show:
  - FR-01 summary PASS
  - PROOF_CHECKPOINT and PROOF_AUTHLOG_OVERRIDE
  - `DEMO_SUMMARY_JSON` path
- Run `./scripts/verify_fr02_mtls.sh` and show:
  - t1..t7 PASS
  - cert-derived identity source (`cert_cn` or `cert_san`)
  - fingerprint allowlist rejection evidence
- Open `EVIDENCE_INDEX.md` and map each screenshot to its FR claim.
