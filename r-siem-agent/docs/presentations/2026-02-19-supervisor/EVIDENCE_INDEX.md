# Evidence Index (2026-02-19)

| Evidence ID | Screenshot filename | FR(s) supported | Trigger/Command | Expected outcome | What it proves |
|---|---|---|---|---|---|
| E01 | `01_FR01_verify_summary.png` | FR-01 | `./scripts/verify_fr01.sh` | Output contains `=== FR-01 SUMMARY ===` and `PASS: FR-01 local verification completed`. | FR-01 minimal slice verification completes successfully. |
| E02 | `02_FR01_checkpoint_authlog.png` | FR-01 | `./scripts/verify_fr01.sh` | Output contains `PROOF_CHECKPOINT:` and `PROOF_AUTHLOG_OVERRIDE:` lines. | Collector checkpoint resume is restart-safe and auth.log override path is resolved. |
| E03 | `03_FR08_demo_summary_json.png` | FR-08, FR-01 | `./scripts/verify_fr01.sh` then `cat demo_artifacts/<latest>/demo_summary.json` | `DEMO_SUMMARY_JSON:` points to a JSON file with FR-01/FR-05 summary data. | FR-08 polish artifact exists and is machine-readable for supervisor review. |
| E04 | `04_FR02_mtls_summary.png` | FR-02 | `./scripts/verify_fr02_mtls.sh` | `=== FR-02 mTLS SUMMARY ===` with `t1..t7=PASS`, `fr02_status=PASS`, and `agent_id_source=cert_cn|cert_san`. | mTLS verifier passes all planned checks and identity source is certificate-derived. |
| E05 | `05_FR02_mtls_negative_tests.png` | FR-02 | `./scripts/verify_fr02_mtls.sh` | Negative checks for no client cert, unknown CA, and identity mismatch are shown as PASS with matching log evidence. | Master rejects invalid mTLS clients deterministically for key failure modes. |
| E06 | `06_FR02_allowlist_reject.png` | FR-02 | `./scripts/verify_fr02_mtls.sh` | Output/log includes `grpc_mtls_client_rejected` with `reason=fingerprint_not_allowlisted`. | Fingerprint allowlist enforcement is active and deny path is proven. |
| E07 | `07_FR05_rollback_success.png` | FR-05 | `./scripts/verify_fr01.sh` (FR-05 regression inside) or `./scripts/demo_fr05.sh` | FR-05 success proof line and run-level `SUCCEEDED` evidence for `PB-QUARANTINE-ROLLBACK-DEMO`. | Quarantine rollback success path is operational and auditable. |
| E08 | `08_FR05_partial_failure_safe.png` | FR-05 | `./scripts/verify_fr01.sh` (FR-05 regression inside) or `./scripts/demo_fr05.sh` | Partial-failure proof line with run-level `FAILED_SAFE` and `manual_restore_check_recommended`. | Safe terminal handling for partial completion is explicit and operator-guided. |

## Screenshot Copy Status

Auto-scan from repo root for the eight PNG files completed. Current result:

- Missing at scan time: all eight filenames (none were found under repo root).
- Destination folder prepared: `docs/presentations/2026-02-19-supervisor/screenshots/`

When PNG files are added to the repo, re-copy into the destination folder and this index remains valid.
