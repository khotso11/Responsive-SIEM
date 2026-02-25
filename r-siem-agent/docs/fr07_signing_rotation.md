# FR-07 Signing and Rotation Runbook

This runbook covers deterministic signing, verification, and key rotation for FR-07.

## Scope

- Sign and verify rules/config bundles (current default root: `configs/`)
- Sign and verify event batch files (current default: `exports/roe_runs.jsonl`)
- Rotate HMAC keys and prove continued operation without data loss in staging

## Key Paths

- Active key: `pki/fr07/hmac/active.key`
- Rotated keys: `pki/fr07/hmac/rotated/<timestamp>.key`

## Initialize Key

```bash
go run -mod=vendor ./cmd/signctl init-key --key pki/fr07/hmac/active.key
```

## Bundle Signing and Verification

```bash
go run -mod=vendor ./cmd/signctl sign-bundle --bundle_root configs --out demo_artifacts/<ts>/bundle.sig.json
go run -mod=vendor ./cmd/signctl verify-bundle --bundle_root configs --sig demo_artifacts/<ts>/bundle.sig.json
```

## Batch Signing and Verification

```bash
go run -mod=vendor ./cmd/signctl sign-batch --in exports/roe_runs.jsonl --out demo_artifacts/<ts>/batch.sig.json
go run -mod=vendor ./cmd/signctl verify-batch --in exports/roe_runs.jsonl --sig demo_artifacts/<ts>/batch.sig.json
```

## Rotate Key

```bash
go run -mod=vendor ./cmd/signctl rotate-key --key pki/fr07/hmac/active.key --rotated_dir pki/fr07/hmac/rotated
```

After rotation, sign/verify commands must still pass with the new active key.

## Proof Scripts

- Signing + tamper rejection proof:

```bash
./scripts/verify_fr07_signing.sh
```

Output includes:

- `PASS: FR-07 signing+verification completed`
- `FR07_SIGNING_PROOF_JSON=...`

- Rotation + no-data-loss staging proof:

```bash
./scripts/verify_fr07_rotation.sh
```

Output includes:

- `PASS: FR-07 rotation completed`
- `FR07_ROTATION_PROOF_JSON=...`

- Full FR-07 wrapper:

```bash
./scripts/verify_fr07_full.sh
```

## Interpreting "No Data Loss"

In this repo, no-data-loss for FR-07 rotation means:

- `exports/roe_runs.jsonl` line count after rotation is not less than before
- `exports/roe_steps.jsonl` line count after rotation is not less than before
- signing and verification still succeed post-rotation and after additional activity generation
