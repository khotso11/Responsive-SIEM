# FR-08 Sizing Guidance (Retained JSONL Store)

Sizing is controlled by:
- `RETAIN_MAX_BYTES`
- `RETAIN_MAX_AGE_SECONDS`

These values bound on-disk retained data (`retained/*.jsonl`) and query scan cost.

## Recommended node classes

### Small node
- Expected load: up to ~100 EPS
- `RETAIN_MAX_BYTES=52428800` (50 MB)
- `RETAIN_MAX_AGE_SECONDS=86400` (1 day)

### Medium node
- Expected load: ~100 to 500 EPS
- `RETAIN_MAX_BYTES=268435456` (256 MB)
- `RETAIN_MAX_AGE_SECONDS=259200` (3 days)

### Large node
- Expected load: ~500 to 2000 EPS
- `RETAIN_MAX_BYTES=1073741824` (1 GB)
- `RETAIN_MAX_AGE_SECONDS=604800` (7 days)

## Practical tuning rule

1. Start with the class above that matches current EPS.
2. Run `scripts/verify_fr08_retention.sh` and `scripts/verify_fr08_acceptance.sh`.
3. If query p95 approaches target limits, reduce retention age or bytes.
4. If compliance needs more history, increase bytes first, then age.
