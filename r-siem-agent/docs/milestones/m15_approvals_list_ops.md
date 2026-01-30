# M15 Approvals List Ops

Milestone: **List pending approvals with lane/age filters and deterministic ordering**

## Preconditions

- exports/roe_runs.jsonl exists
- master-roe is writing run updates to exports/roe_runs.jsonl

## Commands

List all pending approvals (oldest first):

```bash
go run -mod=vendor ./cmd/master-roe-approvals-list -path exports/roe_runs.jsonl
```

List only FAST approvals older than 5 minutes (newest first):

```bash
go run -mod=vendor ./cmd/master-roe-approvals-list -lane FAST -older-than 5m -sort newest
```

List only STANDARD approvals, limit 3:

```bash
go run -mod=vendor ./cmd/master-roe-approvals-list -lane STANDARD -limit 3
```

## Expected output pattern

Each line should match:

```
run_id=<run_id> rule_id=<rule_id> playbook_id=<playbook_id> lane=<lane> created_at=<rfc3339> age=<duration> timeout_ms=<ms>
```

Only runs in WAITING_APPROVAL should be listed.
