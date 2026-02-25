# FR-08 Retention Query Schema

This document describes the retained query output fields for `cmd/retention-query`.

## JSONL output (`--format jsonl`, default)

Records are emitted as one JSON object per line from retained files (`alerts`, `runs`, `steps`, `telemetry`), preserving the retained record payload.

Core fields used across record types:
- `type`: record category (`alerts|runs|steps|telemetry`)
- `status`: run/step status where present (`SUCCEEDED|FAILED_SAFE|...`)
- `run_id`: response run identifier where present
- `playbook_id`: playbook identifier where present
- `ts_unix_ms`: record timestamp in epoch milliseconds
- `source`: source file path used during ingestion
- `line`: original raw line captured during ingestion

Additional fields may appear depending on type:
- `rule_id`, `severity` (alerts)
- `step_id` (steps)
- `event`, `operator_action`, `failed_safe_reason` (runs/telemetry)

## CSV output (`--format csv`)

CSV uses a stable header and stdlib CSV escaping:

`type,status,run_id,playbook_id,ts_unix_ms,source,rule_id,severity,event,step_id,operator_action,failed_safe_reason,line_sha256`

Notes:
- `line` is intentionally omitted to keep CSV bounded and terminal-friendly.
- `line_sha256` is included as a deterministic integrity pointer for the omitted raw line.
- Empty values are expected for fields not applicable to a record type.
