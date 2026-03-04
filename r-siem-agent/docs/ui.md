# FR-06 SOC Console UI

## Run

```bash
./scripts/ui_up.sh
```

Expected output:

```text
PASS: FR-06 UI services started
UI_WEB_URL=http://127.0.0.1:3000
UI_API_URL=http://127.0.0.1:8090
```

Stop:

```bash
./scripts/ui_down.sh
```

## Pages

- `Incidents`
  - SOC queue with stable sorting and pagination.
  - Multi-filter bar (status, lane, severity, node, playbook, rule, search).
  - Right-side investigation drawer with tabs:
    - Overview
    - Steps
    - Timeline (pivot by `user_name`, `src_ip`, `node_id`)
    - Evidence (export/copy bundle, artifact download)
    - Actions (approve/reject when waiting approval)
- `Endpoints`
  - Node last seen, event rates (5m/1h), source distribution.
  - Endpoint drawer with recent events/runs and targeted action test publish.
- `Audit`
  - Approval events grouped/highlighted.
  - Search and time-filtered audit stream.

## API notes

The UI talks only to `cmd/ui-api` (`UI_API_URL`).

Key endpoints used:

- `GET /api/health`
- `GET /api/meta`
- `GET /api/incidents`
- `GET /api/incidents/:run_id`
- `POST /api/incidents/:run_id/approve`
- `GET /api/incidents/:run_id/events`
- `GET /api/endpoints`
- `GET /api/endpoints/:node_id/events`
- `GET /api/endpoints/:node_id/runs`
- `POST /api/endpoints/:node_id/targeted-test`
- `GET /api/audit`
- `GET /api/stream` (SSE refresh hints)

Authentication is via `X-API-Key` header (or `api_key` query parameter for SSE).
