# FR-06 SOC UI

## Components

- `cmd/ui-api`: Go HTTP API for incident/read/query/approval actions.
- `ui/`: Next.js + TypeScript SOC web console.

## API Base

- Default: `http://127.0.0.1:8090`
- Auth header: `X-API-Key: $UI_API_KEY`

## Routes

- `GET /api/health`
- `GET /api/meta`
- `GET /api/incidents`
- `GET /api/incidents/:run_id`
- `POST /api/incidents/:run_id/approve`
- `GET /api/incidents/:run_id/events`
- `GET /api/endpoints`
- `GET /api/audit`
- `GET /api/artifacts`
- `GET /api/artifact`

## Run

```bash
./scripts/ui_up.sh
```

Expected output:

- `PASS: FR-06 UI services started`
- `UI_WEB_URL=http://127.0.0.1:3000`
- `UI_API_URL=http://127.0.0.1:8090`

## Stop

```bash
./scripts/ui_down.sh
```

## Deterministic smoke proof

```bash
./scripts/verify_fr06_ui_smoke.sh
```

Expected output:

- `PASS: FR-06 UI smoke completed`
- `FR06_UI_PROOF_JSON=demo_artifacts/<timestamp>/fr06_ui/fr06_ui_proof.json`

## Screenshot placeholders

- `docs/screenshots/fr06_incident_queue.png`
- `docs/screenshots/fr06_incident_detail.png`
- `docs/screenshots/fr06_endpoints.png`
- `docs/screenshots/fr06_audit.png`
