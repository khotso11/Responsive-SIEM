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
- `POST /api/auth/login`
- `GET /api/auth/me`
- `GET /api/incidents`
- `GET /api/incidents/:run_id`
- `POST /api/incidents/:run_id/approve`
- `GET /api/incidents/:run_id/events`
- `GET /api/endpoints`
- `GET /api/audit`
- `GET /api/artifacts`
- `GET /api/artifact`
- `GET /api/users`
- `POST /api/users`
- `POST /api/users/:id/disable`
- `DELETE /api/users/:id`

## Admin User Management

The UI now supports admin and analyst enrollment with:
- email address
- notification-enabled flag
- disabled flag
- role

This is used by the email notification subsystem to determine who receives security alerts.

## Run

```bash
./scripts/ui_up.sh
```

Expected output:

- `PASS: FR-06 UI services started`
- `UI_WEB_URL=http://127.0.0.1:3200`
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

## Email Notification Proof

For local SMTP validation:

```bash
./scripts/mailpit_up.sh
```

Then run the UI API with:

```bash
RSIEM_MAIL_ENABLED=true \
RSIEM_MAIL_PROVIDER=smtp \
RSIEM_SMTP_HOST=127.0.0.1 \
RSIEM_SMTP_PORT=1025 \
RSIEM_SMTP_FROM=alerts@rsiem.local \
RSIEM_UI_BASE_URL=http://127.0.0.1:3200 \
RSIEM_MAIL_DEV_SINK=true \
go run ./cmd/ui-api
```

Open `http://127.0.0.1:8025` to confirm delivered messages.

## Screenshot placeholders

- `docs/screenshots/fr06_incident_queue.png`
- `docs/screenshots/fr06_incident_detail.png`
- `docs/screenshots/fr06_endpoints.png`
- `docs/screenshots/fr06_audit.png`
