# FR-06 Dashboard

## Start
```bash
./scripts/ui_up.sh
```

## URLs
- UI: `http://127.0.0.1:3200`
- API: `http://127.0.0.1:8090`

## Main panels
- Posture bar: incidents, pending approvals, failed-safe, active endpoints, ingestion/min, p95 latency.
- Threat overview: incidents trend, severity mix, lane mix.
- Live incidents feed: newest runs with quick investigation open.
- Entity spotlight: top `src_ip`, `user_name`, `node_id`.
- Timeline strip: bucketed incident density.

## Investigation workflow
- Open incident drawer from Dashboard/Incidents.
- Tabs: Overview, Steps, Timeline, Entities, Evidence, Actions.
- Actions include approve/reject, assign, note, reviewed mark.

## Real-time updates
- UI subscribes to `GET /api/stream` (SSE).
- Falls back to polling when stream is unavailable.
