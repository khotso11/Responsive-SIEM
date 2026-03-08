# FR-06 UI RBAC

## Auth model
- UI API issues signed session tokens via `POST /api/auth/login`.
- UI sends `Authorization: Bearer <token>` on API requests.
- Server enforces role checks on every protected route.
- API-key auth remains available for non-UI automation and smoke checks.

## Local deterministic users
Users are stored in `configs/ui_users.json` with hashed passwords.

Default local users:
- `admin` / `admin123` (role: `admin`)
- `analyst` / `analyst123` (role: `analyst`)

## Role policy
- `admin`
  - approve/reject incidents
  - assign incidents to any user
  - create/update/disable users via `/api/admin/users`
  - full audit visibility
- `analyst`
  - approve/reject incidents
  - assign incidents only to self
  - add notes and mark reviewed
  - cannot use `/api/admin/users` (returns 403)

## UI state persistence
- Incident assignment/notes/review events are append-only JSONL at:
  - `retained/ui_state/ui_actions.jsonl`
