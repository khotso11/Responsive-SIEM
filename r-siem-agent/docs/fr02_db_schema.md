# FR-02B DB Schema

Database: `rsiem` (TimescaleDB/Postgres)
Table: `normalized_events`

Required columns:
- `event_ts_unix_ms BIGINT NOT NULL`
- `recv_ts_unix_ms BIGINT NOT NULL`
- `node_id TEXT NOT NULL`
- `source_type TEXT NOT NULL`
- `event_type TEXT NOT NULL`
- `event_idem_key TEXT NOT NULL`

Additional columns:
- `id BIGSERIAL PRIMARY KEY`
- `ingest_ts TIMESTAMPTZ NOT NULL DEFAULT now()`
- `src_ip INET NULL`
- `user_name TEXT NULL`
- `severity TEXT NULL`
- `rule_id TEXT NULL`
- `raw_line_sha256 TEXT NULL`

Indexes:
- `normalized_events_event_idem_key_uidx` (UNIQUE)
- `normalized_events_event_ts_idx`
- `normalized_events_node_id_idx`

Optional hypertable conversion is attempted by `scripts/db_up.sh` when TimescaleDB functions are available.
