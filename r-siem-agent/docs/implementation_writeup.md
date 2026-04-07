# System Implementation Overview

## 1) System Implementation Overview

The repository implements two concrete event-ingest paths that converge on response orchestration:

- **Raw collector path**
  - Standalone collectors publish raw normalized event records to JetStream stream `RSIEM_EVENTS`, subject `rsiem.events.raw`.
  - `cmd/detector-v0` consumes that stream, applies rule logic from `configs/detector.yaml`, emits detection logs such as `detector_rule_matched`, and publishes ROE trigger messages through `internal/roe/trigger/publisher.go` to:
    - `rsiem.response.triggers.fast`
    - `rsiem.response.triggers.standard`

- **Agent gRPC mTLS path**
  - `cmd/agent` runs the local pipeline (`internal/supervisor/supervisor.go`) and sends lane-classified batches over gRPC mTLS to `cmd/master`.
  - `cmd/master` verifies client certificates, agent identity policy, and optional fingerprint allowlist, then publishes batches to JetStream stream `RSIEM` on:
    - `rsiem.fast`
    - `rsiem.standard`
  - `cmd/master-consume` pull-consumes `RSIEM`, performs RCE / incident correlation and export handling, and can publish ROE triggers into `RSIEM_RESPONSE`.

The **response path** is:

- **Trigger publish**
  - `internal/roe/trigger.Publisher` serializes trigger alerts with fields such as `rule_id`, `severity`, `confidence_score`, `lane`, `event_idem_key`, `src_ip`, `dst_ip`, `dst_port`, `protocol_family`, `user`, `exec_path`, `comm`, `cmdline`, `dns_name`, `file_sha256`, `exec_sha256`, `latency_ms`.

- **ROE approval gating**
  - `cmd/master-roe` consumes `rsiem.response.triggers.fast|standard`, deduplicates on `trigger_idem_key`, resolves playbooks from `configs/master.yaml`, applies approval rules from `policies.approvals.rules`, persists run state in KV and `exports/roe_runs.jsonl`, and emits `response_run_created` / `response_run_updated`.

- **Step dispatch**
  - `cmd/master-roe` materializes steps from the playbook and publishes them to:
    - `rsiem.response.steps.fast`
    - `rsiem.response.steps.standard`

- **Worker execution**
  - `cmd/master-roe-worker` consumes step subjects, selects a connector from `internal/roe/connectors`, applies action allowlist policy, retries retryable failures with `NakWithDelay`, persists per-step state to KV, writes append-only `exports/roe_steps.jsonl`, updates `exports/roe_steps_latest.jsonl`, and publishes results to:
    - `rsiem.response.results.fast`
    - `rsiem.response.results.standard`

- **Agent command execution**
  - `cmd/agent` subscribes to `rsiem.agent.command` and per-agent subjects such as `rsiem.agent.command.<target_agent_id>`, executes built-in commands from `cmd/agent/command.go`, persists result cache/spool, and replies to the worker.

- **Results / exports / DB / retention**
  - `cmd/master-roe` reconciles step results into run state, writes run export updates to `exports/roe_runs.jsonl`, and writes `normalized_events` into Postgres/Timescale when `db.enabled` is true.
  - `cmd/retention-query` ingests `roe_runs`, `roe_steps`, detector logs, collector logs, and master logs into retained JSONL sets under `retained/` and supports deterministic query/prune/export.

## Executables and role

| Executable | Entry point | Role |
|---|---|---|
| `agent` | `cmd/agent/main.go` | Endpoint pipeline runner + command executor |
| `collector-tail` | `cmd/collector-tail/main.go` | Tails auth/demo log files into `RSIEM_EVENTS` |
| `collector-syslog` | `cmd/collector-syslog/main.go` | UDP syslog collector |
| `collector-syslog-udp` | `cmd/collector-syslog-udp/main.go` | Syslog UDP wrapper/variant |
| `collector-netflowv5` | `cmd/collector-netflowv5/main.go` | NetFlow v5 UDP collector |
| `collector-snmptrap` | `cmd/collector-snmptrap/main.go` | SNMP trap UDP collector |
| `collector-auditd` | `cmd/collector-auditd/main.go` | Auditd exec/connect collector |
| `collector-inotify` | `cmd/collector-inotify/main.go` | File-change collector over watched paths |
| `collector-procnet` | `cmd/collector-procnet/main.go` | `/proc/net` network-connection collector |
| `collector-dns` | `cmd/collector-dns/main.go` | DNS packet collector |
| `detector-v0` | `cmd/detector-v0/main.go` | Rule engine over `RSIEM_EVENTS` |
| `master` | `cmd/master/main.go` | gRPC mTLS ingest server; publishes to `RSIEM` |
| `master-consume` | `cmd/master-consume/main.go` | JetStream consumer / RCE / alert & incident export |
| `master-roe` | `cmd/master-roe/main.go` | Response orchestration engine; run creation and approvals |
| `master-roe-worker` | `cmd/master-roe-worker/main.go` | Step execution worker |
| `investigation-enricher` | `cmd/investigation-enricher/main.go` | External IOC enrichment worker |
| `ui-api` | `cmd/ui-api/main.go` | REST API for incidents, search, actions, models, audit |
| `retention-query` | `cmd/retention-query/main.go` | Retained-store ingest/query/prune/export |
| `signctl` | `cmd/signctl/main.go` | HMAC key init/rotation and bundle/batch signing |
| helper CLIs | `cmd/master-pubevent`, `cmd/master-roe-approve`, `cmd/master-roe-results-list`, `cmd/master-roe-approvals-list`, `cmd/master-roe-worker-probe`, `cmd/master-roe-worker-results-publish`, `cmd/retention-query`, `cmd/ui-api-probe` | Operational probes / test utilities |

---

# 2) Component-by-Component Implementation Detail

## Collectors

### `collector-tail`
- **Purpose**
  - Tails a single file and publishes each line as a raw event.
- **Entry point**
  - `cmd/collector-tail/main.go`
- **Core packages**
  - `internal/config/collector_detector.go`
  - `internal/collector/common`
- **Inputs / outputs**
  - Input file: `tail.path`
  - Checkpoint file: `tail.checkpoint_path`
  - Output stream/subject: `RSIEM_EVENTS` / `rsiem.events.raw`
- **Key config**
  - `configs/collector.yaml`
  - Keys:
    - `jetstream.url`
    - `jetstream.stream`
    - `jetstream.subject`
    - `tail.path`
    - `tail.checkpoint_path`
    - `tail.poll_ms`
  - Env override:
    - `RSIEM_COLLECTOR_TAIL_PATH`
- **Key logs**
  - `collector_started`
  - `collector_tail_input_path_resolved`
  - `collector_nats_connected`
  - `collector_event_published`
  - `collector_tail_checkpoint_state`
- **Failure / idempotency**
  - Uses checkpoint state to avoid rereading committed file offsets.
  - Collectors use offline publish spool support from `internal/collector/common`.

### `collector-syslog`
- **Purpose**
  - UDP syslog listener that publishes raw syslog events.
- **Entry point**
  - `cmd/collector-syslog/main.go`
- **Core packages**
  - `internal/collector/common`
- **Inputs / outputs**
  - Input: UDP bind `collector.bind_addr:collector.port`
  - Output: `RSIEM_EVENTS` / `rsiem.events.raw`
- **Key config**
  - `configs/collector-syslog.yaml`
  - Keys:
    - `collector.bind_addr`
    - `collector.port`
    - `collector.max_packet_bytes`
    - `collector.queue_size`
    - `collector.rate_limit_pps`
    - `collector.node_id`
    - `collector.source_type`
    - `collector.max_message_len`
- **Key logs**
  - `collector_started`
  - `collector_nats_connected`
- **Failure / idempotency**
  - Rate-limited UDP ingest; offline publish spool when JetStream unavailable.

### `collector-syslog-udp`
- **Purpose**
  - Alternate syslog UDP collector executable.
- **Entry point**
  - `cmd/collector-syslog-udp/main.go`
- **Core packages**
  - `internal/collector/common`
- **Inputs / outputs**
  - Same raw-event path to `RSIEM_EVENTS` / `rsiem.events.raw`.
- **Key config**
  - Uses master/collector config pathing as implemented in the binary.
- **Key logs**
  - Collector startup and publish logs.
- **Failure / idempotency**
  - Same UDP/offline spool pattern as other collectors.
- **Notes**
  - This is an implemented executable; repo evidence does not show a separate dedicated YAML file for it. Exact additional config beyond code defaults is `UNKNOWN`.

### `collector-netflowv5`
- **Purpose**
  - UDP NetFlow v5 collector.
- **Entry point**
  - `cmd/collector-netflowv5/main.go`
- **Core packages**
  - `internal/collector/common`
- **Inputs / outputs**
  - Input: UDP bind
  - Output: `RSIEM_EVENTS` / `rsiem.events.raw`
- **Key config**
  - `configs/collector-netflowv5.yaml`
  - Keys:
    - `collector.bind_addr`
    - `collector.port`
    - `collector.max_packet_bytes`
    - `collector.queue_size`
    - `collector.rate_limit_pps`
    - `collector.node_id`
    - `collector.source_type`
- **Key logs**
  - Collector startup/publish logs.
- **Failure / idempotency**
  - UDP queue + offline spool.

### `collector-snmptrap`
- **Purpose**
  - UDP SNMP trap collector.
- **Entry point**
  - `cmd/collector-snmptrap/main.go`
- **Core packages**
  - `internal/collector/common`
- **Inputs / outputs**
  - Input: UDP bind
  - Output: `RSIEM_EVENTS` / `rsiem.events.raw`
- **Key config**
  - `configs/collector-snmptrap.yaml`
  - Keys mirror `collector-netflowv5.yaml`.
- **Key logs**
  - Collector startup/publish logs.
- **Failure / idempotency**
  - UDP queue + offline spool.

### `collector-auditd`
- **Purpose**
  - Parses Linux auditd for process execution and connect telemetry.
- **Entry point**
  - `cmd/collector-auditd/main.go`
- **Core packages**
  - `internal/collector/common`
  - `internal/collector/common/recent_context.go`
- **Inputs / outputs**
  - Input file: `/var/log/audit/audit.log`
  - Checkpoint: `collector.checkpoint_path`
  - Recent context root: `collector.recent_context_root`
  - Output: `RSIEM_EVENTS` / `rsiem.events.raw`
  - Emits `source_type` values:
    - `auditd_exec`
    - `auditd_connect`
- **Key config**
  - `configs/collector-auditd.yaml`
  - Keys:
    - `collector.path`
    - `collector.checkpoint_path`
    - `collector.poll_ms`
    - `collector.source_type`
    - `collector.connect_source_type`
    - `collector.recent_context_root`
    - `collector.exec_context_max_age_ms`
    - `collector.file_access_context_max_age_ms`
- **Key logs**
  - `collector_started`
  - `collector_nats_connected`
  - `offline_publisher_init_failed` when spool decode fails
- **Failure / idempotency**
  - Checkpointed file offsets
  - Offline spool on publish failure
  - Recent exec/file context cache for attribution continuity

### `collector-inotify`
- **Purpose**
  - Watches filesystem paths and emits `file_change` events with recent-process attribution.
- **Entry point**
  - `cmd/collector-inotify/main.go`
- **Core packages**
  - `internal/collector/common/recent_context.go`
- **Inputs / outputs**
  - Input paths from `collector.paths`
  - Output: `RSIEM_EVENTS` / `rsiem.events.raw`
- **Key config**
  - `configs/collector-inotify.yaml`
  - Keys:
    - `collector.paths`
    - `collector.recursive`
    - `collector.source_type`
    - `collector.coalesce_window_ms`
    - `collector.attribution_wait_ms`
    - `collector.recent_context_root`
    - `collector.recent_exec_max_age_ms`
    - `collector.recent_file_access_max_age_ms`
    - `collector.ignore_prefixes`
- **Key logs**
  - Collector startup/publish logs.
- **Failure / idempotency**
  - Coalesces rapid changes before publish.
  - Uses recent context to attribute changes to recent process activity.

### `collector-procnet`
- **Purpose**
  - Polls network connection state and emits `network_connection` events.
- **Entry point**
  - `cmd/collector-procnet/main.go`
- **Core packages**
  - `internal/collector/common`
- **Inputs / outputs**
  - Input: `/proc/net` and process tables
  - Output payload includes:
    - `event_idem_key`
    - `observed_at_unix_ms`
    - `event_ts_unix_ms`
    - `recv_ts_unix_ms`
    - `host`
    - `node_id`
    - `group_key`
    - `source_type`
    - `user`
    - `src_ip`
    - `dst_ip`
    - `dst_port`
    - `pid`
    - `exec_path`
    - `comm`
    - `cmdline`
    - `event_type=network_connection`
- **Key config**
  - `configs/collector-procnet.yaml`
  - Keys:
    - `collector.poll_ms`
    - `collector.source_type`
    - `collector.include_loopback`
- **Key logs**
  - Collector startup/publish logs.
- **Failure / idempotency**
  - Event idempotency key emitted on each network event.

### `collector-dns`
- **Purpose**
  - Captures DNS packets and emits `dns_query` evidence.
- **Entry point**
  - `cmd/collector-dns/main.go`
- **Core packages**
  - `internal/collector/common`
- **Inputs / outputs**
  - Input interface: `collector.interface`
  - Output: `RSIEM_EVENTS` / `rsiem.events.raw`
  - Event context includes DNS names/types and source/destination IPs.
- **Key config**
  - `configs/collector-dns.yaml`
  - Keys:
    - `collector.interface`
    - `collector.source_type`
    - `collector.coalesce_window_ms`
    - `collector.suppress_loopback_stub`
- **Key logs**
  - Collector startup/publish logs.
- **Failure / idempotency**
  - Packet coalescing window before publish.

## Normalization / enrichment layer

### Agent-side event pipeline
- **Purpose**
  - Converts local source events into normalized `event.Event` records, enriches them, assigns lane, writes WAL, batches, and transports them.
- **Entry points**
  - `internal/supervisor/supervisor.go`
  - `internal/event/event.go`
  - `internal/pipeline/processor.go`
  - `internal/pipeline/enricher.go`
  - `internal/pipeline/classifier.go`
  - `internal/pipeline/lane_distributor.go`
  - `internal/pipeline/wal_writer.go`
  - `internal/pipeline/transport_grpc.go`
- **Core packages**
  - `internal/event`
  - `internal/pipeline`
  - `internal/wal`
- **Inputs / outputs**
  - Input: mock generator / local collectors into `event.Event`
  - Output lanes:
    - `FAST`
    - `STANDARD`
  - Transport output: gRPC mTLS batches to `cmd/master`
- **Key implemented fields**
  - `event.Event`:
    - `id`
    - `seq`
    - `timestamp`
    - `host`
    - `source`
    - `type`
    - `severity`
    - `message`
    - `lane`
    - `wal_offset`
    - `fields`
- **Key behavior**
  - `Classifier.classify` maps severities `CRITICAL|HIGH -> FAST`, else `STANDARD`.
  - `CommitManager` advances WAL committed watermark on ACK.
- **Failure / idempotency**
  - WAL replay on startup in `internal/supervisor/supervisor.go`
  - ACK-driven commit boundary
  - transport modes:
    - `mock`
    - `tcp`
    - `grpc_mtls`

### Collector-side enrichment continuity
- **Purpose**
  - Maintains recent exec/file context so later file and network events can be attributed to the originating process.
- **Entry points**
  - `internal/collector/common/recent_context.go`
  - `cmd/collector-auditd/main.go`
  - `cmd/collector-inotify/main.go`
  - `cmd/detector-v0/main.go`
- **Implemented behavior**
  - `auditd_connect` backfills process metadata from recent exec context.
  - `inotify` waits for attribution window and uses recent file/exec context.
  - `detector-v0` backfills missing `exec_path`, `comm`, `cmdline` for network events when recent context exists.
- **Failure / idempotency**
  - Context lookups are time-bounded by max-age config.

## `detector-v0`
- **Purpose**
  - Consumes raw normalized events from `RSIEM_EVENTS`, applies detector logic, dedupe, cooldown, and publishes alerts/triggers.
- **Entry point**
  - `cmd/detector-v0/main.go`
- **Core packages**
  - `internal/config/collector_detector.go`
  - `internal/pipeline/cooldown.go`
  - `internal/roe/trigger/publisher.go`
- **Inputs / outputs**
  - Input stream/subjects:
    - `RSIEM_EVENTS`
    - `rsiem.events.raw`
  - KV buckets:
    - `RSIEM_DETECT_DEDUPE`
    - `RSIEM_DETECT_COOLDOWN`
  - Output subjects:
    - through `internal/roe/trigger.Publisher`
    - `rsiem.response.triggers.fast`
    - `rsiem.response.triggers.standard`
- **Key config**
  - `configs/detector.yaml`
  - Keys:
    - `jetstream.url`
    - `jetstream.stream`
    - `jetstream.subject`
    - `jetstream.durable`
    - `dedupe.bucket`
    - `cooldown.bucket`
    - `cooldown_ms`
    - `baseline.process_first_seen_ttl_ms`
    - `baseline.network_first_seen_ttl_ms`
    - `network.benign_destination_ips`
    - `network.known_bad_destination_ips`
    - `network.risky_ports`
    - `internal_scan.*`
    - `dns.known_bad_domains`
    - `dns.suspicious_tlds`
- **Key logs**
  - `detector_rule_matched`
  - `detector_alert_published`
  - `cooldown_hit`
- **Latency measurement**
  - Published alerts carry:
    - `event_ts_unix_ms`
    - `alert_ts_unix_ms`
    - `latency_ms`
- **Failure / idempotency**
  - Dedupes with KV bucket `RSIEM_DETECT_DEDUPE`
  - Cooldown suppresses repeated trigger publishes by group key/rule
  - Internal scan allowlist uses configured users, nodes, exec path prefixes, and command prefixes
- **Implemented rule surface**
  - Config file exposes internal scan confidence per protocol and DNS suspicious TLDs.
  - Top-level RCE-style rules for many detections are defined in `configs/master.yaml` under `rce.rules`; detector-v0 and ROE share the same overall detection/orchestration model.

## Trigger publisher
- **Purpose**
  - Maps matched detections into ROE trigger messages.
- **Entry points**
  - `internal/roe/trigger/publisher.go`
  - used by `cmd/detector-v0/main.go`
  - used by `cmd/master-consume/main.go`
- **Key structs**
  - `trigger.Alert`
  - `Publisher`
- **Inputs / outputs**
  - Input: matched alert object
  - Output stream/subjects:
    - stream `RSIEM_RESPONSE`
    - `rsiem.response.triggers.fast`
    - `rsiem.response.triggers.standard`
- **Implemented fields**
  - `rule_id`
  - `severity`
  - `confidence_score`
  - `lane`
  - `group_by`
  - `group_key`
  - `observed_at_unix_ms`
  - `event_ts_unix_ms`
  - `alert_ts_unix_ms`
  - `latency_ms`
  - `node_id`
  - `source_type`
  - `event_type`
  - `src_ip`
  - `dst_ip`
  - `dst_port`
  - `protocol_family`
  - `scan_fanout`
  - `top_destinations`
  - `user`
  - `exec_path`
  - `comm`
  - `cmdline`
  - `file_path`
  - `file_sha256`
  - `exec_sha256`
  - `signer_hint`
  - `dns_name`
  - `dns_type`
  - `event_idem_key`
  - `agent_id`
  - `target_agent_id`
- **Confidence calculation**
  - `deriveConfidence` starts from `defaultConfidenceForSeverity`:
    - critical `70`
    - high `58`
    - medium `46`
    - low `32`
    - info `20`
  - Additive implemented adjustments:
    - `FAST` lane `+6`
    - `auditd_connect +9`
    - `auditd_exec +8`
    - `inotify +7`
    - `dns_packet +6`
    - `proc_net +4`
    - host/tail `+3`
    - known user `+6`
    - `exec_path +6`
    - `comm +4`
    - `cmdline +4`
    - `dst_ip +3`
    - `dns_name +6`
    - `file_sha256 +6`
    - `exec_sha256 +6`
    - `signer_hint +2`
  - Normalized by `normalizeConfidence`.
- **Failure / idempotency**
  - Trigger publisher itself is fire-and-publish; downstream ROE dedupe handles repeated `trigger_idem_key`.

## `master` (transport + mTLS)
- **Purpose**
  - Accepts gRPC mTLS ingest from agents and writes batches to JetStream.
- **Entry point**
  - `cmd/master/main.go`
- **Core packages**
  - `internal/ingest/server.go`
  - `internal/buffer`
  - `internal/proto/pb`
- **Inputs / outputs**
  - Input: gRPC mTLS on `listen_addr`
  - Output stream/subjects:
    - `RSIEM`
    - `rsiem.fast`
    - `rsiem.standard`
- **Key config**
  - `configs/master.yaml`
  - Keys:
    - `listen_addr`
    - `transport.mode`
    - `transport.tls.ca`
    - `transport.tls.cert`
    - `transport.tls.key`
    - `transport.tls.server_name`
    - `transport.tls.client_fingerprint_allowlist`
    - `transport.tls.client_fingerprint_allowlist_path`
    - `jetstream.url`
    - `jetstream.stream`
    - `jetstream.subject_fast`
    - `jetstream.subject_standard`
- **Key logs**
  - `grpc_mtls_server_started`
  - `grpc_mtls_server_identity_policy`
  - `grpc_mtls_client_authenticated`
  - `grpc_mtls_client_rejected`
  - `grpc_mtls_handshake_failed`
  - `master_recv_batch`
- **Failure / idempotency**
  - Enforces `tls.RequireAndVerifyClientCert`
  - Optional client fingerprint allowlist
  - Batch idempotency key:
    - `batch.<lane>.<seq_start>.<seq_end>`
  - Duplicate batch replay returns stored ACK/JS sequence instead of republishing.

## `master-consume`
- **Purpose**
  - Pull-consumes `RSIEM`, runs RCE/correlation, exports alerts/incidents, and can emit ROE triggers.
- **Entry point**
  - `cmd/master-consume/main.go`
- **Core packages**
  - `internal/pipeline`
  - `internal/roe/trigger`
  - `internal/proto/pb`
- **Inputs / outputs**
  - Input stream/subjects:
    - `RSIEM`
    - `rsiem.fast`
    - `rsiem.standard`
  - Alert export:
    - `exports/alerts.jsonl`
  - Incident export:
    - `exports/incidents.jsonl`
  - Trigger output:
    - `rsiem.response.triggers.fast|standard`
- **Key config**
  - `configs/master.yaml`
  - Keys:
    - `consumer.fast_workers`
    - `consumer.standard_workers`
    - `consumer.pull_batch`
    - `consumer.pull_timeout_ms`
    - `export.path`
    - `incidents.export.path`
    - `response_triggers.*`
    - `pipeline.cooldown.*`
    - `pipeline.trigger_dedupe.*`
    - `rce.*`
- **Key logs**
  - `master_consumer_config_loaded`
  - `master_consumer_starting`
  - `cooldown_checkpoint_loaded`
  - `cooldown_checkpoint_flushed`
  - `trigger_dedupe_loaded`
  - `export_error`
- **ACK boundaries**
  - Creates explicit-ACK pull consumers via `ensureConsumer(... AckExplicitPolicy ...)`
  - Acks processed messages with `msg.Ack()`
  - Uses pull subscription workers over fast and standard lanes
- **Failure / idempotency**
  - Cooldown and trigger-dedupe integrated before publish
  - Incident state cleanup on inactivity
  - Export failures can be required or best-effort depending on config
- **Observable outputs**
  - `alerts.jsonl` append-only alert export
  - `incidents.jsonl` incident open/update/close export

## `master-roe`
- **Purpose**
  - Creates response runs, resolves approval policy, emits steps, reconciles results, exports runs, and writes `normalized_events`.
- **Entry point**
  - `cmd/master-roe/main.go`
- **Core packages**
  - JetStream/KV orchestration in same file
  - `internal/roe/trigger`
  - DB sink implemented directly in the executable
- **Inputs / outputs**
  - Input subjects:
    - `rsiem.response.triggers.fast`
    - `rsiem.response.triggers.standard`
    - `rsiem.response.results.fast`
    - `rsiem.response.results.standard`
    - `rsiem.response.approvals`
  - Output subjects:
    - `rsiem.response.steps.fast`
    - `rsiem.response.steps.standard`
    - `rsiem.response.approval_requests`
  - KV buckets:
    - `RSIEM_RSP_IDEMP`
    - `RSIEM_RSP_RUNS`
    - `RSIEM_RSP_STEPS`
    - `RSIEM_RSP_LOCKS`
    - `RSIEM_RSP_APPROVALS`
    - `RSIEM_RSP_RESULTS`
  - Exports:
    - `exports/roe_runs.jsonl`
  - DB:
    - `normalized_events`
    - `incident_observables`
    - `observable_enrichments`
    - `enrichment_jobs`
- **Key config**
  - `configs/master.yaml`
  - Keys:
    - `roe.jetstream.*`
    - `roe.kv.*`
    - `roe.export.runs_path`
    - `policies.approvals.*`
    - `playbooks`
    - `policies.guardrails`
    - `policies.action_allowlist`
    - `db.*`
- **Key logs**
  - `response_trigger_duplicate`
  - `response_run_created`
  - `response_run_updated`
  - `response_result_duplicate`
  - `approval_duplicate`
  - `approval_timed_out`
  - `response_run_manual_review_required`
  - `response_run_partial_completion`
- **Approval gating**
  - Evaluates `policies.approvals.rules`
  - Publishes approval requests to `rsiem.response.approval_requests`
  - `scanForApprovalTimeouts` flips stale `WAITING_APPROVAL` runs to:
    - `MANUAL_REVIEW_REQUIRED`
    - `failed_safe_reason=approval_timeout`
    - `approval_decision=timeout`
- **Idempotency**
  - Trigger dedupe keyed by `trigger.TriggerIdemKey`
  - Corroboration dedupe also stores event/trigger tuples in KV
- **Run export fields**
  - `response_run_updated` export object includes:
    - `run_id`
    - `status`
    - `approval_policy_rule_id`
    - `step_total`
    - `step_succeeded_count`
    - `step_failed_safe_count`
    - `step_failed_transient_count`
    - `last_updated_at_unix_ms`
    - `actor`
    - optional:
      - `node_id`
      - `asset_environment`
      - `asset_criticality`
      - `asset_owner`
      - `asset_team`
      - `asset_role`
      - `source_type`
      - `event_type`
      - `src_ip`
      - `user`
      - `identity_*`
      - `agent_id`
      - `target_agent_id`
      - `event_idem_key`
      - `target`
      - `failed_safe_reason`
      - `allowlist_rule_id`
      - `operator_action`
- **DB writer**
  - `ensureSchema` creates `normalized_events`
  - `Insert` uses `ON CONFLICT (event_idem_key) DO NOTHING`
  - Correct user column is:
    - `normalized_events.user_name`
- **Failure / timeout behavior**
  - Approval timeout goes to `MANUAL_REVIEW_REQUIRED`
  - Run may become `FAILED_SAFE` or `FAILED_TRANSIENT` based on step reconciliation
  - `operatorActionForRun` returns:
    - `manual_review_required`
    - `manual_restore_check_recommended`

## `master-roe-worker`
- **Purpose**
  - Executes steps, handles retries/degrade/inflight, writes step journals, publishes results.
- **Entry point**
  - `cmd/master-roe-worker/main.go`
- **Core packages**
  - `internal/roe/connectors`
- **Inputs / outputs**
  - Input step subjects:
    - `rsiem.response.steps.fast`
    - `rsiem.response.steps.standard`
  - Output result subjects:
    - `rsiem.response.results.fast`
    - `rsiem.response.results.standard`
  - KV buckets:
    - `RSIEM_RSP_STEPS`
    - `RSIEM_RSP_RESULTS`
    - `RSIEM_RSP_LOCKS`
  - Exports:
    - `exports/roe_steps.jsonl`
    - `exports/roe_steps_latest.jsonl`
- **Key config**
  - `configs/master.yaml`
  - Keys:
    - `roe.worker.fast_workers`
    - `roe.worker.standard_workers`
    - `roe.worker.pull_batch`
    - `roe.worker.pull_timeout_ms`
    - `roe.worker.max_inflight`
    - `roe.worker.max_attempts`
    - `roe.worker.base_backoff_ms`
    - `roe.worker.max_backoff_ms`
    - `roe.worker.degrade_high_watermark_pct`
    - `roe.worker.lock_ttl_ms`
    - `roe.worker.notify_allow_missing_webhook`
    - `roe.worker.export.steps_path`
    - `roe.worker.export.steps_latest_path`
- **Key logs**
  - `roe_worker_starting`
  - `step_duplicate_succeeded`
  - `step_duplicate_running`
  - `step_duplicate_failed_safe`
  - `roe_connector_selected`
  - `roe_connector_attempt`
  - `roe_connector_retry`
  - `step_failed_transient`
  - `step_failed_safe`
  - `step_succeeded`
  - `roe_connector_terminal`
  - `roe_lock_released`
  - `export_steps_paths`
- **Failure / timeout / idempotency**
  - Duplicate detection keyed by `step_idem_key`
  - Run lock in `RSIEM_RSP_LOCKS`
  - Retryable connector errors go to `FAILED_TRANSIENT` and `NakWithDelay`
  - Terminal or validation errors go to `FAILED_SAFE`
  - Max attempts default `3`
  - Backoff defaults:
    - base `250ms`
    - max `2000ms`
  - `roe_steps.jsonl` is append-only history
  - `roe_steps_latest.jsonl` is latest state per `step_key`

## Agent command executor
- **Purpose**
  - Executes built-in containment/restore/network commands on endpoints and returns receipts.
- **Entry points**
  - `cmd/agent/main.go`
  - `cmd/agent/command.go`
- **Core packages**
  - NATS request/reply logic in same file
  - local filesystem state under `/var/lib/rsiem`
- **Inputs / outputs**
  - Input subjects:
    - `rsiem.agent.command`
    - `rsiem.agent.command.<target_agent_id>`
  - State roots:
    - `/var/lib/rsiem/command_results`
    - `/var/lib/rsiem/command_reply_spool`
    - `/var/lib/rsiem/response_actions`
    - `/var/lib/rsiem/auth_controls`
    - `/var/lib/rsiem/containment_controls`
- **Key runtime env**
  - `RSIEM_AGENT_DISABLE_COMMAND_LISTENER=1`
  - `RSIEM_AGENT_LATERAL_CONTROL_MODE=firewall` from deploy unit
- **Implemented command families**
  - `ping`
  - `quarantine_move`
  - `quarantine_restore`
  - `auth_contain_src_ip`
  - `auth_contain_user_access`
  - `auth_mark_user_verified`
  - `auth_restore_src_ip`
  - `auth_restore_user_access`
  - `contain_destination_ip`
  - `contain_process_exec`
  - `contain_bruteforce_ip`
  - `halt_lateral_movement`
  - `lockdown_privesc`
  - `block_c2_beacon`
  - `kill_chain_stage`
  - `kill_chain_stop`
  - `throttle_exfil`
  - `protect_critical_service_stage`
  - `protect_critical_service`
  - `detector_self_protect`
  - `network_block`
  - `network_rate_limit`
- **Implemented response-action semantics**
  - `block_matching_connections` maps to destination blocking
  - `block_all_incoming` and `block_all_outgoing` now use enforced `network_block`
  - domain targets are handled by `/etc/hosts` override plus resolved-IP nftables egress blocks when available
- **Key logs**
  - `agent_command_subscribe`
  - `agent_command_exec_start`
  - `agent_command_exec_done`
  - `agent_command_exec_denied`
  - `agent_command_reply_publish_failed`
  - `agent_command_reply_spool_enqueue_failed`
  - `agent_command_reply_spool_flush_retry`
- **Failure / idempotency**
  - Result cache and reply spool avoid repeated execution/reply loss
  - Requests can return `SAFE_DENIED`
  - Marker-mode fallback exists for some commands such as `halt_lateral_movement` when no valid private targets are available
  - Network block apply/clear is idempotent for repeated add/delete paths

## Retention store + DB writer

### Timescale/DB writer
- **Purpose**
  - Persists normalized event context into Postgres/Timescale for search and incident evidence.
- **Entry point**
  - `cmd/master-roe/main.go`
- **Table**
  - `normalized_events`
- **Columns**
  - `id`
  - `ingest_ts`
  - `event_ts_unix_ms`
  - `recv_ts_unix_ms`
  - `node_id`
  - `source_type`
  - `event_type`
  - `src_ip`
  - `dst_ip`
  - `dst_port`
  - `protocol_family`
  - `user_name`
  - `severity`
  - `rule_id`
  - `exec_path`
  - `comm`
  - `cmdline`
  - `dns_name`
  - `file_sha256`
  - `exec_sha256`
  - `event_idem_key`
  - `raw_line_sha256`
- **Indexes**
  - `normalized_events_event_idem_key_uidx`
  - `normalized_events_event_ts_idx`
  - `normalized_events_node_id_idx`
- **Failure / idempotency**
  - `ON CONFLICT (event_idem_key) DO NOTHING`
  - `db.fail_closed` controls DB failure behavior
- **Observable behavior**
  - `/api/search/events` reads these fields directly
  - endpoint event logs and Advanced Search depend on them

### Retention store
- **Purpose**
  - Converts exports and logs into a retained JSONL store for FR-08 query/prune/export.
- **Entry point**
  - `cmd/retention-query/main.go`
- **Core packages**
  - `internal/retain/ingest.go`
  - `internal/retain/prune.go`
  - `internal/retain/query.go`
  - `internal/retain/types.go`
- **Subcommands**
  - `ingest`
  - `query`
  - `prune`
- **Inputs**
  - `exports/roe_runs.jsonl`
  - `exports/roe_steps.jsonl`
  - `logs/detector.log`
  - `logs/collector.log`
  - `logs/master-roe.log`
- **Retained files**
  - `retained/runs.jsonl`
  - `retained/steps.jsonl`
  - `retained/alerts.jsonl`
  - `retained/telemetry.jsonl`
- **Query/export flags**
  - `--retained_dir`
  - `--type`
  - `--since`
  - `--until`
  - `--run_id`
  - `--playbook_id`
  - `--status`
  - `--contains`
  - `--out`
  - `--summary_out`
  - `--format jsonl|csv`
- **CSV schema**
  - `type,status,run_id,playbook_id,ts_unix_ms,source,rule_id,severity,event,step_id,operator_action,failed_safe_reason,line_sha256`
- **Failure / idempotency**
  - Prune enforces max-age and max-bytes
  - Query remains functional after prune per FR-08 verifier

## Exports writers

### Alerts / incidents
- **Entry points**
  - `cmd/master-consume/main.go`
- **Files**
  - `exports/alerts.jsonl`
  - `exports/incidents.jsonl`
- **Writer functions**
  - `newExporter`
  - `WriteJSONL`
  - `newIncidentManager`
  - `newIncidentExporter`
- **Behavior**
  - `alerts.jsonl` is append-only alert export
  - `incidents.jsonl` records incident open/update/close state

### ROE runs
- **Entry point**
  - `cmd/master-roe/main.go`
- **File**
  - `exports/roe_runs.jsonl`
- **Writer functions**
  - `newRoeResultsExporter`
  - `WriteJSON`
  - `exportRunUpdate`
- **Behavior**
  - Append-only run lifecycle journal
  - Includes operator action guidance fields when applicable

### ROE steps
- **Entry point**
  - `cmd/master-roe-worker/main.go`
- **Files**
  - `exports/roe_steps.jsonl`
  - `exports/roe_steps_latest.jsonl`
- **Writer functions**
  - `newWorkerExporter`
  - `WriteJSONL`
  - `updateLatestSnapshot`
  - `loadLatestFromAudit`
- **Behavior**
  - `roe_steps.jsonl` is append-only step audit history
  - `roe_steps_latest.jsonl` is latest terminal/latest-known state per `step_key`

### Notify export
- **Entry point**
  - `internal/roe/connectors/builtins.go`
- **Default file**
  - `exports/notify.jsonl`
- **Behavior**
  - File-backed notification artifact when webhook path is absent or alongside notify handling
  - Repo also contains `exports/notify_latest.jsonl` artifact output

## Signing / verification module
- **Purpose**
  - Signs config bundles and JSONL batches; rotates HMAC keys.
- **Entry points**
  - `cmd/signctl/main.go`
  - `internal/sign/*`
- **Commands**
  - `init-key`
  - `rotate-key`
  - `sign-bundle`
  - `verify-bundle`
  - `sign-batch`
  - `verify-batch`
- **Key paths**
  - active key: `pki/fr07/hmac/active.key`
  - rotated keys: `pki/fr07/hmac/rotated/`
- **Default bundle roots**
  - `configs`
  - discovered playbook/rules roots
- **Default exclude prefixes**
  - `demo_artifacts`
  - `retained`
  - `logs`
  - `exports`
  - `tmp`
  - `pki`
- **Key logs / outputs**
  - `PASS: signctl init-key`
  - `PASS: signctl rotate-key`
  - `PASS: signctl sign-bundle`
  - `VERIFY_BUNDLE=PASS`
  - `PASS: signctl sign-batch`
  - `VERIFY_BATCH=PASS`
- **Failure / idempotency**
  - Bundle/batch verify fails on tamper
  - Rotation preserves continued signing after rekey

## Deployment / package surface
- **Scripts**
  - `scripts/deploy/linux/install_endpoint.sh`
  - `scripts/deploy/master/master_up_lan.sh`
  - `scripts/deploy/master/master_down.sh`
  - `scripts/deploy/windows/install_endpoint.ps1`
  - `scripts/deploy/windows/uninstall_endpoint.ps1`
- **Systemd templates**
  - `scripts/deploy/linux/rsiem-agent.service`
  - `scripts/deploy/linux/rsiem-collector-tail.service`
  - `scripts/deploy/linux/rsiem-collector-auditd.service`
  - `scripts/deploy/linux/rsiem-collector-inotify.service`
  - `scripts/deploy/linux/rsiem-collector-procnet.service`
  - `scripts/deploy/linux/rsiem-collector-dns.service`
  - `scripts/deploy/linux/rsiem-collector-syslog.service`
- **Docs**
  - `docs/deploy/linux_endpoint_setup.md`
  - `docs/deploy/master_setup.md`
  - `docs/deploy/multi_endpoint_overview.md`
  - `docs/deploy/two_host_pilot.md`
  - `docs/deploy/windows_endpoint_setup.md`
  - `docs/deploy/certs_allowlist_onboarding.md`
- **Implemented packaging behavior**
  - Linux installer writes configs under `/etc/rsiem/configs`
  - installs binaries under `/opt/rsiem/bin`
  - data under `/var/lib/rsiem`
  - logs under `/var/log/rsiem`
  - renders systemd units with concrete paths and service user
  - sets `RSIEM_AGENT_LATERAL_CONTROL_MODE=firewall` in agent unit
  - installs optional collector binaries if present
  - copies PKI material if provided

---

# 3) Playbooks & Policies (Implementation Only)

## Playbooks

**Playbook location:** all playbooks are defined in `configs/master.yaml` under top-level `playbooks:`.

**Lane note:** there is **no per-playbook lane field** in playbook YAML. Lane is inherited from the trigger path because `response_triggers.lane_policy` is set to `from_alert`. For each playbook below, lane is therefore **inherited from the originating trigger** rather than fixed in the playbook object.

**Rule-definition note:** the following selector rule IDs are referenced by playbooks and verifier scripts, but their rule-definition blocks are not present under `rce.rules` in `configs/master.yaml`:  
`R-PB-BRUTEFORCE-IP-CONTAIN`, `R-PB-PRIVESC-LOCKDOWN`, `R-PB-LATERAL-MOVEMENT-HALT`, `R-PB-C2-BEACON-BLOCK`, `R-PB-RANSOMWARE-KILL-CHAIN-STOP`, `R-PB-DATA-EXFIL-THROTTLE`, `R-PB-CRITICAL-SERVICE-ABUSE-RESPONSE`, `R-PB-DETECTOR-HEALTH-SELF-PROTECT`.  
For those eight, **selector IDs are evidenced; full trigger conditions are UNKNOWN from repo config**.

| Playbook ID | Trigger rule IDs | Lane | Approval requirement | Ordered steps | Failed-safe / rollback notes |
|---|---|---|---|---|---|
| `PB-STAT-PROCESS-MED` | `R-STAT-PROCESS-MED` | inherited (`from_alert`) | `auto` | `notify_soc: notify` | No rollback stage in YAML. |
| `PB-COUNT-PROCESS-HOST` | `R-COUNT-PROCESS-HOST` | inherited | `auto` | `notify_before: notify` -> `contain_host_stub: agent_command(ping)` -> `notify_after: notify` | Stub containment only. |
| `PB-QUARANTINE-ROLLBACK-DEMO` | `R-COLLECT-INVALID-USER` | inherited | `required_for_high` | `quarantine_move: agent_command(quarantine_move)` -> `quarantine_restore: agent_command(quarantine_restore, delay_ms=1200)` | Explicit restore stage is part of playbook. |
| `PB-AGENT-PING-LOCALHOST` | `R-COLLECT-INVALID-USER` | inherited | `required_for_high` | `ping_localhost: agent_command(ping)` | One-step demo action. |
| `PB-AUTH-ABUSE-CONTAIN` | `R-AUTH-FAILED-PW-BURST-USER`, `R-AUTH-FAILED-PW-BURST-SRCIP`, `R-AUTH-USER-SRCIP-BURST` | inherited | `required_for_high` | `auth_contain_src_ip` -> `auth_contain_user_access` -> `notify_auth_containment` | Guardrails normalize containment duration; identity context required. |
| `PB-AUTH-ACCESS-RESTORE` | `R-AUTH-ACCESS-RESTORE-REQUEST` | inherited | `required` | `auth_mark_user_verified` -> `auth_restore_src_ip` -> `auth_restore_user_access` -> `notify_auth_restore` | Explicit restore path. |
| `PB-FILE-SENSITIVE-CHANGE-NOTIFY` | `R-FILE-SENSITIVE-CHANGE` | inherited | `auto` | `notify_sensitive_file_change` | Notify-only. |
| `PB-DNS-SUSPICIOUS-QUERY-NOTIFY` | `R-DNS-SUSPICIOUS-QUERY` | inherited | `auto` | `notify_suspicious_dns_query` | Notify-only. |
| `PB-NET-OUTBOUND-OBSERVE` | `R-NET-OUTBOUND-CONNECTION` | inherited | `auto` | `notify_outbound_connection` | Observe/notify only. |
| `PB-NET-INTERNAL-SCAN-CONTAIN` | `R-NET-INTERNAL-SMB-SCAN`, `R-NET-INTERNAL-RPC-SCAN`, `R-NET-INTERNAL-LDAP-SCAN`, `R-NET-INTERNAL-DNS-SWEEP`, `R-NET-INTERNAL-FTP-SCAN`, `R-NET-INTERNAL-RDP-SCAN`, `R-NET-INTERNAL-WINRM-SCAN`, `R-NET-INTERNAL-SSH-SCAN` | inherited | `auto` | `halt_internal_protocol_scan: agent_command(halt_lateral_movement)` -> `notify_internal_protocol_scan` | Privileged-source review can override auto. |
| `PB-NET-INTERNAL-SCAN-OBSERVE` | `R-NET-INTERNAL-APPROVED-SCAN` | inherited | `auto` | `notify_approved_internal_protocol_scan` | Allowlisted scan observe path. |
| `PB-NET-FIRST-SEEN-CONTAIN` | `R-NET-FIRST-SEEN-RISKY` | inherited | `required_for_high` | `contain_destination_ip` -> `notify_first_seen_risky_destination` | Reversible containment. |
| `PB-PROC-FIRST-SEEN-CONTAIN` | `R-PROC-FIRST-SEEN-SUSPICIOUS` | inherited | `required_for_high` | `contain_process_exec` -> `notify_first_seen_suspicious_process` | Reversible process containment. |
| `PB-SEQ-PROCESS-TO-NET` | `R-SEQ-PROCESS-TO-NET`, `R-COLLECT-FAILED-PW`, `R-COLLECT-INVALID-USER`, `R-COUNT-FAILED-PW-SRCIP` | inherited | `required_for_high` | `block_egress_stub: network_block` | Network block connector path; no rollback step in YAML. |
| `PB-JOIN-HIGH-NET` | `R-JOIN-HIGH-NET` | inherited | `required_for_high` | `rate_limit_src_ip_stub: network_rate_limit` | Rate-limit stub action. |
| `PB-BRUTEFORCE-IP-CONTAIN` | `R-PB-BRUTEFORCE-IP-CONTAIN` | inherited | `required_for_critical` | `contain_bruteforce_ip: agent_command` | Selector rule condition UNKNOWN in repo config. |
| `PB-PRIVESC-LOCKDOWN` | `R-PB-PRIVESC-LOCKDOWN` | inherited | `required` | `lockdown_privesc: agent_command` | Step reversibility is `irreversible`; approval rule `irreversible_action` forces approval. Trigger condition UNKNOWN. |
| `PB-LATERAL-MOVEMENT-HALT` | `R-PB-LATERAL-MOVEMENT-HALT` | inherited | `required` | `halt_lateral_movement: agent_command` | Mixed reversibility; marker fallback on non-private targets. Trigger condition UNKNOWN. |
| `PB-C2-BEACON-BLOCK` | `R-PB-C2-BEACON-BLOCK` | inherited | `required_for_critical` | `block_c2_beacon: agent_command` | Trigger condition UNKNOWN. |
| `PB-RANSOMWARE-KILL-CHAIN-STOP` | `R-PB-RANSOMWARE-KILL-CHAIN-STOP` | inherited | `required` | `kill_chain_stage` -> `kill_chain_stop(simulate_safe_denied=true)` | Verifier expects `FAILED_SAFE`; second step intentionally safe-denies. Trigger condition UNKNOWN. |
| `PB-DATA-EXFIL-THROTTLE` | `R-PB-DATA-EXFIL-THROTTLE` | inherited | `required_for_critical` | `throttle_exfil` | Trigger condition UNKNOWN. |
| `PB-CRITICAL-SERVICE-ABUSE-RESPONSE` | `R-PB-CRITICAL-SERVICE-ABUSE-RESPONSE`, `R-AUTH-PROC-FILE-CHAIN` | inherited | `required` | `protect_critical_service_stage` -> `protect_critical_service(simulate_safe_denied=true)` | Verifier expects `FAILED_SAFE` for the staged irreversible second step. First selector rule condition UNKNOWN; `R-AUTH-PROC-FILE-CHAIN` is defined. |
| `PB-DETECTOR-HEALTH-SELF-PROTECT` | `R-PB-DETECTOR-HEALTH-SELF-PROTECT` | inherited | `auto` | `detector_self_protect` | Trigger condition UNKNOWN. |

## Safety / policies implemented

### Approval gate behavior
- Config path:
  - `configs/master.yaml` under `policies.approvals`
- Global values:
  - `timeout_ms: 300000`
  - `default_auto_min_confidence: 70`
- Rule IDs:
  - `safe_mode_degraded`
  - `irreversible_action`
  - `critical_asset_review`
  - `service_account_review`
  - `privileged_identity_review`
  - `local_source_review`
  - `auto_within_bounds`
  - `required_always`
  - `required_for_high_by_severity`
  - `required_for_high_low_confidence`
  - `required_for_high_auto_path`
  - `required_for_critical_by_severity`
  - `required_for_critical_low_confidence`
  - `required_for_critical_auto_path`
  - `auto_low_confidence_fails_safe`
  - `auto_default`
  - `unknown_mode_fail_safe`
- Runtime implementation:
  - `cmd/master-roe/main.go`
  - `scanForApprovalTimeouts`
  - `publishApprovalRequest`
- Observable outcomes:
  - `WAITING_APPROVAL`
  - `MANUAL_REVIEW_REQUIRED`
  - `FAILED_SAFE`
  - approval audit fields:
    - `approval_policy_rule_id`
    - `approval_decision`
    - `approval_requested_at_unix_ms`
    - `approval_decided_at_unix_ms`
    - `approval_timeout_ms`

### Guardrails
- Config path:
  - `configs/master.yaml` under `policies.guardrails.rules`
- Implemented rules:
  - `enforce_identity_context`
  - `normalize_auth_containment_duration`
  - `normalize_generic_containment_duration`

### Allowlist behavior
- **Transport plane allowlist**
  - `cmd/master/main.go`
  - optional TLS client fingerprint allowlist from:
    - `transport.tls.client_fingerprint_allowlist`
    - `transport.tls.client_fingerprint_allowlist_path`
    - env `RSIEM_MTLS_CLIENT_FINGERPRINT_ALLOWLIST`
- **ROE action allowlist**
  - Config path:
    - `configs/master.yaml` under `policies.action_allowlist`
  - Allowed action types:
    - `notify`
    - `agent_command`
    - `network_block`
    - `network_rate_limit`
  - Playbook-specific allow/deny rules narrow agent commands by prefix.
- **Agent execution plane**
  - `cmd/agent/command.go` only executes compiled-in command names; unknown/disallowed cases return safe-denial or execution denial paths instead of arbitrary shelling out.

### Idempotency / dedupe
- **Batch ingest**
  - `internal/ingest/server.go`
  - key:
    - `batch.<lane>.<seq_start>.<seq_end>`
- **Detector**
  - KV bucket `RSIEM_DETECT_DEDUPE`
- **Cooldown**
  - detector cooldown bucket `RSIEM_DETECT_COOLDOWN`
  - master-consume cooldown checkpoints via `pipeline.CooldownTracker`
- **ROE trigger**
  - `cmd/master-roe/main.go`
  - `trigger_idem_key`
  - `response_trigger_duplicate`
- **ROE step**
  - `step_idem_key`
  - worker duplicate states:
    - `step_duplicate_succeeded`
    - `step_duplicate_running`
    - `step_duplicate_failed_safe`
- **DB**
  - `normalized_events.event_idem_key` unique index

### Retry classes
- Implemented in `cmd/master-roe-worker/main.go`
- `FAILED_TRANSIENT`
  - set when connector error is retryable and attempts remain
  - worker issues `msg.NakWithDelay(backoff)`
- `FAILED_SAFE`
  - set on:
    - allowlist/policy denial
    - connector selection failure
    - validation failure
    - non-retryable connector error
    - retry exhaustion
- `SUCCEEDED`
  - terminal success path
- Run-level reconciliation in `cmd/master-roe/main.go` promotes run status based on step outcomes.

### Audit fields captured/exported
- **Run export**
  - `exports/roe_runs.jsonl`
  - fields include:
    - `run_id`
    - `status`
    - `approval_policy_rule_id`
    - `step_total`
    - `step_succeeded_count`
    - `step_failed_safe_count`
    - `step_failed_transient_count`
    - `last_updated_at_unix_ms`
    - `actor`
    - `event_idem_key`
    - `failed_safe_reason`
    - `operator_action`
    - asset and identity metadata when present
- **Step export**
  - `exports/roe_steps.jsonl`
  - append-only audit log
- **Retained CSV export**
  - `type,status,run_id,playbook_id,ts_unix_ms,source,rule_id,severity,event,step_id,operator_action,failed_safe_reason,line_sha256`

### FAILED_SAFE semantics
- Implemented in worker and master reconciliation.
- Partial-completion guidance:
  - `operator_action=manual_restore_check_recommended`
- Approval timeout guidance:
  - `operator_action=manual_review_required`
- `FAILED_SAFE` is observable in:
  - `exports/roe_runs.jsonl`
  - `exports/roe_steps.jsonl`
  - retained query outputs
  - UI incident state
  - master logs

### Chain-of-custody artifacts for PCAP
- Implemented by `scripts/verify_fr04.sh`
- Artifacts:
  - `demo_artifacts/<timestamp>/fr04/capture.pcap`
  - `demo_artifacts/<timestamp>/fr04/chain_of_custody.json`
  - `demo_artifacts/<timestamp>/fr04/fr04_proof.json`
- `chain_of_custody.json` includes:
  - `timestamp`
  - `host`
  - `interface`
  - `capture_start_rfc3339`
  - `capture_end_rfc3339`
  - `tcpdump_version`
  - `pcap_path`
  - `pcap_owner`
  - `pcap_size_bytes`
  - `pcap_sha256`
  - `case_link.rule_id`
  - `case_link.severity`
  - `case_link.evidence_log`
  - `case_link.evidence_line`

---

# 4) Proof / Verifier Inventory (What proves what)

## Markdown table

| FR / Feature | Script path | What it runs / checks | PASS line | Proof / artifact paths |
|---|---|---|---|---|
| FR-01 | `scripts/verify_fr01_full.sh` | Runs scale15, source-type proof, retention ingest/query of detector latency samples; checks p95 latency and retained alerts export | `PASS: FR-01 full suite completed` | `FR01_FULL_PROOF_JSON=demo_artifacts/<ts>/fr01_full_proof.json`; child proofs include `FR01_SCALE15_PROOF_JSON`, `FR01_SOURCE_TYPES_PROOF_JSON` |
| FR-02 | `scripts/verify_fr02_full.sh` | Wrapper over mTLS, rotation, revocation proofs | `PASS: FR-02 full suite completed` | Wrapper has no single proof file; child scripts emit `FR02_PROOF_JSON`, `FR02_ROTATION_PROOF_JSON`, `FR02_REVOCATION_PROOF_JSON` |
| FR-03 | `scripts/verify_fr03.sh` | Correlation + severity + latency proof for FR-03 detection path | `PASS: FR-03 correlation+severity+latency completed` | `FR03_PROOF_JSON=demo_artifacts/<ts>/fr03_proof.json` |
| FR-04 | `scripts/verify_fr04.sh` | Deception tripwire + localhost capture + chain-of-custody generation | `PASS: FR-04 deception+pcap+chain_of_custody completed` | `FR04_PROOF_JSON=demo_artifacts/<ts>/fr04/fr04_proof.json`; `capture.pcap`; `chain_of_custody.json` |
| FR-05 | `scripts/verify_fr05_full.sh` | Runs `demo_fr05.sh`, validates success and failed-safe runs, plus operator recovery proof for both | `PASS: FR-05 full suite completed` | `FR05_SUCCESS_PROOF_JSON=demo_artifacts/<ts>/fr05_success_proof.json`; `FR05_FAILED_SAFE_PROOF_JSON=demo_artifacts/<ts>/fr05_failed_safe_proof.json`; operator proofs in same dir |
| FR-06 | `scripts/verify_fr06_ui_smoke.sh` | UI/API health, login, RBAC, dashboard, geo, SSE, admin/analyst access checks | `PASS: FR-06 UI smoke completed` | `FR06_UI_SMOKE_PROOF_JSON=demo_artifacts/<ts>/fr06_ui/fr06_ui_smoke_proof.json` |
| FR-07 | `scripts/verify_fr07_rotation.sh` | Key rotation, pre/post signing, no line-count loss in `roe_runs`/`roe_steps` after rotation and additional activity | `PASS: FR-07 rotation completed` | `FR07_ROTATION_PROOF_JSON=demo_artifacts/<ts>/fr07_rotation_proof.json` |
| FR-08 | `scripts/verify_fr08_acceptance.sh` | Runs retention proof, CSV export schema check, 15-window 24h timing suite, p95 query SLA check | `PASS: FR-08 acceptance completed` | `FR08_ACCEPTANCE_PROOF_JSON=demo_artifacts/<ts>/fr08_acceptance_proof.json`; child proof `FR08_PROOF_JSON=demo_artifacts/<ts>/fr08_retention_proof.json` |
| New playbooks proof | `scripts/verify_new_playbooks.sh` | Exercises the eight new robust playbook selectors and checks expected status/step command mapping | `PASS: new playbooks verification completed` | `NEW_PLAYBOOKS_PROOF_JSON=demo_artifacts/<ts>/new_playbooks_proof.json` |
| Multi-agent targeting proof | `scripts/verify_multiagent_targeting.sh` | Starts second agent, publishes targeted step, verifies only targeted agent executes and worker uses per-agent subject | `PASS: multi-agent targeting proof completed` | `MULTIAGENT_TARGETING_PROOF_JSON=demo_artifacts/<ts>/multiagent_targeting_proof.json` |
| Attribution continuity proof | `scripts/verify_attribution_continuity.sh` | Proves continuity of attribution across audit/collector context | `PASS: attribution continuity proof completed` | `ATTRIBUTION_CONTINUITY_PROOF_JSON=demo_artifacts/<ts>/attribution_continuity_proof.json` |
| Full demo wrapper | `scripts/verify_full_demo_suite.sh` | Runs `test_minimal_patch.sh`, FR-02 full, FR-05 full, new playbooks, FR-03, FR-04, and asserts artifact existence | `PASS: full demo suite completed` | `FULL_DEMO_SUITE_LOG=/tmp/verify_full_demo_suite_<ts>.out`; forwards `FR02_ROTATION_PROOF_JSON`, `FR02_REVOCATION_PROOF_JSON`, `FR05_SUCCESS_PROOF_JSON`, `FR05_FAILED_SAFE_PROOF_JSON`, `NEW_PLAYBOOKS_PROOF_JSON`, `FR03_PROOF_JSON`, `FR04_PROOF_JSON` |
| Minimal patch wrapper | `scripts/test_minimal_patch.sh` | Brings stack up, runs reliability suite, FR-02 mTLS verifier, FR-01 verifier | `PASS: minimal patch validation complete` | No dedicated JSON output in script; uses `/tmp/reliability_suite.out`, `/tmp/verify_fr02.out`, `/tmp/verify_fr01.out` |
| Live response actions | `scripts/verify_response_actions_live.sh` | Launches and clears one incident-scoped and one endpoint-scoped action through UI API, then queries fleet ledger | `PASS: live response actions verified` | `ART_DIR=/tmp/rsiem_response_actions_live_<ts>/` with `incident_actions_*`, `endpoint_actions_*`, `fleet_actions.json` |

## CSV text

```csv
FR / Feature,Script path,What it runs / checks,PASS line,Proof / artifact paths
FR-01,scripts/verify_fr01_full.sh,"Runs scale15, source-type proof, retention ingest/query of detector latency samples; checks p95 latency and retained alerts export","PASS: FR-01 full suite completed","FR01_FULL_PROOF_JSON=demo_artifacts/<ts>/fr01_full_proof.json; child proofs FR01_SCALE15_PROOF_JSON, FR01_SOURCE_TYPES_PROOF_JSON"
FR-02,scripts/verify_fr02_full.sh,"Wrapper over mTLS, rotation, revocation proofs","PASS: FR-02 full suite completed","Wrapper has no single proof file; child scripts emit FR02_PROOF_JSON, FR02_ROTATION_PROOF_JSON, FR02_REVOCATION_PROOF_JSON"
FR-03,scripts/verify_fr03.sh,"Correlation + severity + latency proof for FR-03 detection path","PASS: FR-03 correlation+severity+latency completed","FR03_PROOF_JSON=demo_artifacts/<ts>/fr03_proof.json"
FR-04,scripts/verify_fr04.sh,"Deception tripwire + localhost capture + chain-of-custody generation","PASS: FR-04 deception+pcap+chain_of_custody completed","FR04_PROOF_JSON=demo_artifacts/<ts>/fr04/fr04_proof.json; capture.pcap; chain_of_custody.json"
FR-05,scripts/verify_fr05_full.sh,"Runs demo_fr05.sh, validates success and failed-safe runs, plus operator recovery proof for both","PASS: FR-05 full suite completed","FR05_SUCCESS_PROOF_JSON=demo_artifacts/<ts>/fr05_success_proof.json; FR05_FAILED_SAFE_PROOF_JSON=demo_artifacts/<ts>/fr05_failed_safe_proof.json"
FR-06,scripts/verify_fr06_ui_smoke.sh,"UI/API health, login, RBAC, dashboard, geo, SSE, admin/analyst access checks","PASS: FR-06 UI smoke completed","FR06_UI_SMOKE_PROOF_JSON=demo_artifacts/<ts>/fr06_ui/fr06_ui_smoke_proof.json"
FR-07,scripts/verify_fr07_rotation.sh,"Key rotation, pre/post signing, no line-count loss in roe_runs/roe_steps after rotation and additional activity","PASS: FR-07 rotation completed","FR07_ROTATION_PROOF_JSON=demo_artifacts/<ts>/fr07_rotation_proof.json"
FR-08,scripts/verify_fr08_acceptance.sh,"Runs retention proof, CSV export schema check, 15-window 24h timing suite, p95 query SLA check","PASS: FR-08 acceptance completed","FR08_ACCEPTANCE_PROOF_JSON=demo_artifacts/<ts>/fr08_acceptance_proof.json; child proof FR08_PROOF_JSON=demo_artifacts/<ts>/fr08_retention_proof.json"
New playbooks proof,scripts/verify_new_playbooks.sh,"Exercises the eight new robust playbook selectors and checks expected status/step command mapping","PASS: new playbooks verification completed","NEW_PLAYBOOKS_PROOF_JSON=demo_artifacts/<ts>/new_playbooks_proof.json"
Multi-agent targeting proof,scripts/verify_multiagent_targeting.sh,"Starts second agent, publishes targeted step, verifies only targeted agent executes and worker uses per-agent subject","PASS: multi-agent targeting proof completed","MULTIAGENT_TARGETING_PROOF_JSON=demo_artifacts/<ts>/multiagent_targeting_proof.json"
Attribution continuity proof,scripts/verify_attribution_continuity.sh,"Proves continuity of attribution across audit/collector context","PASS: attribution continuity proof completed","ATTRIBUTION_CONTINUITY_PROOF_JSON=demo_artifacts/<ts>/attribution_continuity_proof.json"
Full demo wrapper,scripts/verify_full_demo_suite.sh,"Runs test_minimal_patch.sh, FR-02 full, FR-05 full, new playbooks, FR-03, FR-04, and asserts artifact existence","PASS: full demo suite completed","FULL_DEMO_SUITE_LOG=/tmp/verify_full_demo_suite_<ts>.out; forwards FR02_ROTATION_PROOF_JSON, FR02_REVOCATION_PROOF_JSON, FR05_SUCCESS_PROOF_JSON, FR05_FAILED_SAFE_PROOF_JSON, NEW_PLAYBOOKS_PROOF_JSON, FR03_PROOF_JSON, FR04_PROOF_JSON"
Minimal patch wrapper,scripts/test_minimal_patch.sh,"Brings stack up, runs reliability suite, FR-02 mTLS verifier, FR-01 verifier","PASS: minimal patch validation complete","No dedicated JSON output; uses /tmp/reliability_suite.out, /tmp/verify_fr02.out, /tmp/verify_fr01.out"
Live response actions,scripts/verify_response_actions_live.sh,"Launches and clears one incident-scoped and one endpoint-scoped action through UI API, then queries fleet ledger","PASS: live response actions verified","ART_DIR=/tmp/rsiem_response_actions_live_<ts>/"
```

---

# 5) Runtime Behavior Summary (Observed + implemented)

## STANDARD incident: auto execute
- Event enters via collector or agent path.
- Detection logs appear first:
  - `detector_rule_matched`
  - `detector_alert_published`
  - `cooldown_hit` when suppressed duplicates occur
- Trigger is published to:
  - `rsiem.response.triggers.standard`
- `cmd/master-roe` creates run:
  - `response_run_created`
- If approval policy resolves to auto, `cmd/master-roe` emits steps immediately to:
  - `rsiem.response.steps.standard`
- `cmd/master-roe-worker` logs:
  - `roe_connector_selected`
  - `roe_connector_attempt`
  - `step_succeeded`
- `cmd/master-roe` reconciles result and logs:
  - `response_run_updated`
- Exports written:
  - `exports/roe_runs.jsonl`
  - `exports/roe_steps.jsonl`
  - `exports/roe_steps_latest.jsonl`
  - alert/incident exports if this path is through `master-consume`
- DB write:
  - `normalized_events` row inserted unless `event_idem_key` already exists

## FAST incident: waiting approval -> approved -> execute
- Trigger published to:
  - `rsiem.response.triggers.fast`
- `cmd/master-roe` creates run and resolves approval rule:
  - `response_run_created`
- If policy says approval required:
  - run status becomes `WAITING_APPROVAL`
  - approval request published to `rsiem.response.approval_requests`
- On analyst/admin approval via UI/API or NATS:
  - approval goes to `rsiem.response.approvals`
  - `cmd/master-roe` updates run and emits steps
- Worker executes steps on FAST lane and publishes results.
- `response_run_updated` records terminal state and counters.
- Observable fields across logs/exports:
  - `run_id`
  - `rule_id`
  - `playbook_id`
  - `severity`
  - `confidence_score`
  - `approval_policy_rule_id`
  - `approval_decision`
  - `step_total`
  - `step_succeeded_count`
  - `step_failed_safe_count`
  - `step_failed_transient_count`

## FAILED_SAFE / rollback / operator guidance
- Step-level terminal failures become `FAILED_SAFE` in worker when:
  - validation fails
  - connector selection fails
  - non-retryable connector error occurs
  - max attempts exhausted
- Worker logs:
  - `step_failed_safe`
  - `roe_connector_terminal`
- `cmd/master-roe` reconciles these into run-level terminal or partial state and logs:
  - `response_run_updated`
  - `response_run_partial_completion` when some steps succeeded before failure
- Export fields carry:
  - `failed_safe_reason`
  - `operator_action`
- Implemented operator guidance values:
  - `manual_restore_check_recommended`
  - `manual_review_required`
- Approval timeout specifically:
  - `approval_timed_out`
  - `response_run_manual_review_required`
  - status becomes `MANUAL_REVIEW_REQUIRED`

---

# 6) Implementation Traceability Appendix

## Referenced file paths

```text
configs/agent.yaml
configs/collector.yaml
configs/collector-auditd.yaml
configs/collector-dns.yaml
configs/collector-inotify.yaml
configs/collector-netflowv5.yaml
configs/collector-procnet.yaml
configs/collector-snmptrap.yaml
configs/collector-syslog.yaml
configs/detector.yaml
configs/master.yaml

cmd/agent/main.go
cmd/agent/command.go
cmd/collector-tail/main.go
cmd/collector-syslog/main.go
cmd/collector-syslog-udp/main.go
cmd/collector-netflowv5/main.go
cmd/collector-snmptrap/main.go
cmd/collector-auditd/main.go
cmd/collector-inotify/main.go
cmd/collector-procnet/main.go
cmd/collector-dns/main.go
cmd/detector-v0/main.go
cmd/master/main.go
cmd/master-consume/main.go
cmd/master-roe/main.go
cmd/master-roe-worker/main.go
cmd/investigation-enricher/main.go
cmd/retention-query/main.go
cmd/signctl/main.go
cmd/ui-api/main.go
cmd/ui-api/model_editor.go
cmd/ui-api/response_actions.go

internal/config/collector_detector.go
internal/event/event.go
internal/collector/common/recent_context.go
internal/ingest/server.go
internal/pipeline/classifier.go
internal/pipeline/commit_manager.go
internal/pipeline/cooldown.go
internal/pipeline/enricher.go
internal/pipeline/lane_distributor.go
internal/pipeline/processor.go
internal/pipeline/transport.go
internal/pipeline/transport_grpc.go
internal/pipeline/trigger_dedupe.go
internal/pipeline/wal_writer.go
internal/retain/ingest.go
internal/retain/prune.go
internal/retain/query.go
internal/retain/types.go
internal/roe/connectors/builtins.go
internal/roe/trigger/publisher.go
internal/sign/*
internal/supervisor/supervisor.go

scripts/verify_fr01.sh
scripts/verify_fr01_full.sh
scripts/verify_fr02_mtls.sh
scripts/verify_fr02_rotation.sh
scripts/verify_fr02_revocation.sh
scripts/verify_fr02_full.sh
scripts/verify_fr03.sh
scripts/verify_fr04.sh
scripts/verify_fr05_full.sh
scripts/verify_fr06_ui_smoke.sh
scripts/verify_fr07_signing.sh
scripts/verify_fr07_rotation.sh
scripts/verify_fr08_retention.sh
scripts/verify_fr08_acceptance.sh
scripts/verify_new_playbooks.sh
scripts/verify_multiagent_targeting.sh
scripts/verify_attribution_continuity.sh
scripts/verify_full_demo_suite.sh
scripts/test_minimal_patch.sh
scripts/verify_response_actions_live.sh
scripts/deploy/linux/install_endpoint.sh
scripts/deploy/linux/rsiem-agent.service
scripts/deploy/linux/rsiem-collector-tail.service
scripts/deploy/linux/rsiem-collector-auditd.service
scripts/deploy/linux/rsiem-collector-inotify.service
scripts/deploy/linux/rsiem-collector-procnet.service
scripts/deploy/linux/rsiem-collector-dns.service
scripts/deploy/linux/rsiem-collector-syslog.service
scripts/deploy/master/master_up_lan.sh
scripts/deploy/master/master_down.sh
scripts/deploy/windows/install_endpoint.ps1
scripts/deploy/windows/uninstall_endpoint.ps1

docs/deploy/certs_allowlist_onboarding.md
docs/deploy/linux_endpoint_setup.md
docs/deploy/master_setup.md
docs/deploy/multi_endpoint_overview.md
docs/deploy/two_host_pilot.md
docs/deploy/windows_endpoint_setup.md
docs/fr02_db_schema.md
docs/fr02_mtls_lifecycle.md
docs/fr02_mtls_runbook.md
docs/fr06_ui.md
docs/fr07_signing_rotation.md
docs/fr08_schema.md
docs/fr08_sizing.md
```

## Grep hints for future auditors

```bash
rg "rsiem.response.triggers.fast|rsiem.response.triggers.standard" cmd internal configs
rg "rsiem.response.steps.fast|rsiem.response.steps.standard" cmd internal configs
rg "rsiem.response.results.fast|rsiem.response.results.standard" cmd internal configs
rg "rsiem.response.approvals|rsiem.response.approval_requests" cmd internal configs
rg "response_run_created|response_run_updated|approval_timed_out|response_run_manual_review_required" logs/master-roe.log cmd/master-roe/main.go
rg "step_succeeded|step_failed_safe|step_failed_transient|roe_connector_retry" logs/worker.log cmd/master-roe-worker/main.go
rg "agent_command_exec_start|agent_command_exec_done|agent_command_exec_denied" logs/agent.log cmd/agent/command.go
rg "detector_rule_matched|detector_alert_published|cooldown_hit" logs/detector.log cmd/detector-v0/main.go
rg "normalized_events" cmd/master-roe/main.go docs/fr02_db_schema.md docs/fr08_schema.md
rg "user_name" cmd/master-roe/main.go cmd/ui-api/main.go
rg "FR02_|FR03_|FR04_|FR05_|FR07_|FR08_|NEW_PLAYBOOKS_PROOF_JSON|ATTRIBUTION_CONTINUITY_PROOF_JSON" scripts
rg "PB-" configs/master.yaml scripts/verify_new_playbooks.sh
rg "allowed_action_types|action_allowlist|guardrails|approvals:" configs/master.yaml
rg "sign-bundle|verify-bundle|sign-batch|verify-batch|rotate-key" cmd/signctl/main.go docs/fr07_signing_rotation.md
rg "GET /api/search/events|GET /api/incidents/{run_id}/logic|GET /api/actions|GET /api/entities/ip/{ip}|GET /api/entities/user/{user}|GET /api/investigation/providers" cmd/ui-api/main.go
```

## Explicit UNKNOWNs

- Exact rule-definition blocks for:
  - `R-PB-BRUTEFORCE-IP-CONTAIN`
  - `R-PB-PRIVESC-LOCKDOWN`
  - `R-PB-LATERAL-MOVEMENT-HALT`
  - `R-PB-C2-BEACON-BLOCK`
  - `R-PB-RANSOMWARE-KILL-CHAIN-STOP`
  - `R-PB-DATA-EXFIL-THROTTLE`
  - `R-PB-CRITICAL-SERVICE-ABUSE-RESPONSE`
  - `R-PB-DETECTOR-HEALTH-SELF-PROTECT`
- Per-playbook fixed lane values are **UNKNOWN / not configured**, because playbooks do not declare a lane and `response_triggers.lane_policy` is `from_alert`.
- `collector-syslog-udp` has an implemented executable, but a distinct standalone YAML surface beyond code defaults is not evidenced in the scanned config files.
