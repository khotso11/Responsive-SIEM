# Investigation Enrichment Plan

## Goal

Add a first-class investigation enrichment layer to R-SIEM so network, DNS, URL, and file-facing incidents are not limited to:

- `node_id`
- `src_ip`
- `dst_ip`
- raw rule/playbook metadata

The system should enrich observables with external investigation context and present that context in the existing SOC workflow.

This plan is written against the current repo structure:

- control plane and DB sink: `cmd/master-roe`
- incident assembly and API: `cmd/ui-api`
- SOC workspace: `ui/components/incident-drawer.tsx`
- existing endpoint telemetry and incident fields:
  - `src_ip`
  - `dst_ip`
  - `user`
  - `exec_path`
  - `comm`
  - `cmdline`
  - `attribution_source`

## Current State

The repo already has the right anchors:

- incidents are assembled centrally in `cmd/ui-api/main.go`
- the UI already has an `Investigation Workspace`
- `normalized_events` already stores core fields such as:
  - `src_ip`
  - `dst_ip`
  - `user_name`
  - `rule_id`
  - `event_idem_key`
- file/network/process attribution has materially improved, so investigation can now start from better incident context

What is missing:

- no external enrichment worker
- no provider adapters
- no DB tables for investigation observables/results
- no API endpoint for incident investigation bundles
- no provider-backed investigation panel in the UI

## Non-goals

Phase 1 should not try to do all of these:

- STIX/TAXII platform integration
- full CTI graphing
- automatic provider fanout from the browser
- public submission of internal observables by default
- enrichment for private/RFC1918 IPs
- automatic blocking based purely on third-party reputation

Phase 1 should be:

- asynchronous
- cached
- auditable
- provider-rate-limited
- privacy-aware

## Observable Model

Use a normalized observable model first. Everything else hangs off this.

### Observable kinds

- `ip`
- `domain`
- `url`
- `sha256`

Phase 1 focus:

- `ip`
- `domain`
- `url`

`sha256` should be wired into the schema now because the repo already has file/process hash fields and VirusTotal is more valuable once hashes exist consistently.

### Observable extraction rules

For each incident, derive observables from:

- `dst_ip`
- `src_ip` only if external and investigation-relevant
- `dns_name`
- URL fields when present in future detections
- `exec_sha256`
- `file_sha256`

Do not send these to external providers by default:

- RFC1918/internal IPs
- loopback
- local hostnames
- unapproved internal URLs/domains

## Enrichment Event Schema

Introduce explicit enrichment job events over NATS.

### Subjects

- `rsiem.investigation.enrich.requested`
- `rsiem.investigation.enrich.completed`

Phase 1 can operate with only `requested`; `completed` is optional if UI/API read directly from DB.

### Requested payload

```json
{
  "job_id": "ienrich.01H...",
  "run_id": "9ba17ab7d2cdb8cc",
  "requested_at_unix_ms": 1773309000000,
  "requested_by": "system",
  "priority": "normal",
  "observables": [
    {
      "kind": "ip",
      "value": "93.184.216.34",
      "role": "destination_ip",
      "source": "incident.run.dst_ip"
    },
    {
      "kind": "domain",
      "value": "example.com",
      "role": "queried_domain",
      "source": "normalized_event.dns_name"
    }
  ],
  "privacy_mode": "external_safe",
  "refresh": false
}
```

### Result shape

Store provider results in normalized form rather than leaking raw provider JSON directly into incident assembly.

```json
{
  "job_id": "ienrich.01H...",
  "run_id": "9ba17ab7d2cdb8cc",
  "observable_kind": "ip",
  "observable_value": "93.184.216.34",
  "provider": "greynoise",
  "status": "ok",
  "provider_verdict": "noise",
  "provider_score": 20,
  "summary": "Internet scanner / mass internet background",
  "evidence_url": "https://viz.greynoise.io/ip/93.184.216.34",
  "raw_ref": "blob://...",
  "fetched_at_unix_ms": 1773309002500,
  "expires_at_unix_ms": 1773395402500,
  "data": {
    "noise": true,
    "riot": false,
    "classification": "benign_scanner",
    "tags": ["ssh", "masscan"]
  }
}
```

## Provider Adapter Interface

Add a dedicated internal package:

- `internal/investigation`

Recommended layout:

- `internal/investigation/types.go`
- `internal/investigation/engine.go`
- `internal/investigation/cache.go`
- `internal/investigation/providers/greynoise.go`
- `internal/investigation/providers/abuseipdb.go`
- `internal/investigation/providers/virustotal.go`
- `internal/investigation/providers/urlscan.go`

### Types

```go
package investigation

type ObservableKind string

const (
    ObservableIP     ObservableKind = "ip"
    ObservableDomain ObservableKind = "domain"
    ObservableURL    ObservableKind = "url"
    ObservableSHA256 ObservableKind = "sha256"
)

type Observable struct {
    Kind   ObservableKind `json:"kind"`
    Value  string         `json:"value"`
    Role   string         `json:"role"`
    Source string         `json:"source"`
}

type ProviderResult struct {
    Provider       string         `json:"provider"`
    Status         string         `json:"status"`
    Verdict        string         `json:"verdict"`
    Score          int            `json:"score"`
    Summary        string         `json:"summary"`
    EvidenceURL    string         `json:"evidence_url"`
    FetchedAtUnix  int64          `json:"fetched_at_unix_ms"`
    ExpiresAtUnix  int64          `json:"expires_at_unix_ms"`
    Data           map[string]any `json:"data"`
}

type Provider interface {
    Name() string
    Supports(kind ObservableKind) bool
    Enrich(ctx context.Context, obs Observable) (ProviderResult, error)
}
```

### Engine behavior

The engine should:

1. receive a job
2. expand incident observables
3. filter by privacy rules
4. check cache / DB TTL
5. call only relevant providers
6. normalize/store results
7. expose a merged incident investigation bundle

Do not make providers write directly to UI/API state.

## Providers To Implement First

Phase 1 core:

1. `GreyNoise`
2. `AbuseIPDB`
3. `VirusTotal`

Phase 1b:

4. `urlscan` for URL/domain cases only

### 1. GreyNoise

Use for external IP triage.

Value:

- scanner/noise classification
- benign internet background suppression
- tags and activity hints

Recommended observables:

- `ip`

Recommended result fields:

- `noise`
- `riot`
- `classification`
- `tags`
- `link`

### 2. AbuseIPDB

Use for quick IP abuse scoring.

Value:

- confidence score
- abuse categories
- report count
- last reported time

Recommended observables:

- `ip`

Recommended result fields:

- `abuse_confidence_score`
- `total_reports`
- `last_reported_at`
- `categories`
- `country_code`
- `usage_type`

### 3. VirusTotal

Use for:

- IP
- domain
- URL
- hash

Value:

- multi-engine consensus
- malicious/suspicious counts
- relationships
- external links

Recommended observables:

- `ip`
- `domain`
- `url`
- `sha256`

Recommended result fields:

- `malicious`
- `suspicious`
- `harmless`
- `reputation`
- `last_analysis_stats`
- `permalink`

### 4. urlscan

Add only for URL/domain cases.

Do not run this for every domain by default.

Use for:

- suspicious URLs
- phishing/web content
- redirect investigation
- screenshot/report links

Recommended observables:

- `url`
- optionally `domain`

Recommended controls:

- default visibility should not be public for sensitive/internal cases
- only submit if privacy mode allows it

## DB Changes

Add investigation tables in the same DB initialization path that already manages `normalized_events`:

- `cmd/master-roe/main.go`

### Tables

#### 1. `incident_observables`

Maps incident runs to normalized observables.

```sql
CREATE TABLE IF NOT EXISTS incident_observables (
  id BIGSERIAL PRIMARY KEY,
  run_id TEXT NOT NULL,
  observable_kind TEXT NOT NULL,
  observable_value TEXT NOT NULL,
  observable_role TEXT NOT NULL,
  observable_source TEXT NOT NULL,
  created_at_unix_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS incident_observables_run_idx
  ON incident_observables(run_id);
CREATE INDEX IF NOT EXISTS incident_observables_value_idx
  ON incident_observables(observable_kind, observable_value);
```

#### 2. `observable_enrichments`

Normalized cached provider results.

```sql
CREATE TABLE IF NOT EXISTS observable_enrichments (
  id BIGSERIAL PRIMARY KEY,
  observable_kind TEXT NOT NULL,
  observable_value TEXT NOT NULL,
  provider TEXT NOT NULL,
  status TEXT NOT NULL,
  provider_verdict TEXT NOT NULL,
  provider_score INT NOT NULL,
  summary TEXT NOT NULL,
  evidence_url TEXT NOT NULL,
  data_json JSONB NOT NULL,
  fetched_at_unix_ms BIGINT NOT NULL,
  expires_at_unix_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS observable_enrichments_lookup_idx
  ON observable_enrichments(observable_kind, observable_value, provider);
```

#### 3. `enrichment_jobs`

Tracks job lifecycle and auditability.

```sql
CREATE TABLE IF NOT EXISTS enrichment_jobs (
  job_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  status TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  requested_at_unix_ms BIGINT NOT NULL,
  completed_at_unix_ms BIGINT NULL,
  refresh BOOLEAN NOT NULL DEFAULT FALSE,
  error_text TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS enrichment_jobs_run_idx
  ON enrichment_jobs(run_id);
```

### Why DB first

This keeps:

- provider TTL handling centralized
- UI/API thin
- incident reload deterministic
- external requests auditable

## New Runtime Component

Add:

- `cmd/investigation-enricher/main.go`

Responsibilities:

- subscribe to enrichment requests
- extract observables from incidents or accept provided observables
- fan out to providers
- upsert `incident_observables`
- upsert `observable_enrichments`
- update `enrichment_jobs`

Configuration:

- API keys via env vars
- provider enable/disable flags
- TTLs
- rate limits
- privacy mode

Suggested env vars:

- `GREYNOISE_API_KEY`
- `ABUSEIPDB_API_KEY`
- `VT_API_KEY`
- `URLSCAN_API_KEY`

## UI API Changes

Add these endpoints in `cmd/ui-api/main.go`.

### 1. `GET /api/incidents/{run_id}/investigation`

Returns a merged investigation bundle:

```json
{
  "run": { "...": "existing incident fields" },
  "observables": [
    {
      "kind": "ip",
      "value": "93.184.216.34",
      "role": "destination_ip",
      "source": "incident.run.dst_ip",
      "providers": [
        {
          "provider": "greynoise",
          "status": "ok",
          "verdict": "noise",
          "score": 20,
          "summary": "Internet background scanner",
          "evidence_url": "...",
          "data": { "...": "..." }
        }
      ]
    }
  ],
  "job": {
    "status": "completed",
    "requested_at_unix_ms": 1773309000000,
    "completed_at_unix_ms": 1773309002500
  }
}
```

### 2. `POST /api/incidents/{run_id}/investigation/refresh`

Role:

- `analyst` or `admin`

Behavior:

- publishes a new enrichment request
- returns accepted job metadata

### 3. `GET /api/investigation/providers`

Optional but useful for UI status:

- enabled providers
- last health error
- rate-limit status

## UI Changes

The existing investigation workspace already exists in:

- `ui/components/incident-drawer.tsx`

Reuse it. Do not invent another incident detail system.

### Investigation tab changes

Use the existing `evidence` tab first.

Add a new section:

- `External Intelligence`

Suggested blocks:

1. `Observables`
   - IP/domain/URL/hash chips
   - role and source labels

2. `Provider Cards`
   - GreyNoise
   - AbuseIPDB
   - VirusTotal
   - urlscan when relevant

3. `Summary`
   - external reputation summary
   - abuse/noise decision
   - first/last seen if available

4. `Links`
   - provider evidence URLs
   - raw lookup references if retained

5. `Refresh`
   - button to re-run enrichment

### Incident detail UI fields

Each observable row should show:

- kind
- value
- role
- last fetched
- provider verdict badges

Each provider card should show:

- provider name
- verdict
- score
- short summary
- evidence link
- compact raw details

## Provider-Normalized Investigation View

Phase 1 normalized badges:

- `malicious`
- `suspicious`
- `abusive`
- `scanner/noise`
- `unknown`

Do not force providers into a fake universal score. Keep:

- provider verdict
- provider score
- summary

Then optionally derive a local merged view:

- `investigation_posture`
  - `malicious`
  - `suspicious`
  - `internet_noise`
  - `benign`
  - `unknown`

## Privacy And Safety Rules

These rules should be built in from day one.

### Do not submit externally by default

- RFC1918 IPs
- loopback
- `.local` names
- internal URLs/domains
- internal-only hashes without policy approval

### Cache aggressively

Suggested TTLs:

- GreyNoise IP: `24h`
- AbuseIPDB IP: `6h`
- VirusTotal IP/domain/url/hash: `12h`
- urlscan URL/domain: `24h`

### Rate limit per provider

The worker should enforce provider-local rate limits and backoff.

### Audit every enrichment request

At minimum:

- who requested it
- when
- which observables were sent
- which providers were called
- whether privacy policy suppressed any observable

## Implementation Order

### Phase 1: Core schema and worker

Files:

- `cmd/investigation-enricher/main.go`
- `internal/investigation/types.go`
- `internal/investigation/engine.go`
- DB table creation in `cmd/master-roe/main.go`

Output:

- jobs can be requested
- observables are stored
- worker runs with no providers yet

### Phase 2: Provider adapters

Files:

- `internal/investigation/providers/greynoise.go`
- `internal/investigation/providers/abuseipdb.go`
- `internal/investigation/providers/virustotal.go`
- `internal/investigation/providers/urlscan.go`

Output:

- GreyNoise, AbuseIPDB, VirusTotal live
- urlscan gated to URL/domain use only

### Phase 3: UI API

Files:

- `cmd/ui-api/main.go`

Output:

- incident investigation bundle endpoint
- refresh endpoint

### Phase 4: UI

Files:

- `ui/lib/api.ts`
- `ui/lib/types.ts`
- `ui/components/incident-drawer.tsx`
- optional:
  - `ui/app/incidents/[runId]/page.tsx`

Output:

- investigation panel visible in existing workspace
- refresh action
- provider cards and observable chips

### Phase 5: Verification

Add proof scripts:

- `scripts/verify_investigation_enrichment.sh`

Verify:

- external IP incident gets GreyNoise/AbuseIPDB/VT enrichment
- URL/domain case gets VT and urlscan where allowed
- UI panel renders provider results and refresh behavior

## Acceptance Criteria

The plan is complete when all of these are true:

1. a fresh outbound IP incident can be enriched asynchronously
2. the incident API returns:
   - observables
   - provider results
   - job status
3. UI shows:
   - provider verdicts
   - provider links
   - last fetched time
4. external/private observables are filtered correctly
5. enrichment results are cached with TTL
6. refresh works without duplicate uncontrolled fanout
7. every enrichment request is auditable

## Recommended First Concrete Build

Start with:

1. DB tables
2. `cmd/investigation-enricher`
3. GreyNoise adapter
4. AbuseIPDB adapter
5. VirusTotal adapter
6. `GET /api/incidents/{run_id}/investigation`
7. `Evidence -> External Intelligence` section in the drawer

Add `urlscan` only after URL/domain observables are naturally present in your incidents and privacy controls are explicit.
