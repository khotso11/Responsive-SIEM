# R-SIEM System Testing Manual

## 1. Purpose

This manual defines the recommended testing process for the current R-SIEM repository. It consolidates the implemented verifier scripts, live smoke checks, and evidence expectations into one operational testing reference.

The document is intended to support:

- project verification before demonstrations or assessment
- repeatable functional testing
- evidence collection for reports and presentations
- controlled regression checks after changes

This testing manual is based on scripts and proof paths already committed in the repository.

## 2. Testing Principles

The repository follows an evidence-first test model. A test is considered complete only when:

1. the canonical script runs successfully
2. the required `PASS:` line is printed
3. the proof artifact path is printed
4. the referenced artifact exists on disk

Primary evidence locations:

- `demo_artifacts/<timestamp>/...`
- `logs/*.log`
- `exports/roe_runs.jsonl`
- `exports/roe_steps.jsonl`
- `retained/*.jsonl`

## 3. Test Environment Categories

### 3.1 Fast repository verification

Use when validating script-level functionality without a full live demo path.

Typical stack:

- `./scripts/demo_up.sh`
- `./scripts/ui_up.sh` when UI coverage is required

### 3.2 Live supervisor demonstration verification

Use when validating:

- endpoint collectors
- UI workflows
- approval-gated response
- autonomous containment

Primary launcher:

```bash
REAL_SYSTEM=1 UI_WEB_PORT=3200 ./scripts/demo_local_endpoint_clean_start.sh
```

### 3.3 Multi-endpoint or deployment-path verification

Use when validating:

- Linux endpoint deployment
- Windows endpoint deployment
- LAN master deployment
- EVE-NG or emulated infrastructure workflows

Reference:

- [docs/deploy/master_setup.md](/home/khotso/Final/projects/r-siem-agent/docs/deploy/master_setup.md)
- [docs/deploy/linux_endpoint_setup.md](/home/khotso/Final/projects/r-siem-agent/docs/deploy/linux_endpoint_setup.md)
- [docs/deploy/windows_endpoint_setup.md](/home/khotso/Final/projects/r-siem-agent/docs/deploy/windows_endpoint_setup.md)

## 4. Pre-Test Checklist

Before executing any formal test run:

- confirm the working tree is in the expected state
- confirm required tools are installed
- confirm no conflicting UI port is already in use
- confirm `logs/`, `exports/`, and `demo_artifacts/` are writable
- confirm Docker is available if DB-backed proofs are required
- confirm NATS connectivity if running distributed paths

Recommended checks:

```bash
cd ~/projects/r-siem-agent
git status --short
docker ps --format 'table {{.Names}}\t{{.Status}}'
rg -n 'UI_WEB_PORT|UI_API_ADDR' scripts/ui_up.sh
```

For live endpoint tests on Linux:

```bash
sudo systemctl is-active ssh || true
command -v nmap
command -v tcpdump
```

## 5. Test Levels

### 5.1 Smoke tests

Used to prove that a service plane starts and responds.

Examples:

- UI smoke: [scripts/verify_fr06_ui_smoke.sh](/home/khotso/Final/projects/r-siem-agent/scripts/verify_fr06_ui_smoke.sh)
- local FR-01 collector smoke: [scripts/verify_fr01.sh](/home/khotso/Final/projects/r-siem-agent/scripts/verify_fr01.sh)

### 5.2 Functional requirement verification

Used to verify implemented FR coverage through canonical scripts:

- FR-01 ingestion and normalization
- FR-02 secure transport and TLS lifecycle
- FR-03 correlation and latency
- FR-04 deception, capture, and chain of custody
- FR-05 response safety
- FR-06 UI
- FR-07 signing and key rotation
- FR-08 retention and export

### 5.3 Scenario or demonstration tests

Used to show end-to-end behavior under realistic operator workflows.

Examples:

- supervisor demo runbook
- local endpoint triptych flow
- live response-action proof

## 6. Canonical Functional Test Matrix

| Requirement area | Primary script | Expected success line | Primary proof output |
|---|---|---|---|
| FR-01 acceptance | `./scripts/verify_fr01_acceptance.sh` | `PASS: FR-01 acceptance completed` | `FR01_ACCEPTANCE_PROOF_JSON=...` |
| FR-02 full suite | `./scripts/verify_fr02_full.sh` | `PASS: FR-02 full suite completed` | FR-02 proof lines printed by suite |
| FR-03 | `./scripts/verify_fr03.sh` | `PASS: FR-03 correlation+severity+latency completed` | `FR03_PROOF_JSON=...` |
| FR-04 | `./scripts/verify_fr04.sh` | `PASS: FR-04 live honeypot+pcap+chain_of_custody completed` | `FR04_PROOF_JSON=...` |
| FR-05 full suite | `./scripts/verify_fr05_full.sh` | `PASS: FR-05 full suite completed` | `FR05_SUCCESS_PROOF_JSON=...`, `FR05_FAILED_SAFE_PROOF_JSON=...` |
| FR-05 acceptance | `./scripts/verify_fr05_acceptance.sh` | `PASS: FR-05 acceptance completed` | `FR05_ACCEPTANCE_PROOF_JSON=...` |
| FR-06 UI smoke | `./scripts/verify_fr06_ui_smoke.sh` | `PASS: FR-06 UI smoke completed` | `FR06_UI_PROOF_JSON=...` |
| FR-07 full suite | `./scripts/verify_fr07_full.sh` | `PASS: FR-07 full suite completed` | FR-07 proof lines printed by suite |
| FR-08 retention | `./scripts/verify_fr08_retention.sh` | `PASS: FR-08 retention+query+export completed` | `FR08_PROOF_JSON=...` |
| FR-08 acceptance | `./scripts/verify_fr08_acceptance.sh` | `PASS: FR-08 acceptance completed` | `FR08_ACCEPTANCE_PROOF_JSON=...` |

## 7. Recommended Test Execution Order

For a clean verification cycle, use the following order.

### 7.1 Foundation

1. `./scripts/demo_up.sh`
2. `./scripts/ui_up.sh` if UI checks are required
3. `curl -sS http://127.0.0.1:8090/api/health`

### 7.2 Core functional proofs

1. `./scripts/verify_fr01_acceptance.sh`
2. `./scripts/verify_fr02_full.sh`
3. `./scripts/verify_fr03.sh`
4. `./scripts/verify_fr04.sh`
5. `./scripts/verify_fr05_full.sh`
6. `./scripts/verify_fr06_ui_smoke.sh`
7. `./scripts/verify_fr07_full.sh`
8. `./scripts/verify_fr08_acceptance.sh`

### 7.3 Live demo readiness checks

1. `REAL_SYSTEM=1 UI_WEB_PORT=3200 ./scripts/demo_local_endpoint_clean_start.sh`
2. `./scripts/verify_response_actions_live.sh`
3. scenario-specific endpoint checks from the supervisor runbook

## 8. UI and Workflow Testing

The UI/API should be tested as both an application surface and an operational control surface.

### 8.1 Startup verification

Run:

```bash
./scripts/ui_up.sh
```

Confirm:

- `PASS: FR-06 UI services started`
- `UI_WEB_URL=http://127.0.0.1:3200`
- `UI_API_URL=http://127.0.0.1:8090`

### 8.2 UI smoke script

Run:

```bash
./scripts/verify_fr06_ui_smoke.sh
```

Confirm:

- UI health is reachable
- login succeeds
- main pages load expected API-backed data
- proof artifact is generated

### 8.3 Manual UI workflow verification

Recommended manual checks:

1. log in as analyst
2. open `Incidents`
3. open an incident and review overview, evidence, and steps
4. open `Endpoints` and confirm node context renders
5. open `Audit` and confirm governance actions render
6. if an approval-gated run exists, approve or reject it and confirm audit recording

Reference:

- [docs/fr06_ui.md](/home/khotso/Final/projects/r-siem-agent/docs/fr06_ui.md)
- [docs/ui.md](/home/khotso/Final/projects/r-siem-agent/docs/ui.md)

## 9. Endpoint and Collector Testing

### 9.1 Linux endpoint collection

Recommended proof path:

```bash
REAL_SYSTEM=1 UI_WEB_PORT=3200 ./scripts/demo_local_endpoint_clean_start.sh
sudo systemctl is-active ssh rsiem-agent rsiem-collector-tail rsiem-collector-auditd rsiem-collector-procnet rsiem-collector-dns
```

This validates that the local Linux endpoint services are active before live telemetry scenarios are attempted.

### 9.2 Real event smoke

Run:

```bash
./scripts/real_agent_event_smoke.sh
```

Use this to confirm that real endpoint activity is reflected in collector logs and downstream processing.

### 9.3 First-seen containment

Run:

```bash
./scripts/verify_first_seen_containment.sh
```

This is a stronger endpoint-oriented test because it exercises `proc_net` and `auditd_connect` containment logic.

### 9.4 Windows endpoint deployment testing

Repository-backed Windows validation is primarily deployment-oriented.

Recommended checks:

1. run the Windows installer
2. confirm `rsiem-agent` and `rsiem-collector-tail` services exist
3. confirm logs are being written under `C:\ProgramData\rsiem\logs`
4. confirm the endpoint can participate in shared transport and collection flows

Reference:

- [docs/deploy/windows_endpoint_setup.md](/home/khotso/Final/projects/r-siem-agent/docs/deploy/windows_endpoint_setup.md)

## 10. Response and Safety Testing

### 10.1 Live response action lifecycle

Run:

```bash
./scripts/verify_response_actions_live.sh
```

This test validates:

- incident-scoped action launch
- endpoint-scoped action launch
- active lifecycle state
- clear operation
- fleet action visibility

### 10.2 FR-05 response safety

Run:

```bash
./scripts/verify_fr05_full.sh
./scripts/verify_fr05_acceptance.sh
```

These scripts validate:

- successful response execution
- fail-safe behavior
- rollback-oriented evidence
- audit field completeness

### 10.3 Quarantine and restore proof

Run when file quarantine behavior must be explicitly demonstrated:

```bash
./scripts/mf05_quarantine_rollback_proof.sh
```

## 11. Evidence Handling During Testing

For every formal test run:

1. capture terminal output
2. record the exact `PASS:` line
3. record the proof variable and path
4. verify the artifact exists
5. retain the artifact path in the test log or report

Recommended evidence capture template:

- test name
- execution date and time
- operator
- command used
- expected result
- actual `PASS:` line
- proof artifact path
- notes or deviations

## 12. Failure Handling

If a test fails:

1. do not immediately rerun the full suite
2. identify the exact failing script and stage
3. inspect:
   - `logs/*.log`
   - `demo_artifacts/<timestamp>/...`
   - `exports/roe_*.jsonl`
4. classify the failure as:
   - environment setup issue
   - service start issue
   - proof artifact issue
   - functional regression

Recommended defect record fields:

- failing test
- reproduction command
- observed output
- expected output
- affected component
- temporary workaround

## 13. Post-Test Cleanup

After testing:

```bash
./scripts/ui_down.sh
./scripts/demo_down.sh
```

If the test used local presentation-state preparation, also review:

- [scripts/reset_presentation_demo_state.sh](/home/khotso/Final/projects/r-siem-agent/scripts/reset_presentation_demo_state.sh)

Do not delete generated proof artifacts that are still needed for reporting or assessment.

## 14. Related Repository References

- [README.md](/home/khotso/Final/projects/r-siem-agent/README.md)
- [docs/system_manual.md](/home/khotso/Final/projects/r-siem-agent/docs/system_manual.md)
- [docs/deploy/master_setup.md](/home/khotso/Final/projects/r-siem-agent/docs/deploy/master_setup.md)
- [docs/deploy/linux_endpoint_setup.md](/home/khotso/Final/projects/r-siem-agent/docs/deploy/linux_endpoint_setup.md)
- [docs/deploy/windows_endpoint_setup.md](/home/khotso/Final/projects/r-siem-agent/docs/deploy/windows_endpoint_setup.md)
