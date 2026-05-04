# R-SIEM System Manual

## 1. Purpose

This manual describes how to start, operate, verify, and shut down the current repository implementation of the Responsive Security Event and Information Management System (R-SIEM).

It is intended for:

- system administrators preparing or maintaining the environment
- analysts using the SOC console and response workflow
- project examiners or supervisors who need a clear operating reference

This manual is based on the implemented repository state. Where functionality is optional or environment-dependent, that is stated explicitly.

## 2. System Scope

The repository implements the following major capability areas:

- telemetry collection from multiple collector types
- transport over NATS JetStream and gRPC mTLS
- event detection and correlation
- rule-of-engagement response orchestration
- analyst and admin workflows through the UI
- audit, exports, and retained evidence

Primary components:

- `cmd/collector-*`
- `cmd/agent`
- `cmd/detector-v0`
- `cmd/master`
- `cmd/master-consume`
- `cmd/master-roe`
- `cmd/master-roe-worker`
- `cmd/ui-api`
- `ui/`
- `cmd/retention-query`

Reference implementation summary:

- [README.md](/home/khotso/Final/projects/r-siem-agent/README.md)
- [docs/implementation_writeup.md](/home/khotso/Final/projects/r-siem-agent/docs/implementation_writeup.md)

## 3. Operational Roles

### 3.1 Analyst

The analyst is expected to:

- review incidents
- investigate timeline and evidence
- review endpoint context
- approve or reject approval-gated incidents when permitted
- launch allowed response actions
- monitor action lifecycle and audit traces

Relevant UI surfaces:

- `Incidents`
- `Endpoints`
- `Actions`
- `Audit`

Reference:

- [docs/fr06_ui.md](/home/khotso/Final/projects/r-siem-agent/docs/fr06_ui.md)
- [docs/ui.md](/home/khotso/Final/projects/r-siem-agent/docs/ui.md)

### 3.2 Administrator

The administrator is expected to:

- start and stop services
- maintain certificates and endpoint onboarding
- manage users and notification settings
- validate proofs and artifact generation
- supervise changes to environment configuration

Reference:

- [docs/deploy/master_setup.md](/home/khotso/Final/projects/r-siem-agent/docs/deploy/master_setup.md)
- [docs/deploy/certs_allowlist_onboarding.md](/home/khotso/Final/projects/r-siem-agent/docs/deploy/certs_allowlist_onboarding.md)

## 4. Prerequisites

Minimum host requirements depend on which features are exercised, but the current repository assumes the following tools are available:

- `go`
- `docker`
- `jq`
- `rg`
- `nats` CLI
- `openssl`
- `tcpdump` for packet-capture proofs
- `systemd` on Linux for endpoint and demo service flows

Optional but commonly used during live demos and endpoint proofs:

- `nmap`
- `openssh-server`

## 5. Directory and Evidence Layout

Important repository locations:

- source code: `cmd/`, `internal/`, `ui/`
- runtime scripts: `scripts/`
- configs: `configs/`
- documentation: `docs/`
- runtime logs: `logs/`
- ROE exports: `exports/roe_runs.jsonl`, `exports/roe_steps.jsonl`
- retained outputs: `retained/`
- proof artifacts: `demo_artifacts/<timestamp>/...`

These paths should be preserved during operation because they form part of the project evidence trail.

## 6. Core Runtime Architecture

At a high level, the implemented runtime flow is:

1. collectors publish normalized raw events
2. detector rules evaluate the event stream
3. the response orchestrator creates and gates runs
4. workers execute steps or dispatch endpoint commands
5. the UI/API exposes incidents, evidence, actions, and audit history

The main repository references for this flow are:

- [README.md](/home/khotso/Final/projects/r-siem-agent/README.md)
- [docs/implementation_writeup.md](/home/khotso/Final/projects/r-siem-agent/docs/implementation_writeup.md)
- [docs/deploy/multi_endpoint_overview.md](/home/khotso/Final/projects/r-siem-agent/docs/deploy/multi_endpoint_overview.md)

## 7. Starting the System

### 7.1 Baseline backend stack

To start the core demo stack:

```bash
cd ~/projects/r-siem-agent
./scripts/demo_up.sh
```

This brings up the repository demo services used by the core FR verifier scripts.

To stop the stack:

```bash
./scripts/demo_down.sh
```

### 7.2 UI stack

To start the UI and API:

```bash
./scripts/ui_up.sh
```

Expected output:

```text
PASS: FR-06 UI services started
UI_WEB_URL=http://127.0.0.1:3200
UI_API_URL=http://127.0.0.1:8090
```

To stop the UI:

```bash
./scripts/ui_down.sh
```

Reference:

- [scripts/ui_up.sh](/home/khotso/Final/projects/r-siem-agent/scripts/ui_up.sh)
- [scripts/ui_down.sh](/home/khotso/Final/projects/r-siem-agent/scripts/ui_down.sh)

### 7.3 Supervisor presentation path

For the live endpoint-and-UI demonstration flow:

```bash
REAL_SYSTEM=1 UI_WEB_PORT=3200 ./scripts/demo_local_endpoint_clean_start.sh
```

This path is used when the system is being demonstrated with local endpoint collectors and UI workflows together.

Reference:

- [scripts/demo_local_endpoint_clean_start.sh](/home/khotso/Final/projects/r-siem-agent/scripts/demo_local_endpoint_clean_start.sh)
- [docs/fr06_ui.md](/home/khotso/Final/projects/r-siem-agent/docs/fr06_ui.md)

## 8. Endpoint Deployment

### 8.1 Linux endpoint deployment

Linux endpoint deployment is performed with:

```bash
sudo ./scripts/deploy/linux/install_endpoint.sh \
  --master-ip "<MASTER_IP>" \
  --agent-id "linux-endpoint-01" \
  --nats-url "nats://<MASTER_IP>:4222" \
  --config-dir /tmp/rsiem-endpoint-package
```

Linux deployment provisions:

- `agent`
- `collector-tail`
- optional collectors such as `collector-auditd`, `collector-inotify`, `collector-procnet`, and `collector-dns`
- `systemd` service units
- endpoint config under `/etc/rsiem/configs`

Reference:

- [docs/deploy/linux_endpoint_setup.md](/home/khotso/Final/projects/r-siem-agent/docs/deploy/linux_endpoint_setup.md)
- [scripts/deploy/linux/install_endpoint.sh](/home/khotso/Final/projects/r-siem-agent/scripts/deploy/linux/install_endpoint.sh)

### 8.2 Windows endpoint deployment

Windows endpoint deployment is performed with:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install_endpoint.ps1 `
  -MasterIp <MASTER_IP> `
  -AgentId win-endpoint-01 `
  -NatsUrl nats://<MASTER_IP>:4222 `
  -InstallDir C:\ProgramData\rsiem
```

Windows deployment provisions:

- `agent.exe`
- `collector-tail.exe`
- service registration for `rsiem-agent` and `rsiem-collector-tail`
- local config, PKI, WAL, and log directories

Reference:

- [docs/deploy/windows_endpoint_setup.md](/home/khotso/Final/projects/r-siem-agent/docs/deploy/windows_endpoint_setup.md)
- [scripts/deploy/windows/install_endpoint.ps1](/home/khotso/Final/projects/r-siem-agent/scripts/deploy/windows/install_endpoint.ps1)

## 9. Normal Operating Workflow

### 9.1 Confirm service health

Backend and UI health should be checked first:

```bash
curl -sS http://127.0.0.1:8090/api/health
```

For Linux endpoint demo mode:

```bash
sudo systemctl is-active \
  ssh \
  rsiem-agent \
  rsiem-collector-tail \
  rsiem-collector-auditd \
  rsiem-collector-procnet \
  rsiem-collector-dns
```

### 9.2 Open the UI

Open:

```text
http://127.0.0.1:3200
```

Primary pages:

- `Incidents`
- `Endpoints`
- `Actions`
- `Search`
- `Models`
- `Audit`

### 9.3 Investigate incidents

On the `Incidents` page, the operator should:

1. identify new or active incidents
2. open the incident detail or drawer
3. review overview, steps, timeline, evidence, and actions
4. determine whether approval, investigation, or response is required

### 9.4 Manage approval-gated runs

For incidents in `WAITING_APPROVAL` or equivalent approval-gated states:

1. inspect evidence and context
2. approve or reject using the UI
3. confirm the action is captured in the audit view

### 9.5 Launch manual response actions

Supported UI-managed action categories include:

- blocking matching connections
- blocking inbound or outbound targets
- quarantining a device
- enforcing pattern-of-life containment

The operator should:

1. choose the incident or endpoint context
2. launch the action with a bounded duration
3. confirm the lifecycle state moves through the expected bucket
4. clear or allow expiry as required

Reference:

- [cmd/ui-api/response_actions.go](/home/khotso/Final/projects/r-siem-agent/cmd/ui-api/response_actions.go)
- [scripts/verify_response_actions_live.sh](/home/khotso/Final/projects/r-siem-agent/scripts/verify_response_actions_live.sh)

## 10. Evidence and Audit Handling

The system generates evidence in several places:

- incident and response records in `exports/`
- retained JSONL outputs in `retained/`
- generated proof artifacts in `demo_artifacts/`
- audit activity in the UI/API audit endpoints

When preparing reports or presentations:

1. preserve printed `PASS:` lines from verifier scripts
2. preserve the proof JSON path printed by the script
3. confirm the referenced artifact exists on disk

This is the repository’s evidence-first operating model.

## 11. Notifications and User Administration

The UI/API supports user administration with:

- username
- role
- email address
- notification-enabled flag
- disabled flag

Reference:

- [docs/fr06_ui.md](/home/khotso/Final/projects/r-siem-agent/docs/fr06_ui.md)
- [docs/ui_rbac.md](/home/khotso/Final/projects/r-siem-agent/docs/ui_rbac.md)

If email notifications are enabled in the environment, user email fields are consumed by the UI API notification subsystem. Actual delivery depends on valid SMTP environment configuration.

## 12. Troubleshooting

### 12.1 UI does not open

Check:

- `./scripts/ui_up.sh` completed successfully
- port `3200` is free
- `cmd/ui-api` is listening on `127.0.0.1:8090`

Useful checks:

```bash
rg -n 'PASS: FR-06 UI services started|UI_WEB_URL|UI_API_URL' logs/ui-api.log 2>/dev/null || true
curl -sS http://127.0.0.1:8090/api/health
```

### 12.2 Endpoint collectors appear inactive

Check Linux services:

```bash
sudo systemctl status rsiem-agent rsiem-collector-tail --no-pager
sudo journalctl -u rsiem-agent -n 50 --no-pager
sudo journalctl -u rsiem-collector-tail -n 50 --no-pager
```

### 12.3 Proof script fails

When a proof script fails:

1. inspect the exact failing `PASS:` expectation
2. review logs under `logs/`
3. review any partially created `demo_artifacts/<timestamp>/...`
4. rerun only the affected verifier rather than the full suite where possible

## 13. Controlled Shutdown

Recommended shutdown order:

1. stop the UI if running
2. stop the demo or master stack
3. stop optional DB helpers if they were started separately

Commands:

```bash
./scripts/ui_down.sh
./scripts/demo_down.sh
```

If the LAN master deployment helper was used:

```bash
./scripts/deploy/master/master_down.sh
```

## 14. Related Repository References

- [README.md](/home/khotso/Final/projects/r-siem-agent/README.md)
- [docs/implementation_writeup.md](/home/khotso/Final/projects/r-siem-agent/docs/implementation_writeup.md)
- [docs/deploy/master_setup.md](/home/khotso/Final/projects/r-siem-agent/docs/deploy/master_setup.md)
- [docs/deploy/linux_endpoint_setup.md](/home/khotso/Final/projects/r-siem-agent/docs/deploy/linux_endpoint_setup.md)
- [docs/deploy/windows_endpoint_setup.md](/home/khotso/Final/projects/r-siem-agent/docs/deploy/windows_endpoint_setup.md)
- [docs/fr06_ui.md](/home/khotso/Final/projects/r-siem-agent/docs/fr06_ui.md)
