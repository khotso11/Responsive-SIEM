# EVE-NG Deployment Path For This Machine

This document chooses the practical EVE-NG deployment model for the current R-SIEM development machine and gives the exact integration steps.

## Host profile used for the decision

Use `scripts/eve_ng_preflight.sh` to capture the current machine profile.

At the time this path was selected, the host had:

- CPU cores: `8`
- Memory: `15 GiB`
- Root disk free: about `147 GiB`

This host is already used to run:

- `ui-api`
- `ui-web`
- `detector-v0`
- `master-roe`
- `master-roe-worker`
- `nats`
- `timescaledb`
- browser and verifier load during the defense

## Chosen deployment path

For this machine, the recommended path is:

- **Primary recommendation:** run EVE-NG on a separate VM or second host with a fixed IP
- **Fallback option:** run a compact EVE-NG VM locally only if the lab is kept small

This is the correct choice because a full EVE-NG topology plus the full R-SIEM stack on the same 15 GiB laptop will compete for RAM and make the live defense less stable.

## What "separate EVE host" means here

Use one of these:

1. Another laptop or workstation on the same LAN
2. A dedicated VM on a second machine
3. A local hypervisor VM with strict memory limits and a compact lab

If you use a second host, give it:

- a fixed IP address
- HTTPS enabled
- reachable management access from the R-SIEM host

Example:

- EVE host IP: `192.168.1.50`

## Required integration values

R-SIEM does not need EVE-NG to live in this repo. It only needs the following values to be reachable from the host running `ui-api`:

- `RSIEM_EVE_NG_UI_URL`
- `RSIEM_EVE_NG_API_BASE_URL`
- `RSIEM_EVE_NG_API_LAB_PATH`
- `RSIEM_EVE_NG_USERNAME`
- `RSIEM_EVE_NG_PASSWORD`

## Recommended environment setup

Set these before starting the R-SIEM stack:

```bash
export RSIEM_EVE_NG_UI_URL='https://192.168.1.50/'
export RSIEM_EVE_NG_API_BASE_URL='https://192.168.1.50'
export RSIEM_EVE_NG_API_LAB_PATH='/R-SIEM/rsiem-infrastructure.unl'
export RSIEM_EVE_NG_USERNAME='admin'
export RSIEM_EVE_NG_PASSWORD='your-eve-password'
export RSIEM_EVE_NG_ALLOW_INSECURE_TLS='true'
```

The UI API now supports these environment overrides directly, so you do not need to keep editing the placeholder `eve-ng.local` values in `configs/labs/emulated_infrastructure_lab.yaml`.

## Bring-up sequence

1. Start or verify the EVE-NG server
2. Confirm the lab exists at:
   - `/R-SIEM/rsiem-infrastructure.unl`
3. Confirm the R-SIEM host can reach the EVE host:

```bash
curl -k https://192.168.1.50
```

4. Export the EVE runtime variables
5. Start the R-SIEM stack:

```bash
cd ~/projects/r-siem-agent
REAL_SYSTEM=1 UI_WEB_PORT=3100 ./scripts/demo_local_endpoint_clean_start.sh
```

6. Validate the integration:

```bash
./scripts/verify_eve_ng_runtime_ui.sh
```

7. Open:

- `/infrastructure/topology`
- `/infrastructure/runbook`

## If you insist on local EVE on this laptop

Keep the lab compact:

- `rsiem-master-01`
- `edge-rtr-01`
- `fw-01`
- `sw-core-01`
- `linux-endpoint-01`
- `win-endpoint-01`
- `attacker-01`

Do not try to run a larger lab plus the full R-SIEM stack plus a browser workload without reducing concurrency and memory pressure.

## Operational rule for the defense

The stable demonstration model is:

- R-SIEM stack on this laptop
- EVE-NG lab on a separate reachable host or VM
- topology and control through the R-SIEM UI using EVE runtime integration

That is the most defensible and least fragile setup.
