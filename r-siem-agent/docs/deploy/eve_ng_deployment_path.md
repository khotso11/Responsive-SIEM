# EVE-NG Deployment Path For This Machine

This document records the current EVE-NG deployment model for the R-SIEM development and defense machine and gives the exact integration steps.

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

For the current machine, the chosen path is:

- R-SIEM stack on the Ubuntu host
- EVE-NG Community Edition inside a dedicated VMware Workstation Pro VM
- VMware NAT networking for the current operational phase

This keeps the control plane and the emulated lab separated while still allowing the laptop to host both sides of the demo.

## Current validated VM state

- EVE VM IP: `192.168.59.128`
- web UI path: `http://192.168.59.128`
- transport currently used by R-SIEM: HTTP
- nested virtualization inside the EVE guest: working

Bridged networking was tested earlier and did not obtain IPv4. NAT is the current known-good operating mode and should be treated as the active baseline until a later static-IP revisit.

## Required integration values

R-SIEM does not need EVE-NG to live in this repo. It only needs the following values to be reachable from the host running `ui-api`:

- `RSIEM_EVE_NG_UI_URL`
- `RSIEM_EVE_NG_API_BASE_URL`
- `RSIEM_EVE_NG_API_LAB_PATH`
- `RSIEM_EVE_NG_USERNAME`
- `RSIEM_EVE_NG_PASSWORD`
- `RSIEM_INFRA_HOST_COLLECTOR_IP`

## Recommended environment setup

Set these before starting the R-SIEM stack:

```bash
export RSIEM_EVE_NG_UI_URL='http://192.168.59.128/'
export RSIEM_EVE_NG_API_BASE_URL='http://192.168.59.128'
export RSIEM_EVE_NG_API_LAB_PATH='/R-SIEM/rsiem-infrastructure.unl'
export RSIEM_EVE_NG_USERNAME='admin'
export RSIEM_EVE_NG_PASSWORD='<eve-web-password>'
export RSIEM_EVE_NG_ALLOW_INSECURE_TLS='false'
export RSIEM_INFRA_HOST_COLLECTOR_IP='192.168.59.1'
```

The UI API supports these environment overrides directly, and the infrastructure topology loader supports `RSIEM_INFRA_HOST_COLLECTOR_IP` so the management anchor and collector destinations reflect the real Ubuntu host address visible from the EVE VM.

## Bring-up sequence

1. Start or verify the EVE VM
2. Confirm the lab exists at:
   - `/R-SIEM/rsiem-infrastructure.unl`
3. Confirm the Ubuntu host can reach the EVE VM:

```bash
curl http://192.168.59.128
```

4. Confirm the Ubuntu host address that the EVE VM can reach:

```bash
ip -4 addr show | grep '192.168.59.'
```

5. Export the EVE runtime variables
6. Start the R-SIEM stack:

```bash
cd ~/projects/r-siem-agent
REAL_SYSTEM=1 UI_WEB_PORT=3100 ./scripts/demo_local_endpoint_clean_start.sh
```

7. Validate the integration:

```bash
./scripts/verify_eve_ng_vm_integration.sh
./scripts/verify_eve_ng_runtime_ui.sh
```

8. Open:

- `/infrastructure/topology`
- `/infrastructure/runbook`

## Operational rule for the defense

The stable demonstration model is:

- R-SIEM stack on the laptop host
- EVE-NG lab inside the VMware VM at `192.168.59.128`
- topology and control through the R-SIEM UI using EVE runtime integration
- telemetry exported from the EVE lab back to the host-side collectors

That is the current working architecture and the one the repo should now reflect.
