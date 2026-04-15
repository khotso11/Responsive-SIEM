# EVE-NG Lab Runbook

This runbook is the defense-time procedure for bringing up the emulated R-SIEM infrastructure lab and showing that the topology in the UI corresponds to the actual EVE-NG lab.

## Source of truth

- EVE-NG provider config: `configs/labs/emulated_infrastructure_lab.yaml`
- Imported EVE-NG lab file: `configs/labs/eve_ng_rsiem_infrastructure.unl`
- Live topology API: `GET /api/infrastructure/topology`
- UI page: `/infrastructure/topology`
- UI runbook page: `/infrastructure/runbook`

## EVE-NG runtime prerequisites

Set these on the host running `ui-api` before starting the UI stack:

```bash
export RSIEM_EVE_NG_UI_URL='https://192.168.1.50/'
export RSIEM_EVE_NG_API_BASE_URL='https://192.168.1.50'
export RSIEM_EVE_NG_API_LAB_PATH='/R-SIEM/rsiem-infrastructure.unl'
export RSIEM_EVE_NG_USERNAME='admin'
export RSIEM_EVE_NG_PASSWORD='eve-password'
export RSIEM_EVE_NG_ALLOW_INSECURE_TLS='true'
```

These values override the placeholder provider values from `configs/labs/emulated_infrastructure_lab.yaml`. Use env overrides for the defense instead of editing the placeholder host repeatedly.

If EVE-NG uses a self-signed certificate, `RSIEM_EVE_NG_ALLOW_INSECURE_TLS='true'` keeps the runtime query path working.

## Topology summary

The emulated lab contains:

- `rsiem-master-01`: management plane node for R-SIEM
- `edge-rtr-01`: router
- `fw-01`: firewall / gateway / NetFlow exporter
- `sw-core-01`: switch segment
- `linux-endpoint-01`, `linux-endpoint-02`: managed Linux endpoints
- `win-endpoint-01`: managed Windows endpoint
- `app-srv-01`, `db-srv-01`: internal servers
- `dmz-srv-01`: DMZ service node
- `attacker-01`: attacker simulation node

Networks:

- `management`
- `user_lan`
- `server_lan`
- `dmz`
- `red_team`

## Defense bring-up order

Open EVE-NG, load the lab, and start nodes in this order:

1. `edge-rtr-01`
   - verify management reachability
   - verify syslog / SNMP exporter targets point to `10.10.0.10`
2. `fw-01`
   - verify DMZ and red-team facing interfaces are up
   - verify syslog / NetFlow / SNMP exporters point to `10.10.0.10`
3. `sw-core-01`
   - verify link-state notifications can be emitted
4. `linux-endpoint-01`
   - start R-SIEM agent and endpoint collectors
5. `linux-endpoint-02`
   - confirm second endpoint joins user segment
6. `win-endpoint-01`
   - confirm Windows agent / tail path health
7. `app-srv-01`
8. `db-srv-01`
9. `dmz-srv-01`
10. `attacker-01`

## What to show in the UI while bringing it up

Keep `/infrastructure/topology` open and show:

- provider runtime status changes from `credentials_missing` or `not_configured` to `connected`
- imported EVE node names and node IDs
- imported link map
- selected-node runtime status (`running` / `stopped`)
- selected-node console URL when provided by EVE-NG
- selected-node admin controls (`start`, `stop`, `wipe`) when a mapped EVE node is selected

## Telemetry destinations

Configured collector endpoints on `rsiem-master-01`:

- Syslog UDP: `10.10.0.10:5140`
- NetFlow v5: `10.10.0.10:2055`
- SNMP trap: `10.10.0.10:9162`

## Demonstration sequence

After all nodes are running:

1. Open `/infrastructure/topology`
2. Open `/infrastructure/runbook`
3. Show the EVE provider panel and imported link map
4. Run one verifier command from the runbook
5. Show the activity reflected on:
   - `/infrastructure/topology`
   - `/search?category=infrastructure`
   - `/incidents?category=infrastructure`

Recommended proof order:

1. `./scripts/verify_infra_firewall_deny_burst.sh`
2. `./scripts/verify_infra_east_west_flow_scan.sh`
3. `./scripts/verify_infra_network_admin_login.sh`
4. `./scripts/verify_infra_link_flap_burst.sh`
5. `./scripts/verify_infra_firewall_config_change_oow.sh`
6. `./scripts/verify_infra_post_containment_block_verification.sh`

## Expected live rule IDs

- `R-INFRA-FIREWALL-DENY-BURST`
- `R-INFRA-EAST-WEST-FLOW-SCAN`
- `R-INFRA-NETWORK-ADMIN-LOGIN`
- `R-INFRA-LINK-FLAP-BURST`
- `R-INFRA-FIREWALL-CONFIG-CHANGE-OOW`
- `R-INFRA-POST-CONTAINMENT-BLOCK-VERIFY`

## If EVE runtime status is not connected

Check in order:

1. `RSIEM_EVE_NG_UI_URL`, `RSIEM_EVE_NG_API_BASE_URL`, and `RSIEM_EVE_NG_API_LAB_PATH`
2. `RSIEM_EVE_NG_USERNAME` and `RSIEM_EVE_NG_PASSWORD`
3. whether the EVE-NG host is reachable from the `ui-api` host
4. whether the same EVE account is already logged in elsewhere and has invalidated the current session
5. `./scripts/verify_eve_ng_runtime_ui.sh`

## Current integration boundary

The current implementation reads runtime node state from EVE-NG, imports the `.unl` lab topology, and exposes admin-only `start`, `stop`, and `wipe` node controls from the R-SIEM UI. It does not yet manage full lab lifecycle operations such as creating labs or importing images.
