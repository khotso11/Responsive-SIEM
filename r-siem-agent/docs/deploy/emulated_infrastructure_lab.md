# Emulated Infrastructure Lab Plan

## Purpose
This document defines the concrete next expansion of R-SIEM from endpoint-centric monitoring into infrastructure-plane monitoring.

It is anchored in what already exists in this repo:
- endpoint agents and collectors
- Windows endpoint packaging and service installation
- infrastructure collectors for `syslog`, `netflow_v5`, and `snmp_trap`
- unified detector, ROE, response, search, and audit surfaces

This is not a theoretical note. It is the implementation plan for an emulated lab that can drive real telemetry into the existing stack.

## Current Endpoint Plane Statement
Use this wording consistently:

- Linux endpoint support is the most tested and currently the strongest live proof path.
- Windows endpoint support exists in the repo through `scripts/deploy/windows/install_endpoint.ps1`, `scripts/deploy/windows/uninstall_endpoint.ps1`, and `docs/deploy/windows_endpoint_setup.md`.
- Windows has been packaged and implemented, but Linux has been exercised more heavily in live demonstrations and validation.

That is the correct technical statement.

## Why Emulated Infrastructure Instead of Mininet
Use an emulated virtual environment when the project needs to represent:
- routers
- firewalls
- switch-connected segments
- server networks
- management-plane telemetry

Mininet is useful for topology and path simulation, but this project now needs device-like telemetry over the protocols already implemented by R-SIEM:
- `syslog`
- `netflow_v5`
- `snmp_trap`

An emulated virtual environment is a better fit because it lets the project show infrastructure telemetry using the same collection interfaces that would be used in a real deployment.

## Exact Lab Topology
The machine-readable source of truth for this lab is:
- `configs/labs/emulated_infrastructure_lab.yaml`

### Management Node
- `rsiem-master-01`
- Management IP: `10.10.0.10/24`
- Runs:
  - NATS JetStream
  - `master-roe`
  - `master-roe-worker`
  - `detector-v0`
  - `ui-api`
  - `ui-web`
  - `investigation-enricher`
  - Postgres / TimescaleDB

### Collector Endpoints on the Management Node
- Syslog UDP collector destination: `10.10.0.10:5140`
- NetFlow v5 collector destination: `10.10.0.10:2055`
- SNMP trap collector destination: `10.10.0.10:9162`

### Networks
- `management`: `10.10.0.0/24`
- `user_lan`: `10.20.10.0/24`
- `server_lan`: `10.20.20.0/24`
- `dmz`: `10.20.30.0/24`
- `red_team`: `10.30.0.0/24`

### Emulated Nodes
- `edge-rtr-01`
  - router
  - management IP `10.10.0.21/24`
  - routed interfaces into `user_lan`, `server_lan`, `dmz`, `red_team`
- `fw-01`
  - firewall / gateway
  - management IP `10.10.0.22/24`
  - DMZ / red team inspection boundary
- `sw-core-01`
  - switch-segment telemetry source
  - management IP `10.10.0.23/24`
- `linux-endpoint-01`
  - managed Linux endpoint
  - IP `10.20.10.11/24`
- `linux-endpoint-02`
  - managed Linux endpoint
  - IP `10.20.10.12/24`
- `win-endpoint-01`
  - managed Windows endpoint
  - IP `10.20.10.21/24`
- `app-srv-01`
  - Linux application server
  - IP `10.20.20.11/24`
- `db-srv-01`
  - Linux database server
  - IP `10.20.20.12/24`
- `dmz-srv-01`
  - DMZ service target
  - IP `10.20.30.11/24`
- `attacker-01`
  - attacker simulation node
  - IP `10.30.0.11/24`

## Telemetry Mapping Into Existing Collectors
This project already has the ingestion binaries required for the infrastructure plane.

### Device syslog
- Exporters:
  - `edge-rtr-01`
  - `fw-01`
  - `sw-core-01`
- Collector:
  - `cmd/collector-syslog/main.go`
- Config:
  - `configs/collector-syslog.yaml`
- Normalized source type:
  - `syslog`
- Publish path:
  - stream `RSIEM_EVENTS`
  - subject `rsiem.events.raw`
- Expected infrastructure signals:
  - device login
  - firewall deny
  - config commit
  - route change
  - interface state change

### Flow export
- Exporter:
  - `fw-01`
- Collector:
  - `cmd/collector-netflowv5/main.go`
- Config:
  - `configs/collector-netflowv5.yaml`
- Normalized source type:
  - `netflow_v5`
- Publish path:
  - stream `RSIEM_EVENTS`
  - subject `rsiem.events.raw`
- Expected infrastructure signals:
  - east-west scan
  - denied or short-lived flow burst
  - DMZ access attempts
  - beacon-like egress patterns

### Device traps
- Exporters:
  - `edge-rtr-01`
  - `fw-01`
  - `sw-core-01`
- Collector:
  - `cmd/collector-snmptrap/main.go`
- Config:
  - `configs/collector-snmptrap.yaml`
- Normalized source type:
  - `snmp_trap`
- Publish path:
  - stream `RSIEM_EVENTS`
  - subject `rsiem.events.raw`
- Expected infrastructure signals:
  - link down
  - link up
  - cold start
  - device state notifications

### Managed endpoint telemetry inside the same lab
The infrastructure lab must not replace the endpoint plane. It must extend it.

#### Linux managed endpoints
- `cmd/agent/main.go`
- `cmd/collector-auditd/main.go`
- `cmd/collector-inotify/main.go`
- `cmd/collector-procnet/main.go`
- `cmd/collector-dns/main.go`

#### Windows managed endpoint
- installer:
  - `scripts/deploy/windows/install_endpoint.ps1`
- uninstall:
  - `scripts/deploy/windows/uninstall_endpoint.ps1`
- doc:
  - `docs/deploy/windows_endpoint_setup.md`
- implemented services:
  - `rsiem-agent`
  - `rsiem-collector-tail`

## Control Principle For This Expansion
The project should make a clean distinction between two planes.

### Endpoint plane
- deep host telemetry
- deepest response capability
- strongest current proof path
- Linux most heavily validated
- Windows implemented, less exercised

### Infrastructure plane
- agentless telemetry from routers, firewall, and switch-like nodes
- visibility over the broader environment
- first response path should focus on:
  - notify
  - correlation
  - bounded enforcement on Linux-controlled choke points or managed endpoints

That is the correct path to a robust system.

## First 6 Network / Infrastructure Tests To Implement
These six tests are the correct first set because together they cover:
- management-plane activity
- data-plane flow visibility
- infrastructure health events
- governance/configuration events
- response verification after action

### Test 1. Firewall deny burst to DMZ service
- ID: `infra-01-firewall-deny-burst`
- Initiator: `attacker-01`
- Target: `dmz-srv-01`
- Telemetry required:
  - `syslog`
  - `netflow_v5`
- Goal:
  - prove the infrastructure plane sees blocked north-south abuse
- Expected outcome:
  - collector evidence in `collector-syslog.log` and `collector-netflowv5.log`
  - normalized evidence searchable in `Search`
  - candidate future rule class: firewall deny burst or denied flow concentration

### Test 2. East-west scan from managed endpoint to server LAN
- ID: `infra-02-east-west-scan`
- Initiator: `linux-endpoint-01`
- Target segment: `server_lan`
- Telemetry required:
  - `netflow_v5`
  - `syslog`
  - optionally endpoint `proc_net` and `auditd_connect`
- Goal:
  - prove infrastructure telemetry can be correlated with endpoint telemetry from the same host
- Expected outcome:
  - flow evidence at the firewall or router boundary
  - endpoint evidence on the managed Linux host
  - strong Advanced Search demonstration across both planes

### Test 3. Network admin login to router or firewall
- ID: `infra-03-network-admin-login`
- Initiator: `attacker-01` or management host outside normal admin source range
- Target: `edge-rtr-01` or `fw-01`
- Telemetry required:
  - `syslog`
- Goal:
  - prove management-plane access events are visible to R-SIEM
- Expected outcome:
  - syslog evidence of device login
  - candidate future rule class: privileged device access or unusual management-plane origin

### Test 4. Link-down or interface flap burst
- ID: `infra-04-link-flap-or-linkdown`
- Initiator: `sw-core-01`
- Telemetry required:
  - `snmp_trap`
  - `syslog`
- Goal:
  - prove infrastructure health events are captured and can be promoted to incident workflow
- Expected outcome:
  - SNMP trap evidence for link state changes
  - optional corroborating syslog from the same node
  - candidate future rule class: interface flap burst / unstable link

### Test 5. Firewall config change or policy commit
- ID: `infra-05-firewall-config-change`
- Initiator: `fw-01`
- Telemetry required:
  - `syslog`
- Goal:
  - prove governance and configuration change events are visible to R-SIEM
- Expected outcome:
  - syslog evidence of commit / policy change
  - candidate future rule class: config change outside maintenance window

### Test 6. Domain or destination block verification
- ID: `infra-06-domain-or-destination-block-verification`
- Initiator: `linux-endpoint-01`
- Target / enforcement boundary: `fw-01`
- Telemetry required:
  - endpoint `dns`
  - endpoint `proc_net`
  - infrastructure `syslog`
  - infrastructure `netflow_v5`
- Goal:
  - prove before-during-after verification for a response action
- Expected outcome:
  - before action: attempted access visible
  - during action: blocked attempts visible
  - after action: endpoint no longer reaches destination successfully

This sixth test is the strongest bridge between the current endpoint response model and the new infrastructure visibility model.

## Current Proofs Already Available In The Repo
The infrastructure plane is not empty today. These current proofs already validate the collection side:
- `scripts/verify_fr01_syslog.sh`
- `scripts/verify_fr01_netflowv5.sh`
- `scripts/verify_fr01_snmptrap.sh`

A new wrapper added for this expansion is:
- `scripts/verify_infrastructure_plane_phase1.sh`

This wrapper does not claim full network-lab correlation yet. It proves that the three core infrastructure collectors already work together as an ingestion surface.

## Recommended Implementation Sequence
Build in this order.

### Phase 1. Prove infrastructure ingestion
- Start with:
  - `scripts/verify_infrastructure_plane_phase1.sh`
- Outcome:
  - verified syslog + netflow + snmp trap ingestion

### Phase 2. Stand up the emulated lab
- Build the exact nodes listed in `configs/labs/emulated_infrastructure_lab.yaml`
- Route all infrastructure telemetry to the existing collector endpoints on `rsiem-master-01`

### Phase 3. Add first infrastructure detections
The first rule classes should be:
- firewall deny burst
- east-west scan at flow boundary
- unusual network admin login
- interface flap burst
- firewall config change outside allowed window
- block verification after containment

### Phase 4. Add first infrastructure playbooks
Start with bounded playbooks only:
- notify-only for device governance events
- observe/contain hybrids where enforcement happens on Linux-controlled nodes or endpoints
- do not overclaim direct router/firewall reconfiguration until a real connector exists

### Phase 5. Add end-to-end proofs
Each of the six tests above should get its own verifier script and proof JSON artifact.

## Strong Final Claim After This Expansion
Use this wording when the lab is built and tested:

"R-SIEM monitors two planes in one system: the endpoint plane through installed agents and endpoint collectors, and the infrastructure plane through syslog, NetFlow, and SNMP trap telemetry from an emulated network environment. The same detection, policy, response, search, and audit framework spans both planes."

That is a strong claim and still technically honest.
