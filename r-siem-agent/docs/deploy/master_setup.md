# Master Setup (LAN)

This guide configures one master host for multi-endpoint deployment.

## Services on Master

- NATS JetStream (LAN reachable on TCP 4222)
- `master-roe`
- `master-roe-worker`
- `detector-v0`
- TimescaleDB (`rsiem-timescale` container)

## Prerequisites

- Docker
- Go toolchain
- `nats` CLI
- `rg`, `jq`

## Start Master Stack

Use the deployment helper:

```bash
cd /path/to/r-siem-agent
./scripts/deploy/master/master_up_lan.sh
```

This script:
- Ensures NATS is reachable on local loopback (and published on master LAN IP:4222).
- Ensures TimescaleDB is up (`./scripts/db_up.sh`).
- Starts ROE + worker + detector + local demo agent/collector via `./scripts/demo_up.sh`.
- Prints `MASTER_IP`, NATS URL for endpoints, and mTLS transport address.

## Stop Master Stack

```bash
./scripts/deploy/master/master_down.sh
```

Options:
- `--keep-nats` to keep NATS container running.
- `--keep-db` to keep Timescale container running.

## Firewall Guidance

Open inbound to master from endpoint networks:
- TCP 4222 (NATS)
- TCP 7777 (master gRPC mTLS listener)

Keep DB local unless remote queries are required:
- TCP 5432 optional; default should stay localhost-only.

## Health Checks

```bash
nats pub rsiem.deploy.check '{"ts":'"$(date +%s)'"}'
rg '"msg":"roe_stream_info"' logs/master-roe.log | tail -n 1
rg '"msg":"detector_started"' logs/detector.log | tail -n 1
docker ps --format 'table {{.Names}}\t{{.Status}}' | rg 'rsiem-timescale|rsiem-nats-lan|nats'
```
