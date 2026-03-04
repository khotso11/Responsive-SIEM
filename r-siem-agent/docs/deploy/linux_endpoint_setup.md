# Linux Endpoint Setup

This endpoint package installs:
- `agent`
- `collector-tail`
- optional collector unit templates (`collector-syslog`)

## Required Inputs

- Endpoint ID (unique): `agent.instance_id`
- Master IP reachable from endpoint
- NATS URL (typically `nats://<MASTER_IP>:4222`)
- Package directory containing binaries/configs/pki

Discover runtime values on the master and pass them to the endpoint install:

```bash
MASTER_IP="$(hostname -I | awk '{print $1}')"
NATS_URL="nats://${MASTER_IP}:4222"
MASTER_ADDR="${MASTER_IP}:7777"
echo "MASTER_IP=$MASTER_IP"
echo "NATS_URL=$NATS_URL"
echo "MASTER_ADDR=$MASTER_ADDR"
```

## Install Command

```bash
cd /path/to/r-siem-agent
MASTER_IP="$(hostname -I | awk '{print $1}')"
NATS_URL="nats://${MASTER_IP}:4222"
sudo ./scripts/deploy/linux/install_endpoint.sh \
  --master-ip "$MASTER_IP" \
  --agent-id linux-endpoint-01 \
  --nats-url "$NATS_URL" \
  --config-dir /tmp/rsiem-endpoint-package
```

## What Installer Creates

- Binaries under `/opt/rsiem/bin`
- Configs under `/etc/rsiem/configs`
- PKI under `/etc/rsiem/pki`
- WAL/data under `/var/lib/rsiem`
- Logs under `/var/log/rsiem`
- systemd units:
  - `rsiem-agent.service`
  - `rsiem-collector-tail.service`

## Config Matrix (per endpoint)

| Field | Value example | Notes |
|---|---|---|
| `agent.instance_id` | `linux-endpoint-01` | Must be unique |
| collector `node_id` | `linux-endpoint-01` | Prefer same as instance ID |
| NATS URL | `nats://${MASTER_IP}:4222` | Endpoint to master |
| gRPC mTLS addr | `${MASTER_IP}:7777` | From master `listen_addr` |
| WAL path | `/var/lib/rsiem/agent.wal` | Endpoint-local persistent |
| Collector file path | `/var/log/auth.log` or chosen file | For tail collector |

## Service Health Checks

```bash
sudo systemctl status rsiem-agent --no-pager
sudo systemctl status rsiem-collector-tail --no-pager
sudo journalctl -u rsiem-agent -n 50 --no-pager
sudo journalctl -u rsiem-collector-tail -n 50 --no-pager
ss -ltnp | rg '7777|4222' || true
```
