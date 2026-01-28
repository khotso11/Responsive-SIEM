# M8 Restart Safety Approval Gate

Milestone: **Approve while worker + agent are DOWN, then drain queued step and reach SUCCEEDED**

## Preconditions

Must be running (terminals/processes):
- NATS
- master-consume
- master-roe
- collector-tail

Must be stopped:
- worker
- agent

Proof commands:
```bash
pgrep -af "master-roe-worker" || echo "OK: worker down"
pgrep -af "./cmd/agent" || echo "OK: agent down"
