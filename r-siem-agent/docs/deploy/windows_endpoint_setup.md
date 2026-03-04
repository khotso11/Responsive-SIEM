# Windows Endpoint Setup

This installer registers two Windows services:
- `rsiem-agent`
- `rsiem-collector-tail`

## Prerequisites

- Run PowerShell as Administrator
- Endpoint package staged locally (binaries/configs/pki)
- Master reachable on:
  - `tcp/4222` (NATS)
  - `tcp/7777` (gRPC mTLS)

## Install Command

```powershell
Set-ExecutionPolicy -Scope Process Bypass
$MASTER_IP = "<MASTER_IP_FROM_master_up_lan>"
$NATS_URL = "nats://$MASTER_IP`:4222"
cd C:\path\to\r-siem-agent\scripts\deploy\windows
.\install_endpoint.ps1 `
  -MasterIp $MASTER_IP `
  -AgentId win-endpoint-01 `
  -NatsUrl $NATS_URL `
  -InstallDir C:\ProgramData\rsiem
```

## Files and Paths

- Install root: `C:\ProgramData\rsiem`
- Binaries: `C:\ProgramData\rsiem\bin`
- Configs: `C:\ProgramData\rsiem\configs`
- PKI: `C:\ProgramData\rsiem\pki`
- WAL: `C:\ProgramData\rsiem\wal\agent.wal`
- Logs: `C:\ProgramData\rsiem\logs`
- Tail input default: `C:\ProgramData\rsiem\logs\endpoint.log`

## Service Management

```powershell
Get-Service rsiem-agent,rsiem-collector-tail
Start-Service rsiem-agent
Start-Service rsiem-collector-tail
Get-Content C:\ProgramData\rsiem\logs\agent.log -Tail 50
Get-Content C:\ProgramData\rsiem\logs\collector-tail.log -Tail 50
```

## Uninstall

```powershell
.\uninstall_endpoint.ps1 -InstallDir C:\ProgramData\rsiem
```
