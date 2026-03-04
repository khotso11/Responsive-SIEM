[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)] [string]$MasterIp,
  [Parameter(Mandatory = $true)] [string]$AgentId,
  [Parameter(Mandatory = $true)] [string]$NatsUrl,
  [string]$InstallDir = "C:\ProgramData\rsiem",
  [string]$PackageDir = $PSScriptRoot
)

$ErrorActionPreference = "Stop"

function Require-Admin {
  $current = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $current.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script as Administrator."
  }
}

function Resolve-Binary([string[]]$Candidates) {
  foreach ($c in $Candidates) {
    if (Test-Path $c) {
      return (Resolve-Path $c).Path
    }
  }
  return $null
}

function Remove-ServiceIfExists([string]$Name) {
  $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
  if ($svc) {
    try { Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue } catch {}
    & sc.exe delete $Name | Out-Null
    Start-Sleep -Seconds 1
  }
}

function Install-Service([string]$Name, [string]$ExePath, [string]$Arguments, [string]$LogPath) {
  $nssm = Get-Command nssm -ErrorAction SilentlyContinue
  Remove-ServiceIfExists -Name $Name

  if ($nssm) {
    & $nssm.Source install $Name $ExePath $Arguments | Out-Null
    & $nssm.Source set $Name AppStdout $LogPath | Out-Null
    & $nssm.Source set $Name AppStderr $LogPath | Out-Null
    & $nssm.Source set $Name Start SERVICE_AUTO_START | Out-Null
  }
  else {
    $binPath = '"{0}" {1}' -f $ExePath, $Arguments
    & sc.exe create $Name start= auto binPath= $binPath | Out-Null
  }

  Start-Service -Name $Name
}

Require-Admin

$BinDir = Join-Path $InstallDir "bin"
$CfgDir = Join-Path $InstallDir "configs"
$PkiDir = Join-Path $InstallDir "pki"
$WalDir = Join-Path $InstallDir "wal"
$LogDir = Join-Path $InstallDir "logs"

New-Item -ItemType Directory -Force -Path $BinDir, $CfgDir, $PkiDir, $WalDir, $LogDir | Out-Null

$AgentExe = Resolve-Binary @(
  (Join-Path $PackageDir "agent.exe"),
  (Join-Path $PackageDir "bin\agent.exe")
)
$CollectorExe = Resolve-Binary @(
  (Join-Path $PackageDir "collector-tail.exe"),
  (Join-Path $PackageDir "bin\collector-tail.exe")
)

if (-not $AgentExe) { throw "Could not find agent.exe under $PackageDir" }
if (-not $CollectorExe) { throw "Could not find collector-tail.exe under $PackageDir" }

Copy-Item -Force $AgentExe (Join-Path $BinDir "agent.exe")
Copy-Item -Force $CollectorExe (Join-Path $BinDir "collector-tail.exe")

foreach ($f in @("ca.pem", "agent.pem", "agent-key.pem")) {
  $srcA = Join-Path $PackageDir ("pki\" + $f)
  $srcB = Join-Path $PackageDir ("certs\" + $f)
  if (Test-Path $srcA) {
    Copy-Item -Force $srcA (Join-Path $PkiDir $f)
  }
  elseif (Test-Path $srcB) {
    Copy-Item -Force $srcB (Join-Path $PkiDir $f)
  }
}

$agentCfg = @"
log:
  level: INFO
heartbeat:
  interval_seconds: 60
mock:
  interval_seconds: 1
agent:
  name: r-siem-agent
  instance_id: $AgentId
  quarantine_root: $InstallDir\quarantine
  quarantine_allowed_source_roots:
    - C:\\Temp
lanes:
  fast_buffer: 1000
  standard_buffer: 5000
wal:
  path: $WalDir\agent.wal
  fsync: true
batch:
  fast:
    max_size: 50
    max_latency_ms: 200
  standard:
    max_size: 200
    max_latency_ms: 500
transport:
  mode: grpc_mtls
  addr: $MasterIp`:7777
  ack_delay_ms: 150
  ack_drop_rate: 0.0
  tls:
    ca: $PkiDir\ca.pem
    cert: $PkiDir\agent.pem
    key: $PkiDir\agent-key.pem
    server_name: master.local
"@

$collectorCfg = @"
log_level: INFO

jetstream:
  url: $NatsUrl
  stream: RSIEM_EVENTS
  subject: rsiem.events.raw

tail:
  path: $LogDir\endpoint.log
  checkpoint_path: $WalDir\tail.checkpoint.json
  poll_ms: 200
"@

Set-Content -Path (Join-Path $CfgDir "agent.yaml") -Value $agentCfg -Encoding UTF8
Set-Content -Path (Join-Path $CfgDir "collector.yaml") -Value $collectorCfg -Encoding UTF8

$agentLog = Join-Path $LogDir "agent.log"
$collectorLog = Join-Path $LogDir "collector-tail.log"
New-Item -ItemType File -Path $agentLog -Force | Out-Null
New-Item -ItemType File -Path $collectorLog -Force | Out-Null

Install-Service -Name "rsiem-agent" -ExePath (Join-Path $BinDir "agent.exe") -Arguments "--config \"$CfgDir\agent.yaml\"" -LogPath $agentLog
Install-Service -Name "rsiem-collector-tail" -ExePath (Join-Path $BinDir "collector-tail.exe") -Arguments "--config \"$CfgDir\collector.yaml\"" -LogPath $collectorLog

Write-Host "PASS: windows endpoint install completed"
Write-Host "AGENT_ID=$AgentId"
Write-Host "MASTER_ADDR=$MasterIp`:7777"
Write-Host "NATS_URL=$NatsUrl"
Write-Host "Health checks:"
Write-Host "  Get-Service rsiem-agent,rsiem-collector-tail"
Write-Host "  Get-Content $agentLog -Tail 50"
Write-Host "  Get-Content $collectorLog -Tail 50"
