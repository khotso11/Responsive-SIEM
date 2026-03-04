[CmdletBinding()]
param(
  [string]$InstallDir = "C:\ProgramData\rsiem"
)

$ErrorActionPreference = "Stop"

function Require-Admin {
  $current = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $current.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script as Administrator."
  }
}

function Remove-ServiceIfExists([string]$Name) {
  $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
  if ($svc) {
    try { Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue } catch {}
    & sc.exe delete $Name | Out-Null
    Start-Sleep -Seconds 1
  }
}

Require-Admin

Remove-ServiceIfExists -Name "rsiem-agent"
Remove-ServiceIfExists -Name "rsiem-collector-tail"

Write-Host "PASS: windows endpoint uninstall completed"
Write-Host "InstallDir retained: $InstallDir"
