#Requires -Version 5.1
<#
.SYNOPSIS
  Backup Compose Postgres + host data/ (+ .env.production) for Network Finder.

.DESCRIPTION
  For Windows host-nmap production (Postgres in Docker, app on the host).
  Schedule with Task Scheduler, for example daily at 02:15:
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "<repo>\scripts\backup.ps1"

.PARAMETER BackupRoot
  Destination root (default: <repo>\backups)

.PARAMETER KeepDays
  Delete backup sets older than this many days (default: 14)
#>
[CmdletBinding()]
param(
    [string] $BackupRoot = "",
    [int] $KeepDays = 14
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $Root

if (-not $BackupRoot) { $BackupRoot = Join-Path $Root "backups" }
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$Out = Join-Path $BackupRoot $Stamp
New-Item -ItemType Directory -Force -Path $Out | Out-Null

$EnvFile = if (Test-Path (Join-Path $Root ".env.production")) { ".env.production" } elseif (Test-Path (Join-Path $Root ".env")) { ".env" } else { $null }

Write-Host "[backup] writing $Out"

# Custom-format dump (pg_restore-friendly). cmd redirect keeps the binary intact.
$DumpPath = Join-Path $Out "postgres.dump"
$ComposeArgs = @()
if ($EnvFile) { $ComposeArgs += @("--env-file", $EnvFile) }
$ComposeArgs += @("exec", "-T", "db", "pg_dump", "-U", "netfinder", "-d", "netfinder", "-Fc")
$ArgLine = ($ComposeArgs | ForEach-Object { if ($_ -match '\s') { '"{0}"' -f $_ } else { $_ } }) -join ' '
cmd /c "docker compose $ArgLine > `"$DumpPath`""
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $DumpPath) -or ((Get-Item $DumpPath).Length -lt 32)) {
    throw "pg_dump failed or produced an empty file at $DumpPath"
}

# Host data directory: web captures, logs, optional .secret_key.
$DataDir = Join-Path $Root "data"
if (Test-Path $DataDir) {
    $DataArchive = Join-Path $Out "appdata.tar.gz"
    tar -czf $DataArchive -C $DataDir .
} else {
    Write-Warning "[backup] data/ not found; dump-only set"
}

if ($EnvFile) {
    Copy-Item (Join-Path $Root $EnvFile) (Join-Path $Out ("env" + ($EnvFile -replace '^\.env', '')))
}

try {
    git rev-parse HEAD | Set-Content (Join-Path $Out "git-revision.txt")
} catch { }

@"
created=$Stamp
host=$env:COMPUTERNAME
compose=docker compose $ArgLine
"@ | Set-Content (Join-Path $Out "MANIFEST.txt")

# Retention.
Get-ChildItem -Path $BackupRoot -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$KeepDays) } |
    Remove-Item -Recurse -Force

Write-Host "[backup] done: $Out"
Write-Host "[backup] copy $Out off-box; see docs/runbook.md for restore drill and RPO/RTO"
