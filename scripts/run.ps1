#Requires -Version 5.1
<#
.SYNOPSIS
  Run Network Finder on Windows with host nmap (Npc) and Docker Postgres only.

.DESCRIPTION
  production  - loads .env.production, starts Compose `db` only, builds frontend,
                migrates, serves UI+API with host nmap (no app container, no SQLite)
  dev         - loads .env and runs `npm run dev` (Vite + uvicorn --reload)

  Task Scheduler (at startup / after reboot), example:
    Program:  powershell.exe
    Arguments: -NoProfile -ExecutionPolicy Bypass -File "<repo-root>\scripts\run.ps1" -Mode production
    Start in:  <repo-root>

.PARAMETER Mode
  production (default) or dev

.PARAMETER SkipBuild
  production only: skip `npm run build` if frontend/dist/index.html already exists

.PARAMETER ForceRestart
  If the listen port is already in use by a previous instance, stop it first

.PARAMETER Background
  production only: start in a hidden window and return once the app is listening.
  Output goes to data\logs\production.log; stop with -Stop

.PARAMETER Stop
  Stop the production app process (leaves Docker `db` running)

.PARAMETER StopDb
  With -Stop: also stop the Compose `db` container
#>
[CmdletBinding()]
param(
    [ValidateSet("production", "dev")]
    [string] $Mode = "production",

    [switch] $SkipBuild,
    [switch] $ForceRestart,
    [switch] $Background,
    [switch] $Stop,
    [switch] $StopDb
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location -LiteralPath $Root

$DataDir = Join-Path $Root "data"
$LogDir = Join-Path $DataDir "logs"
$PidFile = Join-Path $DataDir "network-finder-prod.pid"
$LogFile = Join-Path $LogDir "production.log"
$ComposeFile = Join-Path $Root "docker-compose.yml"
$ProdEnvFile = Join-Path $Root ".env.production"
$BackgroundStartTimeoutS = 300

function Write-Log {
    param([string] $Message, [string] $Level = "INFO")
    $line = "{0:yyyy-MM-dd HH:mm:ss} [{1}] {2}" -f (Get-Date), $Level, $Message
    Write-Host $line
    if ($Mode -eq "production") {
        New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
        Add-Content -LiteralPath $LogFile -Value $line -Encoding UTF8
    }
}

function Import-DotEnv {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Env file not found: $Path"
    }
    Get-Content -LiteralPath $Path -Encoding UTF8 | ForEach-Object {
        $line = $_.Trim()
        if (-not $line -or $line.StartsWith("#")) { return }
        $eq = $line.IndexOf("=")
        if ($eq -lt 1) { return }
        $key = $line.Substring(0, $eq).Trim()
        $val = $line.Substring($eq + 1).Trim()
        if (
            ($val.Length -ge 2) -and (
                ($val.StartsWith('"') -and $val.EndsWith('"')) -or
                ($val.StartsWith("'") -and $val.EndsWith("'"))
            )
        ) {
            $val = $val.Substring(1, $val.Length - 2)
        }
        Set-Item -Path "Env:$key" -Value $val
    }
}

function Test-EnvSet {
    param([string] $Name)
    $item = Get-Item -Path "Env:$Name" -ErrorAction SilentlyContinue
    return ($null -ne $item -and -not [string]::IsNullOrWhiteSpace($item.Value))
}

function Get-PostgresDatabaseUrl {
    # Build a URL that overrides any sqlite DATABASE_URL from a leftover .env file.
    if (-not (Test-EnvSet "POSTGRES_PASSWORD")) {
        throw "POSTGRES_PASSWORD is missing in .env.production"
    }
    $user = [uri]::EscapeDataString($env:POSTGRES_USER)
    $pass = [uri]::EscapeDataString($env:POSTGRES_PASSWORD)
    $db = [uri]::EscapeDataString($env:POSTGRES_DB)
    $pgHost = $env:POSTGRES_HOST
    $port = $env:POSTGRES_PORT
    return "postgresql+psycopg://${user}:${pass}@${pgHost}:${port}/${db}"
}

function Get-ListenPids {
    param([int] $Port)
    try {
        $conns = @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
    } catch {
        return @()
    }
    if ($conns.Length -eq 0) { return @() }
    $ids = @(
        $conns |
            Select-Object -ExpandProperty OwningProcess -Unique |
            Where-Object { $_ -and $_ -gt 0 }
    )
    return $ids
}

function Stop-ProductionInstance {
    param([int] $Port)

    $pids = New-Object "System.Collections.Generic.HashSet[int]"
    if (Test-Path -LiteralPath $PidFile) {
        $raw = (Get-Content -LiteralPath $PidFile -Raw).Trim()
        if ($raw -match "^\d+$") { [void]$pids.Add([int]$raw) }
    }
    foreach ($p in @(Get-ListenPids -Port $Port)) { [void]$pids.Add([int]$p) }

    if ($pids.Count -eq 0) {
        Write-Log "No production app found (port $Port / PID file)."
        Remove-Item -LiteralPath $PidFile -Force -ErrorAction SilentlyContinue
    } else {
        foreach ($procId in @($pids)) {
            try {
                Write-Log "Stopping PID $procId"
                Stop-Process -Id $procId -Force -ErrorAction Stop
            } catch {
                Write-Log "Could not stop PID ${procId}: $($_.Exception.Message)" "WARN"
            }
        }
        Remove-Item -LiteralPath $PidFile -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
    }

    if ($StopDb) {
        Write-Log "Stopping Docker Compose db service"
        & docker compose -f $ComposeFile --env-file $ProdEnvFile stop db
        if ($LASTEXITCODE -ne 0) {
            Write-Log "docker compose stop db failed (exit $LASTEXITCODE)" "WARN"
        }
    }
}

function Get-NpmCmd {
    # Prefer npm.cmd — npm.ps1 breaks under Set-StrictMode ("Statement" property errors).
    $cmd = Get-Command npm.cmd -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $cmd = Get-Command npm -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    throw "npm not found on PATH."
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Label,
        [Parameter(Mandatory = $true)]
        [string] $FilePath,
        [string[]] $ArgumentList = @()
    )
    Write-Log $Label
    $global:LASTEXITCODE = 0
    & $FilePath @ArgumentList
    $code = $global:LASTEXITCODE
    if ($null -eq $code) { $code = 0 }
    if ([int]$code -ne 0) {
        throw "$Label failed (exit $code)"
    }
}

function Start-DockerDb {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        throw "docker not found on PATH. Install Docker Desktop and ensure it is running."
    }
    if (-not (Test-Path -LiteralPath $ComposeFile)) {
        throw "Compose file not found: $ComposeFile"
    }
    if (-not (Test-EnvSet "POSTGRES_PASSWORD")) {
        throw "POSTGRES_PASSWORD is missing in .env.production"
    }

    Write-Log "Starting Docker Compose service: db (Postgres only)"
    # Only the db service — app stays on the host for Npcap/ARP.
    & docker compose -f $ComposeFile --env-file $ProdEnvFile up -d --wait db
    if ($null -ne $LASTEXITCODE -and $LASTEXITCODE -ne 0) {
        # Older compose without --wait
        Write-Log "compose --wait failed; falling back to up -d + health poll" "WARN"
        & docker compose -f $ComposeFile --env-file $ProdEnvFile up -d db
        if ($null -ne $LASTEXITCODE -and $LASTEXITCODE -ne 0) {
            throw "docker compose up db failed (exit $LASTEXITCODE)"
        }
        $deadline = (Get-Date).AddMinutes(2)
        do {
            Start-Sleep -Seconds 2
            & docker compose -f $ComposeFile --env-file $ProdEnvFile exec -T db `
                pg_isready -U $env:POSTGRES_USER -d $env:POSTGRES_DB 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Postgres is ready"
                return
            }
        } while ((Get-Date) -lt $deadline)
        throw "Postgres did not become ready within 2 minutes"
    }
    Write-Log "Postgres container is healthy"
}

# --- resolve env file / port -------------------------------------------------
$envFile = if ($Mode -eq "production") { $ProdEnvFile } else { Join-Path $Root ".env" }

$listenPort = 8081
$listenHost = "0.0.0.0"
$forwarded = "127.0.0.1"

if ($Mode -eq "production") {
    Import-DotEnv -Path $envFile

    # Make Python Settings load .env.production instead of .env (see app/config.py).
    $env:NETWORK_FINDER_ENV_FILE = $ProdEnvFile
    $env:APP_ENV = "production"
    $env:DEV_SEED = "false"
    if (-not (Test-EnvSet "SCANNER_MODE")) { $env:SCANNER_MODE = "nmap" }
    if (-not (Test-EnvSet "NMAP_PATH")) { $env:NMAP_PATH = "nmap" }
    if (-not (Test-EnvSet "POSTGRES_DB")) { $env:POSTGRES_DB = "netfinder" }
    if (-not (Test-EnvSet "POSTGRES_USER")) { $env:POSTGRES_USER = "netfinder" }
    if (-not (Test-EnvSet "POSTGRES_PORT")) { $env:POSTGRES_PORT = "5434" }

    # Host app → Docker-published Postgres on localhost (never SQLite in production).
    # Must set DATABASE_URL explicitly: process env wins over any file, and .env often
    # still has sqlite which would otherwise take precedence over POSTGRES_HOST alone.
    $env:POSTGRES_HOST = "127.0.0.1"
    $env:DATABASE_URL = Get-PostgresDatabaseUrl
    Write-Log "Database: Docker Postgres at $($env:POSTGRES_HOST):$($env:POSTGRES_PORT)/$($env:POSTGRES_DB) (env file: .env.production)"

    if ($env:APP_PORT -and $env:APP_PORT -match "^\d+$") { $listenPort = [int]$env:APP_PORT }
    if (Test-EnvSet "APP_HOST") { $listenHost = $env:APP_HOST }
    if (Test-EnvSet "FORWARDED_ALLOW_IPS") { $forwarded = $env:FORWARDED_ALLOW_IPS }
} else {
    if (Test-Path -LiteralPath $envFile) { Import-DotEnv -Path $envFile }
    $listenPort = 8000
    if ($env:BACKEND_PORT -and $env:BACKEND_PORT -match "^\d+$") { $listenPort = [int]$env:BACKEND_PORT }
}

if ($Stop) {
    if ($Mode -ne "production") {
        throw "-Stop is only supported for -Mode production (dev: Ctrl+C in the npm run dev window)."
    }
    Stop-ProductionInstance -Port $listenPort
    exit 0
}

New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

# --- already running? (wrap in @() — PowerShell unwraps single-element returns) -
$existing = @(Get-ListenPids -Port $listenPort)
if ($existing.Count -gt 0) {
    if ($ForceRestart) {
        Write-Log "Port $listenPort in use by PID(s) $($existing -join ', '); ForceRestart"
        Stop-ProductionInstance -Port $listenPort
    } else {
        Write-Log "Already listening on port $listenPort (PID(s) $($existing -join ', ')); exiting."
        exit 0
    }
}

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    throw "node not found on PATH. Install Node.js 20.19+ and retry."
}
$npmCmd = Get-NpmCmd

if ($Background) {
    if ($Mode -ne "production") {
        throw "-Background is only supported for -Mode production."
    }
    $childArgs = @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden",
        "-File", "`"$PSCommandPath`"", "-Mode", "production"
    )
    if ($SkipBuild) { $childArgs += "-SkipBuild" }
    $child = Start-Process -FilePath "powershell.exe" -ArgumentList $childArgs -WindowStyle Hidden -PassThru
    Write-Host "Starting Network Finder in background (PID $($child.Id)) ..."
    $deadline = (Get-Date).AddSeconds($BackgroundStartTimeoutS)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 2
        if (@(Get-ListenPids -Port $listenPort).Count -gt 0) {
            Write-Host "Network Finder is running on http://localhost:$listenPort  (log: $LogFile, stop: .\scripts\run.ps1 -Stop)"
            exit 0
        }
        if ($child.HasExited) {
            Write-Host "Network Finder failed to start (exit $($child.ExitCode)). See $LogFile" -ForegroundColor Red
            exit 1
        }
    }
    Write-Host "Still starting after ${BackgroundStartTimeoutS}s; check $LogFile" -ForegroundColor Yellow
    exit 0
}

trap {
    # Write-Log persists to production.log, so hidden -Background runs keep the failure reason.
    Write-Log "$($_.Exception.Message)" "ERROR"
    break
}

# --- modes -------------------------------------------------------------------
if ($Mode -eq "dev") {
    Write-Log "Starting development (env file: .env)"
    if (-not (Test-Path -LiteralPath (Join-Path $Root ".env"))) {
        Invoke-Checked -Label "npm run setup" -FilePath $npmCmd -ArgumentList @("run", "setup")
    }
    Write-Log "npm run dev  (Ctrl+C to stop)"
    & $npmCmd @("run", "dev")
    exit $LASTEXITCODE
}

# production
Write-Log "Starting production on ${listenHost}:${listenPort} (env: .env.production, DB: Docker Postgres)"

Start-DockerDb

$distIndex = Join-Path $Root "frontend\dist\index.html"
$needBuild = -not $SkipBuild
if ($SkipBuild -and -not (Test-Path -LiteralPath $distIndex)) {
    Write-Log "frontend/dist missing; build required despite -SkipBuild" "WARN"
    $needBuild = $true
}

if (-not (Test-Path -LiteralPath (Join-Path $Root "node_modules"))) {
    Invoke-Checked -Label "npm install" -FilePath $npmCmd -ArgumentList @("install")
}

if ($needBuild) {
    Invoke-Checked -Label "npm run build" -FilePath $npmCmd -ArgumentList @("run", "build")
} else {
    Write-Log "Skipping frontend build (-SkipBuild)"
}

Invoke-Checked -Label "database migrate" -FilePath $npmCmd -ArgumentList @("run", "db:migrate")

$PID | Set-Content -LiteralPath $PidFile -Encoding ascii
Write-Log "PID file $PidFile <- $PID"

Write-Log "uvicorn app.main:app (host nmap + Docker Postgres:$($env:POSTGRES_PORT))"
$uvArgs = @(
    "scripts/py.mjs", "-m", "uvicorn", "app.main:app",
    "--host", $listenHost,
    "--port", "$listenPort",
    "--proxy-headers",
    "--forwarded-allow-ips", $forwarded,
    "--log-level", "warning"
)

try {
    & node @uvArgs 2>&1 | ForEach-Object {
        $text = "$_"
        Write-Host $text
        Add-Content -LiteralPath $LogFile -Value $text -Encoding UTF8
    }
    $code = if ($null -eq $LASTEXITCODE) { 0 } else { $LASTEXITCODE }
    Write-Log "uvicorn exited with code $code" $(if ($code -eq 0) { "INFO" } else { "ERROR" })
    exit $code
} finally {
    Remove-Item -LiteralPath $PidFile -Force -ErrorAction SilentlyContinue
}
