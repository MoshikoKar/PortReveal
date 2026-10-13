#Requires -Version 5.1
<#
.SYNOPSIS
  Install optional web-capture host tools on Windows (Playwright Chromium, ffmpeg, FreeRDP).

.DESCRIPTION
  Idempotent helpers for Windows host production (Postgres may be in Docker; capture tools
  stay on the host). Soft-fails by default so `npm run setup` still succeeds when winget
  or Scoop cannot run. Use -Strict to exit non-zero on failure.

  FreeRDP nightlies currently ship `sdl-freerdp.exe` (not `wfreerdp.exe`). This script
  installs Scoop's freerdp-nightly and ensures a `wfreerdp` shim so Network Finder and
  PATH checks resolve a client binary.

.PARAMETER SkipPlaywright
  Do not install Playwright Chromium into backend\.venv

.PARAMETER SkipFfmpeg
  Do not install or PATH-fix ffmpeg

.PARAMETER SkipFreeRdp
  Do not install Scoop FreeRDP

.PARAMETER Strict
  Exit 1 if any requested tool could not be made available
#>
[CmdletBinding()]
param(
    [switch] $SkipPlaywright,
    [switch] $SkipFfmpeg,
    [switch] $SkipFreeRdp,
    [switch] $Strict
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$failed = New-Object System.Collections.Generic.List[string]

function Write-Step([string] $Message, [string] $Level = "INFO") {
    Write-Host ("[capture-tools] [{0}] {1}" -f $Level, $Message)
}

function Add-UserPathDir([string] $Dir) {
    if (-not $Dir -or -not (Test-Path -LiteralPath $Dir)) { return $false }
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not $userPath) { $userPath = "" }
    $parts = $userPath -split ";" | Where-Object { $_ -and $_.Trim() }
    $match = $parts | Where-Object { $_.TrimEnd("\") -ieq $Dir.TrimEnd("\") }
    if (-not $match) {
        $newPath = if ($userPath.Trim()) { "$userPath;$Dir" } else { $Dir }
        [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
        Write-Step "Added to User PATH: $Dir"
    }
    if ($env:Path -notlike "*$Dir*") {
        $env:Path = "$Dir;$env:Path"
    }
    return $true
}

function Test-Cmd([string] $Name) {
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Ensure-Playwright {
    $py = Join-Path $Root "backend\.venv\Scripts\python.exe"
    if (-not (Test-Path -LiteralPath $py)) {
        Write-Step "backend\.venv missing — skip Playwright (run npm run setup first)" "WARN"
        [void]$failed.Add("playwright")
        return
    }
    Write-Step "Installing Playwright Chromium (venv)"
    & $py -m playwright install chromium
    if ($LASTEXITCODE -ne 0) {
        Write-Step "playwright install chromium failed (exit $LASTEXITCODE)" "WARN"
        [void]$failed.Add("playwright")
        return
    }
    Write-Step "Playwright Chromium ready"
}

function Find-FfmpegBin {
    $cmd = Get-Command ffmpeg -ErrorAction SilentlyContinue
    if ($cmd) { return Split-Path -Parent $cmd.Source }

    $roots = @(
        (Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Packages"),
        (Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Links"),
        "C:\Program Files\WinGet\Links",
        "C:\ffmpeg"
    )
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        $exe = Get-ChildItem -LiteralPath $root -Recurse -Filter ffmpeg.exe -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($exe) { return $exe.Directory.FullName }
    }
    return $null
}

function Ensure-Ffmpeg {
    if (Test-Cmd "ffmpeg") {
        Write-Step "ffmpeg already on PATH"
        return
    }

    $bin = Find-FfmpegBin
    if ($bin) {
        [void](Add-UserPathDir $bin)
        if (Test-Cmd "ffmpeg") {
            Write-Step "ffmpeg found and added to PATH ($bin)"
            return
        }
    }

    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Step "winget not available — install ffmpeg manually and add its bin to PATH" "WARN"
        [void]$failed.Add("ffmpeg")
        return
    }

    Write-Step "Installing ffmpeg via winget (Gyan.FFmpeg)"
    winget install -e --id Gyan.FFmpeg --accept-package-agreements --accept-source-agreements
    # winget may report "already installed"; still try to locate the binary
    $bin = Find-FfmpegBin
    if ($bin) {
        [void](Add-UserPathDir $bin)
    }
    if (Test-Cmd "ffmpeg") {
        Write-Step "ffmpeg ready"
        return
    }
    Write-Step "ffmpeg still not on PATH after winget — open a new shell or add the bin folder manually" "WARN"
    [void]$failed.Add("ffmpeg")
}

function Get-ScoopCmd {
    $scoop = Get-Command scoop -ErrorAction SilentlyContinue
    if ($scoop) { return $scoop.Source }
    $shim = Join-Path $env:USERPROFILE "scoop\shims\scoop.cmd"
    if (Test-Path -LiteralPath $shim) { return $shim }
    return $null
}

function Ensure-Scoop {
    $scoop = Get-ScoopCmd
    if ($scoop) {
        [void](Add-UserPathDir (Join-Path $env:USERPROFILE "scoop\shims"))
        return $scoop
    }
    Write-Step "Installing Scoop (current user)"
    try {
        Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force -ErrorAction SilentlyContinue
        Invoke-RestMethod -Uri "https://get.scoop.sh" | Invoke-Expression
    } catch {
        Write-Step "Scoop install failed: $($_.Exception.Message)" "WARN"
        [void]$failed.Add("freerdp")
        return $null
    }
    $scoop = Get-ScoopCmd
    if (-not $scoop) {
        Write-Step "Scoop installed but scoop.cmd not found" "WARN"
        [void]$failed.Add("freerdp")
        return $null
    }
    [void](Add-UserPathDir (Join-Path $env:USERPROFILE "scoop\shims"))
    return $scoop
}

function Test-FreeRdpClient {
    foreach ($name in @("wfreerdp", "xfreerdp", "wlfreerdp", "sdl-freerdp", "sdl3-freerdp")) {
        if (Test-Cmd $name) { return $name }
    }
    return $null
}

function Ensure-WfreerdpShim {
    if (Test-Cmd "wfreerdp") { return $true }
    $app = Join-Path $env:USERPROFILE "scoop\apps\freerdp-nightly\current"
    $shims = Join-Path $env:USERPROFILE "scoop\shims"
    if (-not (Test-Path -LiteralPath $app)) { return $false }
    $src = @(
        (Join-Path $app "wfreerdp.exe"),
        (Join-Path $app "sdl-freerdp.exe"),
        (Join-Path $app "sdl3-freerdp.exe"),
        (Join-Path $app "xfreerdp.exe")
    ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $src) { return $false }
    New-Item -ItemType Directory -Force -Path $shims | Out-Null
    Copy-Item -LiteralPath $src -Destination (Join-Path $shims "wfreerdp.exe") -Force
    [void](Add-UserPathDir $shims)
    return (Test-Cmd "wfreerdp")
}

function Ensure-FreeRdp {
    $have = Test-FreeRdpClient
    if ($have) {
        [void](Ensure-WfreerdpShim)
        Write-Step "FreeRDP client already available ($have)"
        return
    }

    $scoop = Ensure-Scoop
    if (-not $scoop) { return }

    Write-Step "Ensuring Scoop versions bucket"
    & $scoop bucket add versions 2>$null | Out-Null

    Write-Step "Installing freerdp-nightly via Scoop"
    & $scoop install freerdp-nightly
    if ($LASTEXITCODE -ne 0 -and -not (Test-Path -LiteralPath (Join-Path $env:USERPROFILE "scoop\apps\freerdp-nightly\current"))) {
        Write-Step "scoop install freerdp-nightly failed (exit $LASTEXITCODE)" "WARN"
        [void]$failed.Add("freerdp")
        return
    }

    if (-not (Ensure-WfreerdpShim)) {
        Write-Step "FreeRDP installed but no client exe could be shimmed as wfreerdp" "WARN"
        [void]$failed.Add("freerdp")
        return
    }
    Write-Step "FreeRDP ready (wfreerdp shim)"
}

Write-Step "Root: $Root"
if (-not $SkipPlaywright) { Ensure-Playwright }
if (-not $SkipFfmpeg) { Ensure-Ffmpeg }
if (-not $SkipFreeRdp) { Ensure-FreeRdp }

Write-Step ("Summary — ffmpeg={0} freerdp={1} playwright_skipped={2}" -f `
    (Test-Cmd "ffmpeg"), `
    [bool](Test-FreeRdpClient), `
    [bool]$SkipPlaywright)

if ($failed.Count -gt 0) {
    Write-Step ("Incomplete: {0}" -f ($failed -join ", ")) "WARN"
    if ($Strict) { exit 1 }
    exit 0
}
Write-Step "All requested capture tools ready"
exit 0
