# =====================================================================
#  install_agent.ps1 - HunterAI/PentestAI-Unified + OpenCode Installer
#  Downloads & assembles EVERYTHING the agent needs, in the right order.
#  Idempotent - safe to re-run anytime.
#
#  Usage:
#    .\install_agent.ps1                       # full default install (core skills)
#    .\install_agent.ps1 -Profiles core,redteam
#    .\install_agent.ps1 -Full                 # compatibility flag; centralized catalog remains active
#    .\install_agent.ps1 -KaliTools            # also install Kali arsenal (WSL/bash)
#    .\install_agent.ps1 -CheckOnly            # verify environment only
# =====================================================================
param(
    [string]$Profiles = "core",
    [switch]$Full,
    [switch]$SkipPythonDeps,
    [switch]$SkipSkills,
    [switch]$KaliTools,
    [switch]$CheckOnly
)

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

# ---------------------------------------------------------------
function Step  { param($n, $m) Write-Host "`n== [$n] $m" -ForegroundColor Cyan }
function Ok    { param($m) Write-Host "   [OK] $m" -ForegroundColor Green }
function Warnm { param($m) Write-Host "   [!]  $m" -ForegroundColor Yellow }
function Fail  { param($m) Write-Host "   [X]  $m" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "=============================================" -ForegroundColor Magenta
Write-Host " HunterAI OpenCode Agent Installer" -ForegroundColor Magenta
Write-Host " Root: $Root" -ForegroundColor Magenta
Write-Host "=============================================" -ForegroundColor Magenta

# ---------------------------------------------------------------
Step 1 "Checking prerequisites"
$GitExe    = Get-Command git    -ErrorAction SilentlyContinue
$PythonExe = Get-Command python -ErrorAction SilentlyContinue
$NodeExe   = Get-Command node   -ErrorAction SilentlyContinue
if (-not $GitExe)    { Fail "git not found    -> https://git-scm.com/download/win" }
if (-not $PythonExe) { Fail "python not found -> https://www.python.org/downloads/ (3.11+)" }
if (-not $NodeExe)   { Warnm "node not found - npx-based MCP servers (filesystem/github) will fail until Node.js is installed" }
$GitV  = & git --version
$PyV   = & python --version
$NodeV = if ($NodeExe) { & node --version } else { "MISSING" }
Ok "git: $GitV"
Ok "python: $PyV"
Ok "node: $NodeV"

# ---------------------------------------------------------------
Step 2 "Python dependencies (requirements.txt)"
if ($SkipPythonDeps) {
    Warnm "skipped by flag"
} elseif ($CheckOnly) {
    Warnm "check-only: verifying file existence only"
} else {
    & python -m pip install --quiet --disable-pip-version-check -r requirements.txt
    if ($LASTEXITCODE -ne 0) { Fail "pip install -r requirements.txt failed" }
    Ok "python dependencies installed"
}

# ---------------------------------------------------------------
Step 3 "uv package (provides uvx for semgrep-mcp and other uvx MCP servers)"
$Uvx = Get-Command uvx -ErrorAction SilentlyContinue
if ($Uvx) {
    Ok "uvx already present"
} elseif ($CheckOnly) {
    Warnm "check-only: uvx missing - will be installed on real run"
} else {
    & python -m pip install --quiet --disable-pip-version-check uv
    if ($LASTEXITCODE -ne 0) {
        Warnm "uv install failed (optional - only uvx MCP servers need it)"
    } else {
        Ok "uv installed"
    }
}

# ---------------------------------------------------------------
Step 4 "Reviewed project skill registry"
if (-not (Test-Path "skills/registry.json")) { Fail "skills/registry.json missing" }
if (-not (Test-Path "skills/hunterai-redteam/SKILL.md")) { Fail "canonical hunterai-redteam skill missing" }
Ok "canonical project registry found; community packages are intake material, not active skills"

# ---------------------------------------------------------------
Step 5 "Synchronizing centralized skills -> .opencode/skills and .agents/skills"
$SkillArgs = @()
if ($Full) { $SkillArgs += "--full" } else { $SkillArgs += @("--profiles", $Profiles) }
if ($SkipSkills) {
    Warnm "skipped by flag"
} elseif ($CheckOnly) {
    & python tools/install_opencode_skills.py --check
    if ($LASTEXITCODE -ne 0) { Fail "project skill registry check failed" }
    Ok "project skill registry and mirrors are synchronized"
} else {
    & python tools/install_opencode_skills.py --clean @SkillArgs
    if ($LASTEXITCODE -ne 0) { Fail "skill installer failed" }
    Ok "centralized HunterAI red-team skill installed"
}

# ---------------------------------------------------------------
Step 6 "Validating opencode.json (MCP servers config)"
if (Test-Path opencode.json) {
    try {
        $null = Get-Content opencode.json -Raw | ConvertFrom-Json
        Ok "opencode.json valid"
    } catch {
        Fail "opencode.json is not valid JSON: $($_.Exception.Message)"
    }
} else {
    Warnm "opencode.json missing - MCP servers not configured (see docs/OPENCODE_INTEGRATION.md)"
}

# ---------------------------------------------------------------
Step 7 "Agent MCP sanity check (python pentest.py mcp-serve --list-tools)"
$tools = & python pentest.py mcp-serve --list-tools 2>$null | Select-String "exposes"
if ($tools) { Ok "$($tools.ToString().Trim())" }
else        { Warnm "mcp-serve listing failed - run it manually to debug" }

# ---------------------------------------------------------------
Step 8 "Kali arsenal tools (optional, needs WSL/bash)"
if ($KaliTools) {
    if ($CheckOnly) {
        Warnm "check-only: would run install_tools_kali.sh"
    } else {
        $Wsl = Get-Command wsl -ErrorAction SilentlyContinue
        if ($Wsl) {
            & wsl bash -c "cd /mnt/e/Agant/PentestAI-Unified && bash install_tools_kali.sh"
            if ($LASTEXITCODE -eq 0) { Ok "Kali tools installed via WSL" }
            else { Warnm "kali install script exited non-zero - check its output" }
        } else {
            Warnm "WSL not found - install Kali tools manually per install_tools_kali.sh"
        }
    }
} else {
    Write-Host "   skipped (use -KaliTools to install)" -ForegroundColor DarkGray
}

# ---------------------------------------------------------------
Write-Host ""
Write-Host "=============================================" -ForegroundColor Magenta
if ($CheckOnly) { Write-Host " CHECK-ONLY COMPLETE - no downloads were made" -ForegroundColor Magenta }
else            { Write-Host " INSTALL COMPLETE - agent is ready" -ForegroundColor Magenta }
Write-Host "  Skills : .opencode/skills/MANIFEST.json" -ForegroundColor Magenta
Write-Host "  MCP    : opencode.json" -ForegroundColor Magenta
Write-Host "  Docs   : docs/OPENCODE_INTEGRATION.md" -ForegroundColor Magenta
Write-Host "=============================================" -ForegroundColor Magenta
