# =====================================================================
#  install_agent.ps1 - HunterAI/PentestAI-Unified + OpenCode Installer
#  Downloads & assembles EVERYTHING the agent needs, in the right order.
#  Idempotent - safe to re-run anytime.
#
#  Usage:
#    .\install_agent.ps1                       # full default install (core skills)
#    .\install_agent.ps1 -Profiles core,redteam
#    .\install_agent.ps1 -Full                 # install ALL skills in the library
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
Step 4 "Skills library packs (skills_library/)"
$Packs = @(
    @{ Dir="skills_library/anthropic-cyber"; Url="https://github.com/mukul975/Anthropic-Cybersecurity-Skills.git" },
    @{ Dir="skills_library/trailofbits";     Url="https://github.com/trailofbits/skills.git" },
    @{ Dir="skills_library/briiirussell";    Url="https://github.com/briiirussell/cybersecurity-skills.git" },
    @{ Dir="skills_library/anthropics";      Url="https://github.com/anthropics/skills.git" },
    @{ Dir="skills_library/microsoft";       Url="https://github.com/microsoft/skills.git" }
)
foreach ($p in $Packs) {
    if ($CheckOnly) {
        Warnm "check-only: $($p.Dir)"
        continue
    }
    if (Test-Path $p.Dir) {
        & git -C $p.Dir pull --ff-only 2>$null
        if ($LASTEXITCODE -eq 0) { Ok "updated $($p.Dir)" }
        else { Warnm "pull failed for $($p.Dir) (keeping local copy)" }
    } else {
        Write-Host "   cloning $($p.Url) ..." -ForegroundColor DarkCyan
        & git clone --depth 1 $p.Url $p.Dir 2>$null
        if ($LASTEXITCODE -ne 0) { Fail "clone failed: $($p.Url)" }
        Ok "cloned $($p.Dir)"
    }
}

# ---------------------------------------------------------------
Step 5 "Installing active skills -> .opencode/skills/"
$SkillArgs = @()
if ($Full) { $SkillArgs += "--full" } else { $SkillArgs += @("--profiles", $Profiles) }
if ($SkipSkills) {
    Warnm "skipped by flag"
} elseif ($CheckOnly) {
    $cnt = 0
    if (Test-Path .opencode/skills) { $cnt = (Get-ChildItem .opencode/skills -Directory).Count }
    Warnm "check-only: $cnt skills currently active"
} else {
    & python tools/install_opencode_skills.py --clean @SkillArgs
    if ($LASTEXITCODE -ne 0) { Fail "skill installer failed" }
    $label = if ($Full) { "FULL" } else { $Profiles }
    Ok "skills installed (profiles: $label)"
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
