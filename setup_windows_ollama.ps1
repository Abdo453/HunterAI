# ============================================================
# HunterAI — Windows Ollama Setup (Secure Localhost Default)
# Defaults to 127.0.0.1:11434. Pass -AllowLAN explicitly only
# if you intentionally expose Ollama to a local Kali VM/WSL2.
# ============================================================
param(
    [switch]$AllowLAN
)

$bindHost = if ($AllowLAN) { "0.0.0.0:11434" } else { "127.0.0.1:11434" }

Write-Host "`n[*] HunterAI - Configuring Ollama ($bindHost)..." -ForegroundColor Cyan

# ─── 1. Configure OLLAMA_HOST (safe 127.0.0.1:11434 default) ───
Write-Host "`n[1] Setting OLLAMA_HOST to $bindHost..." -ForegroundColor Yellow
[System.Environment]::SetEnvironmentVariable("OLLAMA_HOST", $bindHost, "User")
$env:OLLAMA_HOST = $bindHost
Write-Host "    [+] OLLAMA_HOST set to $bindHost" -ForegroundColor Green

# ─── 2. Optional Firewall Rule (ONLY when -AllowLAN is passed) ─
if ($AllowLAN) {
    Write-Host "`n[2] -AllowLAN enabled: checking Windows Firewall rule for port 11434..." -ForegroundColor Yellow
    $existing = Get-NetFirewallRule -DisplayName "Ollama AI Port" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "    [+] Firewall rule already exists" -ForegroundColor Green
    } else {
        New-NetFirewallRule -DisplayName "Ollama AI Port" `
            -Direction Inbound `
            -Protocol TCP `
            -LocalPort 11434 `
            -Profile Private `
            -Action Allow | Out-Null
        Write-Host "    [+] Private-network firewall rule added" -ForegroundColor Green
    }
} else {
    Write-Host "`n[2] Localhost-only binding active (no inbound firewall rule opened)." -ForegroundColor Green
}

# ─── 3. Restart Ollama ────────────────────────────────────────
Write-Host "`n[3] Restarting Ollama service..." -ForegroundColor Yellow
$ollamaProc = Get-Process -Name "ollama" -ErrorAction SilentlyContinue
if ($ollamaProc) {
    Stop-Process -Name "ollama" -Force
    Start-Sleep -Seconds 2
    Write-Host "    [+] Ollama stopped" -ForegroundColor Green
}

$ollamaCmd = Get-Command ollama -ErrorAction SilentlyContinue
if ($ollamaCmd) {
    $ollamaPath = $ollamaCmd.Source
} elseif (Test-Path "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe") {
    $ollamaPath = "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe"
} elseif (Test-Path "C:\Program Files\Ollama\ollama.exe") {
    $ollamaPath = "C:\Program Files\Ollama\ollama.exe"
} else {
    $ollamaPath = $null
}

if ($ollamaPath -and (Test-Path $ollamaPath)) {
    Start-Process $ollamaPath -ArgumentList "serve" -WindowStyle Hidden
    Start-Sleep -Seconds 3
    Write-Host "    [+] Ollama started on $bindHost" -ForegroundColor Green
} else {
    Write-Host "    [!] Ollama binary not found - install Ollama and start it manually" -ForegroundColor Yellow
}

# ─── 4. Verify Localhost Endpoint ─────────────────────────────
Write-Host "`n[4] Verifying Ollama on http://127.0.0.1:11434/api/tags..." -ForegroundColor Yellow
Start-Sleep -Seconds 2
try {
    $models = Invoke-RestMethod -Uri "http://127.0.0.1:11434/api/tags" -TimeoutSec 5
    Write-Host "    [+] Ollama reachable! Models available: $($models.models.Count)" -ForegroundColor Green
    foreach ($m in $models.models) {
        Write-Host "        - $($m.name)" -ForegroundColor White
    }
} catch {
    Write-Host "    [!] Could not reach http://127.0.0.1:11434/api/tags yet." -ForegroundColor Yellow
}

Write-Host "`n============================================" -ForegroundColor Green
Write-Host "  HunterAI Ollama Setup Complete!" -ForegroundColor Green
Write-Host "  Endpoint: http://127.0.0.1:11434" -ForegroundColor Cyan
Write-Host "  Launch:   python pentest.py artex" -ForegroundColor Cyan
Write-Host "============================================`n" -ForegroundColor Green
