# ============================================================
# PentestAI Unified — Windows Ollama Network Setup
# شغّل هذا السكربت على Windows لتفعيل Ollama للـ VM
# Run as Administrator!
# ============================================================

Write-Host "`n[*] PentestAI - Configuring Ollama for Kali VM..." -ForegroundColor Cyan

# ─── 1. تفعيل Ollama على 0.0.0.0 ─────────────────────────────
Write-Host "`n[1] Setting OLLAMA_HOST to 0.0.0.0:11434..." -ForegroundColor Yellow
[System.Environment]::SetEnvironmentVariable("OLLAMA_HOST", "0.0.0.0:11434", "Machine")
$env:OLLAMA_HOST = "0.0.0.0:11434"
Write-Host "    [+] OLLAMA_HOST set to 0.0.0.0:11434" -ForegroundColor Green

# ─── 2. Firewall Rule ─────────────────────────────────────────
Write-Host "`n[2] Adding Firewall rule for Ollama port 11434..." -ForegroundColor Yellow
$existing = Get-NetFirewallRule -DisplayName "Ollama AI Port" -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "    [+] Firewall rule already exists" -ForegroundColor Green
} else {
    New-NetFirewallRule -DisplayName "Ollama AI Port" `
        -Direction Inbound `
        -Protocol TCP `
        -LocalPort 11434 `
        -Action Allow | Out-Null
    Write-Host "    [+] Firewall rule added" -ForegroundColor Green
}

# ─── 3. إعادة تشغيل Ollama ────────────────────────────────────
Write-Host "`n[3] Restarting Ollama service..." -ForegroundColor Yellow
$ollamaProc = Get-Process -Name "ollama" -ErrorAction SilentlyContinue
if ($ollamaProc) {
    Stop-Process -Name "ollama" -Force
    Start-Sleep -Seconds 2
    Write-Host "    [+] Ollama stopped" -ForegroundColor Green
}

# ابحث عن ollama.exe
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

if (Test-Path $ollamaPath) {
    Start-Process $ollamaPath -ArgumentList "serve" -WindowStyle Hidden
    Start-Sleep -Seconds 3
    Write-Host "    [+] Ollama started with network access" -ForegroundColor Green
} else {
    Write-Host "    [!] Ollama not found - start it manually" -ForegroundColor Yellow
}

# ─── 4. الـ Windows IP ────────────────────────────────────────
Write-Host "`n[4] Your Windows IP addresses (use one of these in Kali):" -ForegroundColor Yellow
$ips = Get-NetIPAddress -AddressFamily IPv4 | 
       Where-Object { $_.InterfaceAlias -notlike "*Loopback*" -and $_.IPAddress -ne "127.0.0.1" } |
       Select-Object IPAddress, InterfaceAlias
foreach ($ip in $ips) {
    Write-Host "    IP: $($ip.IPAddress)  ($($ip.InterfaceAlias))" -ForegroundColor Cyan
}

# ─── 5. التحقق ────────────────────────────────────────────────
Write-Host "`n[5] Verifying Ollama is listening..." -ForegroundColor Yellow
Start-Sleep -Seconds 2
$listening = netstat -an | Select-String ":11434" | Select-String "LISTENING"
if ($listening) {
    Write-Host "    [+] Ollama is listening on port 11434" -ForegroundColor Green
    
    # قائمة الموديلات
    try {
        $models = Invoke-RestMethod -Uri "http://localhost:11434/api/tags" -TimeoutSec 5
        Write-Host "    [+] Models available: $($models.models.Count)" -ForegroundColor Green
        foreach ($m in $models.models) {
            Write-Host "        - $($m.name)" -ForegroundColor White
        }
    } catch {
        Write-Host "    [!] Could not list models" -ForegroundColor Yellow
    }
} else {
    Write-Host "    [-] Ollama is NOT listening - check if it's running" -ForegroundColor Red
}

# ─── النتيجة ──────────────────────────────────────────────────
Write-Host "`n============================================" -ForegroundColor Green
Write-Host "  Setup Complete!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Now in Kali VM:" -ForegroundColor White
Write-Host "  1. Get Windows IP:  ip route | grep default" -ForegroundColor Cyan
Write-Host "  2. Test Ollama:     curl http://[WINDOWS_IP]:11434/api/tags" -ForegroundColor Cyan
Write-Host "  3. Run setup:       sudo ./setup_kali.sh" -ForegroundColor Cyan
Write-Host "  4. Start PentestAI: python3 main.py" -ForegroundColor Cyan
Write-Host ""
