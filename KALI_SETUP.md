# PentestAI Unified — Kali VM + Windows Ollama Setup

## Architecture

```
┌─────────────────────────────┐     ┌──────────────────────────────────────┐
│     Windows Host            │     │        Kali Linux VM                 │
│                             │     │                                      │
│  Ollama :11434              │◄────│  PentestAI Unified                   │
│  ├─ xploiter/pentester      │     │  ├─ Web UI (port 7070)               │
│  ├─ qwen2.5-coder:14b       │     │  ├─ Model Council (connects to Win)  │
│  └─ WhiteRabbitNeo:8B       │     │  ├─ nmap, nuclei, sqlmap, gobuster   │
│                             │     │  ├─ ffuf, dalfox, httpx, subfinder   │
│                             │     │  └─ 150+ security tools              │
└─────────────────────────────┘     └──────────────────────────────────────┘
```

---

## STEP 1 — Windows: Expose Ollama on the Network

By default, Ollama binds only to `127.0.0.1`. Bind it to `0.0.0.0` so the Kali VM can reach it.

### PowerShell (Windows)

Open **PowerShell as Administrator**:

```powershell
# Set the environment variable
[System.Environment]::SetEnvironmentVariable("OLLAMA_HOST", "0.0.0.0:11434", "Machine")

# Restart the Ollama service
Stop-Process -Name "ollama" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Start-Process "ollama" -ArgumentList "serve"
```

### Manual Configuration
1. Search Windows for **"Edit system environment variables"**.
2. Add a new system variable:
   - **Name**: `OLLAMA_HOST`
   - **Value**: `0.0.0.0:11434`
3. Restart Ollama.

### Verify
```powershell
# From Windows
curl http://localhost:11434/api/tags

# From Kali VM (replace IP)
curl http://192.168.x.x:11434/api/tags
```

---

## STEP 2 — Windows: Firewall

```powershell
# Allow inbound Ollama traffic through Windows Firewall
New-NetFirewallRule -DisplayName "Ollama AI Port" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 11434 `
    -Action Allow
```

---

## STEP 3 — Find the Windows Host IP from Kali VM

```bash
# From Kali
ip route | grep default
# Example: default via 192.168.72.1 dev eth0
#          ↑ Windows Host IP
```

**Common host IPs:**
| VM Network Type | Windows IP inside Kali |
|-----------------|------------------------|
| VMware NAT | `192.168.72.1` or `192.168.x.1` |
| VirtualBox NAT | `10.0.2.2` |
| VMware Host-Only | `192.168.x.1` |
| Bridged | Same subnet as the router |

---

## STEP 4 — Kali: Install and Run

```bash
# Copy the project to Kali (via shared folder or git)
# If using a VMware shared folder:
cp -r /mnt/hgfs/Agant/PentestAI-Unified/ ~/pentestai/
cd ~/pentestai

# Or serve it from Windows with Python HTTP server:
# On Windows: python -m http.server 8888 --directory E:\Agant
# On Kali: wget http://192.168.x.x:8888/PentestAI-Unified.zip

# Run full installation
chmod +x setup_kali.sh
sudo ./setup_kali.sh
```

---

## STEP 5 — Update `.env` Manually (if the setup script did not apply it)

```bash
nano .env
```

Edit:
```
OLLAMA_HOST=http://192.168.72.1:11434
```

(Replace `192.168.72.1` with the actual Windows host IP.)

---

## STEP 6 — Test the Connection

```bash
source venv/bin/activate
python3 test_connection.py
```

### Verify Toolchain Inside Kali

```bash
python3 scripts/verify_kali_toolchain.py --strict
```

This check contacts no external targets; it runs `--version` or `--help` on each tool and outputs a structured JSON report. If a required tool is missing or fails, it exits with a non-zero status code rather than allowing the agent to start with an incomplete toolchain.

### Verify Agent + Burp + Browser Before Scanning a Target

Start Burp Suite with a Proxy listener on `127.0.0.1:8080`, then run strict mode:

```bash
python3 main.py -t https://your-authorized-target.example \
  --authorized --proxy http://127.0.0.1:8080 --require-burp-browser
```

This mode blocks any target-facing phase unless it confirms Burp proxy connectivity, a running local HunterAI Gateway, and Playwright launching with the same proxy configured. Check results are saved to `00_integration/agent_burp_browser.json` under the session artifacts directory.

Expected output:
```
[*] Testing Ollama at: http://192.168.72.1:11434
[+] Connected! Models found: 3
    - xploiter/pentester:latest
    - qwen2.5-coder:14b
    - WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest

[+] All 3 required models are available!
```

---

## STEP 7 — Run PentestAI

```bash
source venv/bin/activate

# Web UI
python3 main.py
# Then open in Kali: http://localhost:7070

# Or run CLI directly
python3 main.py --cli

# Or run a direct scan
python3 main.py -t 192.168.1.100 --mode full
```

---

## Troubleshooting

### Issue: "Cannot connect to Ollama"
```bash
# Check default gateway IP
ip route | grep default

# Test directly
curl http://[WINDOWS_IP]:11434/api/tags

# If it fails, check Windows Firewall rules
```

### Issue: "Connection refused"
```powershell
# On Windows — verify Ollama is listening
netstat -an | findstr 11434
# Expected: TCP 0.0.0.0:11434 LISTENING
```

### Issue: Ollama listens only on `127.0.0.1`
```powershell
# Stop Ollama
Stop-Process -Name "ollama" -Force
# Start with explicit host binding
$env:OLLAMA_HOST = "0.0.0.0:11434"
ollama serve
```

---

## Network Modes

### VMware NAT (Easiest)
- Windows IP from Kali: `192.168.72.1` (or `192.168.x.1`)
- Ollama URL: `http://192.168.72.1:11434`

### VirtualBox NAT
- Windows IP from Kali: `10.0.2.2`
- Ollama URL: `http://10.0.2.2:11434`

### Bridged (Best for pentesting)
- All hosts share the same network segment.
- Windows IP: the host machine's LAN IP address.
