# PentestAI Unified — Kali VM + Windows Ollama Setup

## الـ Architecture

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

## STEP 1 — Windows: تفعيل Ollama على الشبكة

بـ default، Ollama بيسمع على `127.0.0.1` بس.
لازم نخليه يسمع على `0.0.0.0` عشان الـ VM يوصله.

### الطريقة (Windows):

افتح **PowerShell as Administrator**:

```powershell
# إضافة متغير البيئة
[System.Environment]::SetEnvironmentVariable("OLLAMA_HOST", "0.0.0.0:11434", "Machine")

# إعادة تشغيل Ollama service
Stop-Process -Name "ollama" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Start-Process "ollama" -ArgumentList "serve"
```

### أو يدوياً:
1. ابحث في Windows عن **"Edit system environment variables"**
2. أضف متغير جديد:
   - **Name**: `OLLAMA_HOST`
   - **Value**: `0.0.0.0:11434`
3. أعد تشغيل Ollama

### التحقق:
```powershell
# من Windows
curl http://localhost:11434/api/tags

# من Kali VM (استبدل IP)
curl http://192.168.x.x:11434/api/tags
```

---

## STEP 2 — Windows: الـ Firewall

```powershell
# السماح بـ Ollama عبر الـ Firewall
New-NetFirewallRule -DisplayName "Ollama AI Port" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 11434 `
    -Action Allow
```

---

## STEP 3 — الحصول على الـ Windows IP داخل Kali VM

```bash
# من Kali
ip route | grep default
# مثال: default via 192.168.72.1 dev eth0
#        ↑ هذا هو IP الـ Windows Host
```

**IPs شائعة:**
| نوع الـ VM | Windows IP داخل Kali |
|------------|---------------------|
| VMware NAT | `192.168.72.1` أو `192.168.x.1` |
| VirtualBox NAT | `10.0.2.2` |
| VMware Host-Only | `192.168.x.1` |
| Bridged | نفس شبكة الـ router |

---

## STEP 4 — Kali: تثبيت وتشغيل

```bash
# نسخ المشروع لـ Kali (من Windows share أو git)
# إذا عندك shared folder:
cp -r /mnt/hgfs/Agant/PentestAI-Unified/ ~/pentestai/
cd ~/pentestai

# أو استخدم Python HTTP server من Windows:
# على Windows: python -m http.server 8888 --directory E:\Agant
# على Kali: wget http://192.168.x.x:8888/PentestAI-Unified.zip

# تثبيت كل شيء
chmod +x setup_kali.sh
sudo ./setup_kali.sh
```

---

## STEP 5 — تحديث .env يدوياً (لو السكربت ما اشتغلش)

```bash
nano .env
```

عدّل:
```
OLLAMA_HOST=http://192.168.72.1:11434
```

(استبدل `192.168.72.1` بـ IP الـ Windows الفعلي)

---

## STEP 6 — اختبار الاتصال

```bash
source venv/bin/activate
python3 test_connection.py
```

المتوقع:
```
[*] Testing Ollama at: http://192.168.72.1:11434
[+] Connected! Models found: 3
    - xploiter/pentester:latest
    - qwen2.5-coder:14b
    - WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest

[+] All 3 required models are available!
```

---

## STEP 7 — تشغيل PentestAI

```bash
source venv/bin/activate

# Web UI
python3 main.py
# ثم افتح في Kali: http://localhost:7070

# أو CLI مباشر
python3 main.py --cli

# أو scan مباشر
python3 main.py -t 192.168.1.100 --mode full
```

---

## استكشاف الأخطاء

### مشكلة: "Cannot connect to Ollama"
```bash
# تحقق من الـ IP
ip route | grep default

# اختبار مباشر
curl http://[WINDOWS_IP]:11434/api/tags

# لو فاشل، تحقق من الـ Firewall على Windows
```

### مشكلة: "Connection refused"
```powershell
# على Windows — تحقق إن Ollama شغال
netstat -an | findstr 11434
# لازم تشوف: TCP 0.0.0.0:11434 LISTENING
```

### مشكلة: Ollama بيسمع على 127.0.0.1 بس
```powershell
# أوقف Ollama
Stop-Process -Name "ollama" -Force
# شغّل مع explicit host
$env:OLLAMA_HOST = "0.0.0.0:11434"
ollama serve
```

---

## الـ Network Modes

### VMware NAT (الأسهل):
- Windows IP من Kali: `192.168.72.1` (أو `192.168.x.1`)
- Ollama URL: `http://192.168.72.1:11434`

### VirtualBox NAT:
- Windows IP من Kali: `10.0.2.2`
- Ollama URL: `http://10.0.2.2:11434`

### Bridged (الأفضل للـ pentest):
- كل الأجهزة على نفس الشبكة
- Windows IP: نفس IP الجهاز الفعلي على الشبكة
