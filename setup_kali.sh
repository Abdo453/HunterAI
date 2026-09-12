#!/bin/bash
# ==============================================================================
# PentestAI Unified — 1-Click Kali Linux Setup & Tool Installer
# تثبيت كافة أدوات المنهجية وإعداد الاتصال بموديلات Ollama على ويندوز
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "======================================================================"
echo "   🧠 PentestAI Unified — Kali Linux 1-Click Setup & Installer"
echo "======================================================================"
echo -e "${NC}"

# 1. تحديث الحزم وتثبيت الأساسيات والمتصفح
echo -e "${YELLOW}[1/6] Installing Core Prerequisites, Chromium, HTTPX Toolkit & Go Environment...${NC}"
sudo apt install -y git curl wget jq python3 python3-pip python3-venv golang-go nmap sqlmap chromium chromium-driver firefox-esr httpx-toolkit

# إعداد مسارات Go في .bashrc
export GOPATH=$HOME/go
export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin
if ! grep -q "export GOPATH=" ~/.bashrc; then
    echo "export GOPATH=\$HOME/go" >> ~/.bashrc
    echo "export PATH=\$PATH:/usr/local/go/bin:\$GOPATH/bin" >> ~/.bashrc
fi

# 2. تثبيت أدوات Go المشهورة للمنهجية (ProjectDiscovery & TomNomNom)
echo -e "${YELLOW}[2/6] Installing Essential Go Recon Tools...${NC}"

echo -e "${BLUE}  -> Installing subfinder...${NC}"
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

echo -e "${BLUE}  -> Installing httpx...${NC}"
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

echo -e "${BLUE}  -> Installing katana (Crawler)...${NC}"
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

echo -e "${BLUE}  -> Installing nuclei (Vulnerability Scanner)...${NC}"
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

echo -e "${BLUE}  -> Installing anew (Merge & Deduplication)...${NC}"
go install -v github.com/tomnomnom/anew@latest

echo -e "${BLUE}  -> Installing gau (URL Archive Finder)...${NC}"
go install -v github.com/lc/gau/v2/cmd/gau@latest

echo -e "${BLUE}  -> Installing qsreplace (Parameter Fuzzing)...${NC}"
go install -v github.com/tomnomnom/qsreplace@latest

echo -e "${BLUE}  -> Installing ffuf (Fast Web Fuzzer)...${NC}"
go install -v github.com/ffuf/ffuf/v2@latest

# 3. تثبيت أدوات Python (Arjun, Dirsearch, Wafw00f)
echo -e "${YELLOW}[3/6] Installing Python Security Tools...${NC}"
pip install --break-system-packages --upgrade pip httpx rich click python-dotenv pyyaml psutil requests 2>/dev/null || true
pip install --break-system-packages --upgrade arjun dirsearch wafw00f 2>/dev/null || sudo apt install -y wafw00f dirsearch || true

# 4. تجهيز مجلد القوائم والـ Wordlists
echo -e "${YELLOW}[4/6] Setting up Wordlists Directory...${NC}"
sudo mkdir -p /usr/share/wordlists/seclists
if [ -d "/home/kali/wordlist/SecLists" ]; then
    echo -e "${GREEN}  -> Found user SecLists at /home/kali/wordlist/SecLists!${NC}"
    if [ -z "$(ls -A /usr/share/wordlists/seclists 2>/dev/null)" ]; then
        echo -e "${BLUE}  -> Symlinking /home/kali/wordlist/SecLists -> /usr/share/wordlists/seclists...${NC}"
        sudo ln -sfn /home/kali/wordlist/SecLists/* /usr/share/wordlists/seclists/ 2>/dev/null || true
    fi
fi
if [ ! -f /usr/share/wordlists/rockyou.txt ] && [ -f /usr/share/wordlists/rockyou.txt.gz ]; then
    echo -e "${BLUE}  -> Uncompressing rockyou.txt.gz...${NC}"
    sudo gunzip -f /usr/share/wordlists/rockyou.txt.gz || true
fi

# 5. إعداد البيئة الافتراضية للمشروع
echo -e "${YELLOW}[5/6] Setting up Python Virtual Environment for PentestAI...${NC}"
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt || true
echo -e "${BLUE}  -> Installing Playwright browser engines (Chromium & Firefox)...${NC}"
playwright install --with-deps chromium firefox 2>/dev/null || true

# 6. ضبط عنوان Windows Ollama Host
echo -e "${YELLOW}[6/6] Configuring Windows Ollama Connection...${NC}"
DEFAULT_IP="192.168.1.8"
read -p "Enter your Windows Host IP address [$DEFAULT_IP]: " WIN_IP
WIN_IP=${WIN_IP:-$DEFAULT_IP}

OLLAMA_URL="http://${WIN_IP}:11434"

# تحديث ملف .env
if [ -f .env.example ]; then
    cp .env.example .env
    sed -i "s|OLLAMA_HOST=.*|OLLAMA_HOST=${OLLAMA_URL}|g" .env
else
    echo "OLLAMA_HOST=${OLLAMA_URL}" >> .env
fi

echo -e "${CYAN}Testing connection to Windows Ollama at ${OLLAMA_URL}...${NC}"
if curl -s --connect-timeout 4 "${OLLAMA_URL}/api/tags" > /dev/null; then
    echo -e "${GREEN}[✓] SUCCESS: Connected to Windows Ollama!${NC}"
else
    echo -e "${RED}[!] WARNING: Could not connect to Windows Ollama at ${OLLAMA_URL}.${NC}"
    echo -e "${YELLOW}Make sure Windows Firewall allows port 11434 and OLLAMA_HOST=0.0.0.0:11434 is set on Windows.${NC}"
fi

echo -e "${GREEN}"
echo "======================================================================"
echo " 🎉 PentestAI Unified Setup Complete!"
echo " To start the Web UI on Kali:  python3 main.py"
echo " To test the 3 models on Kali: python3 test_3_models.py ${OLLAMA_URL}"
echo "======================================================================"
echo -e "${NC}"
