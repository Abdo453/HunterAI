#!/bin/bash
set -e

echo "[*] Initializing Kali Linux Environment for PentestAI-Unified..."

# 1. Force IPv4 for apt to prevent IPv6 timeout on regional mirrors
echo 'Acquire::ForceIPv4 "true";' > /etc/apt/apt.conf.d/99force-ipv4

# 2. Update and install core system & security packages available in Kali apt
echo "[*] Installing Kali apt security packages..."
DEBIAN_FRONTEND=noninteractive apt-get install -y --fix-missing \
    golang-go \
    subfinder \
    nuclei \
    httpx-toolkit \
    feroxbuster \
    dirsearch \
    arjun \
    assetfinder \
    hakrawler \
    enum4linux-ng \
    ssh-audit \
    medusa \
    sherlock \
    gdb \
    checksec \
    foremost \
    steghide 2>/dev/null || {
    for pkg in golang-go subfinder nuclei httpx-toolkit feroxbuster dirsearch arjun assetfinder hakrawler enum4linux-ng ssh-audit medusa sherlock gdb checksec foremost steghide; do
        DEBIAN_FRONTEND=noninteractive apt-get install -y --fix-missing "$pkg" 2>/dev/null || true
    done
}

# 3. Install Go-based tools (katana, dalfox, gau, waybackurls, anew, qsreplace) directly to /usr/local/bin
export GOPATH=/root/go
export GOBIN=/usr/local/bin
export PATH="/usr/local/go/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$GOPATH/bin"

install_go_tool() {
    local bin_name="$1"
    local pkg_url="$2"
    if ! command -v "$bin_name" >/dev/null 2>&1; then
        echo "[*] Installing Go tool: $bin_name..."
        GOBIN=/usr/local/bin go install "$pkg_url" 2>/dev/null || true
    else
        echo "[+] Tool already available: $bin_name ($(command -v "$bin_name"))"
    fi
}

install_go_tool "katana"      "github.com/projectdiscovery/katana/cmd/katana@latest"
install_go_tool "subfinder"   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool "nuclei"      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
install_go_tool "dalfox"      "github.com/hahwul/dalfox/v2@latest"
install_go_tool "gau"         "github.com/lc/gau/v2/cmd/gau@latest"
install_go_tool "waybackurls" "github.com/tomnomnom/waybackurls@latest"
install_go_tool "assetfinder" "github.com/tomnomnom/assetfinder@latest"
install_go_tool "hakrawler"   "github.com/hakluke/hakrawler@latest"
install_go_tool "anew"        "github.com/tomnomnom/anew@latest"
install_go_tool "qsreplace"   "github.com/tomnomnom/qsreplace@latest"

# 4. Configure /home/kali workspace and SecLists structure
echo "[*] Configuring /home/kali workspace and SecLists structure..."
mkdir -p /home/kali/Desktop
mkdir -p /home/kali/wordlist/SecLists/Discovery/Web-Content
mkdir -p /home/kali/wordlist/SecLists/Ai/LLM_Testing
mkdir -p /home/kali/wordlist/SecLists/Passwords/Common-Credentials
mkdir -p /usr/share/wordlists

if [ -d "/mnt/e/Agant/PentestAI-Unified/data/wordlists" ]; then
    cp -r /mnt/e/Agant/PentestAI-Unified/data/wordlists/* /home/kali/wordlist/SecLists/ 2>/dev/null || true
fi

if [ ! -e "/usr/share/seclists" ]; then
    ln -sfn /home/kali/wordlist/SecLists /usr/share/seclists
fi
if [ ! -e "/usr/share/wordlists/seclists" ]; then
    ln -sfn /home/kali/wordlist/SecLists /usr/share/wordlists/seclists
fi

# 5. Ensure virtual environment and core requirements.txt packages (pydantic>=2.5, openai, fastapi) are intact
echo "[*] Ensuring Python virtual environment & core requirements..."
if [ ! -x "/home/kali/pentest-venv/bin/python" ]; then
    python3 -m venv /home/kali/pentest-venv
fi

if [ -f "/mnt/e/Agant/PentestAI-Unified/requirements.txt" ]; then
    /home/kali/pentest-venv/bin/pip install -q -r /mnt/e/Agant/PentestAI-Unified/requirements.txt
fi

# Symlink venv CLI tools to /usr/local/bin if missing on system PATH
if ! command -v paramspider >/dev/null 2>&1; then
    /home/kali/pentest-venv/bin/pip install -q git+https://github.com/devanshbatham/paramspider.git 2>/dev/null || true
fi
for vtool in arjun dirsearch ssh-audit checkov prowler kube-hunter vol paramspider; do
    if [ -x "/home/kali/pentest-venv/bin/$vtool" ] && [ ! -e "/usr/local/bin/$vtool" ]; then
        ln -sfn "/home/kali/pentest-venv/bin/$vtool" "/usr/local/bin/$vtool"
    fi
done

# Optional binary tools (zsteg, findomain, rustscan, trivy)
command -v zsteg >/dev/null 2>&1 || gem install zsteg --no-document 2>/dev/null || true
if ! command -v findomain >/dev/null 2>&1; then
    curl -sSL https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip -o /tmp/findomain.zip && unzip -qo /tmp/findomain.zip -d /usr/local/bin && chmod +x /usr/local/bin/findomain && rm -f /tmp/findomain.zip || true
fi
if ! command -v rustscan >/dev/null 2>&1; then
    curl -sSL https://github.com/bee-san/RustScan/releases/download/2.3.0/rustscan_2.3.0_amd64.deb -o /tmp/rustscan.deb && dpkg -i /tmp/rustscan.deb 2>/dev/null && rm -f /tmp/rustscan.deb || true
fi
if ! command -v trivy >/dev/null 2>&1; then
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin 2>/dev/null || true
fi

# 6. Set correct permissions for kali user
chown -R kali:kali /home/kali/Desktop /home/kali/wordlist /home/kali/pentest-venv 2>/dev/null || true

# 7. Create global CLI launcher /usr/local/bin/pentest
echo "[*] Creating global /usr/local/bin/pentest launcher..."
cat << 'EOF' > /usr/local/bin/pentest
#!/bin/bash
export PATH="$PATH:/usr/local/go/bin:/usr/local/bin:/home/kali/go/bin:/home/kali/pentest-venv/bin"
REPO_DIR="/mnt/e/Agant/PentestAI-Unified"
VENV_PY="/home/kali/pentest-venv/bin/python"

if ! curl -s --connect-timeout 1 http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
    WIN_IP="$(ip route show default 2>/dev/null | awk '/default/ {print $3; exit}')"
    if [ -n "$WIN_IP" ]; then
        export OLLAMA_HOST="http://${WIN_IP}:11434"
        export OLLAMA_BASE_URL="http://${WIN_IP}:11434"
    fi
fi

if [ -f "$REPO_DIR/pentest.py" ] && [ -x "$VENV_PY" ]; then
    cd "$REPO_DIR" && exec "$VENV_PY" "$REPO_DIR/pentest.py" "$@"
else
    echo "Error: PentestAI repository or virtualenv not found."
    exit 1
fi
EOF
chmod +x /usr/local/bin/pentest

echo "[+] PentestAI-Unified setup complete on Kali Linux!"
echo "[+] You can now run: pentest web [target] or pentest opencode [target] or pentest all [target]"
