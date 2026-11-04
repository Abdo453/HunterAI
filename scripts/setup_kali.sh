#!/bin/bash
set -e

echo "[*] Initializing Kali Linux Environment for PentestAI-Unified..."

# 1. Force IPv4 for apt to prevent IPv6 timeout on regional mirrors
echo 'Acquire::ForceIPv4 "true";' > /etc/apt/apt.conf.d/99force-ipv4

# 2. Update and install core system packages
echo "[*] Updating apt repositories and installing Python & core tools..."
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y --fix-missing \
    python3-pip \
    python3-venv \
    python3-full \
    git \
    curl \
    ca-certificates

# 3. Create Desktop & wordlists workspace for kali user
echo "[*] Configuring /home/kali workspace structure..."
mkdir -p /home/kali/Desktop
mkdir -p /home/kali/wordlist/SecLists

# If repository wordlists exist, link or copy standard lists
if [ -d "/mnt/e/Agant/PentestAI-Unified/data/wordlists" ]; then
    mkdir -p /home/kali/wordlist/SecLists/Discovery/Web-Content
    mkdir -p /home/kali/wordlist/SecLists/Ai/LLM_Testing
    cp -r /mnt/e/Agant/PentestAI-Unified/data/wordlists/* /home/kali/wordlist/ 2>/dev/null || true
fi

# 4. Create and configure virtual environment
echo "[*] Setting up Python virtual environment at /home/kali/pentest-venv..."
python3 -m venv /home/kali/pentest-venv

# 5. Upgrade pip and install repository dependencies
echo "[*] Installing Python dependencies from requirements.txt..."
/home/kali/pentest-venv/bin/pip install --upgrade pip setuptools wheel
if [ -f "/mnt/e/Agant/PentestAI-Unified/requirements.txt" ]; then
    /home/kali/pentest-venv/bin/pip install -r /mnt/e/Agant/PentestAI-Unified/requirements.txt
fi

# 6. Set correct permissions for kali user
chown -R kali:kali /home/kali/Desktop /home/kali/wordlist /home/kali/pentest-venv

# 7. Create global CLI launcher /usr/local/bin/pentest
echo "[*] Creating global /usr/local/bin/pentest launcher..."
cat << 'EOF' > /usr/local/bin/pentest
#!/bin/bash
REPO_DIR="/mnt/e/Agant/PentestAI-Unified"
VENV_PY="/home/kali/pentest-venv/bin/python"

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
