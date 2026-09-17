#!/usr/bin/env bash
# ============================================================
#  HunterAI — Kali Linux Full Tool Installation Script
#  Run once:  chmod +x install_tools_kali.sh && ./install_tools_kali.sh
# ============================================================
set -e
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
NC="\033[0m"

echo -e "${GREEN}[HunterAI] Full Offensive Toolkit Installer (Kali)${NC}"

# -- Go-based tools --
echo -e "\n${YELLOW}[+] Installing Go tools...${NC}"
go_tools=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/ffuf/ffuf/v2@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/tomnomnom/httprobe@latest"
    "github.com/tomnomnom/hakrawler@latest"
    "github.com/tomnomnom/anew@latest"
    "github.com/tomnomnom/qsreplace@latest"
    "github.com/PentestPad/subzy@latest"
    "github.com/hahwul/dalfox/v2@latest"
    "github.com/Emoe/kxss@latest"
    "github.com/OJ/gobuster/v3@latest"
)

for pkg in "${go_tools[@]}"; do
    tool=$(basename "$pkg" | cut -d'@' -f1)
    if command -v "$tool" &>/dev/null || [ -f "$HOME/go/bin/$tool" ]; then
        echo -e "  SKIP $tool already installed"
    else
        echo -e "  INSTALL $tool ..."
        go install -v "$pkg" 2>/dev/null && echo "  OK $tool" || echo "  FAIL $tool"
    fi
done

if ! echo "$PATH" | grep -q "$HOME/go/bin"; then
    echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
    echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.zshrc
    export PATH="$PATH:$HOME/go/bin"
fi

# -- APT tools --
echo -e "\n${YELLOW}[+] Installing APT tools...${NC}"
sudo apt-get update -qq
for tool in nmap gobuster nikto sqlmap amass feroxbuster dnsrecon; do
    if command -v "$tool" &>/dev/null; then
        echo "  SKIP $tool"
    else
        sudo apt-get install -y "$tool" 2>/dev/null && echo "  OK $tool" || echo "  FAIL $tool"
    fi
done

# theHarvester
if ! command -v theHarvester &>/dev/null; then
    sudo apt-get install -y theharvester 2>/dev/null || pip install theHarvester 2>/dev/null || true
fi

# -- Python tools --
echo -e "\n${YELLOW}[+] Installing Python tools...${NC}"
for tool in arjun dirsearch trufflehog; do
    pip install "$tool" 2>/dev/null && echo "  OK $tool" || echo "  FAIL $tool"
done

# -- SecLists --
echo -e "\n${YELLOW}[+] Checking SecLists...${NC}"
if [ -d "/usr/share/seclists" ] || [ -d "/home/kali/wordlist/SecLists" ] || [ -d "$HOME/wordlist/SecLists" ]; then
    echo "  SecLists already available"
else
    sudo apt-get install -y seclists 2>/dev/null || git clone --depth=1 https://github.com/danielmiessler/SecLists.git ~/wordlist/SecLists
fi

# -- Nuclei templates update --
if command -v nuclei &>/dev/null || [ -f "$HOME/go/bin/nuclei" ]; then
    echo -e "\n${YELLOW}[+] Updating Nuclei templates...${NC}"
    nuclei -update-templates -silent 2>/dev/null || true
fi

# -- Final status --
echo -e "\n${GREEN}===== TOOL STATUS CHECK =====${NC}"
ALL_TOOLS=(subfinder httpx katana nuclei ffuf gau waybackurls assetfinder httprobe
           hakrawler subzy dalfox kxss gobuster nmap nikto sqlmap amass feroxbuster
           dnsrecon theHarvester arjun dirsearch)
for tool in "${ALL_TOOLS[@]}"; do
    lower=$(echo "$tool" | tr '[:upper:]' '[:lower:]')
    if command -v "$lower" &>/dev/null || command -v "$tool" &>/dev/null || [ -f "$HOME/go/bin/$lower" ]; then
        echo -e "  [OK]   $tool"
    else
        echo -e "  [MISS] $tool --- NOT FOUND"
    fi
done
echo -e "\n${GREEN}Done! Run: python main.py -t https://target.com --hunter --authorized --mode full${NC}"
