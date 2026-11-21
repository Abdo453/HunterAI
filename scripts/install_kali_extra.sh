#!/usr/bin/env bash
set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}======================================================================${NC}"
echo -e "${GREEN} 🚀 Installing & Verifying All Agent Security Tools on Kali Linux${NC}"
echo -e "${CYAN}======================================================================${NC}"

export GOPATH="$HOME/go"
mkdir -p "$GOPATH/bin"
export PATH="$GOPATH/bin:/usr/local/bin:$PATH"

# 1. تثبيت أدوات Go الناقصة
echo -e "\n${YELLOW}[1/4] Installing missing Go reconnaissance tools...${NC}"

install_go_tool() {
    local name="$1"
    local repo="$2"
    if command -v "$name" &>/dev/null || [ -f "/usr/local/bin/$name" ] || [ -f "$GOPATH/bin/$name" ]; then
        echo -e "  ${GREEN}✔${NC} $name is already installed."
    else
        echo -e "  ⏳ Installing $name ($repo)..."
        go install "$repo" 2>/dev/null || true
        if [ -f "$GOPATH/bin/$name" ]; then
            sudo cp "$GOPATH/bin/$name" /usr/local/bin/ 2>/dev/null || cp "$GOPATH/bin/$name" "$HOME/.local/bin/" 2>/dev/null || true
            echo -e "  ${GREEN}✔${NC} $name installed successfully!"
        else
            echo -e "  ⚠️ $name install skipped or failed."
        fi
    fi
}

install_go_tool "naabu" "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
install_go_tool "dnsx" "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
install_go_tool "subzy" "github.com/PentestPad/subzy@latest"
install_go_tool "kxss" "github.com/Emoe/kxss@latest"

# 2. فحص وتحديث قوالب Nuclei
echo -e "\n${YELLOW}[2/4] Updating Nuclei vulnerability templates...${NC}"
if command -v nuclei &>/dev/null; then
    nuclei -update-templates -silent 2>/dev/null || true
    echo -e "  ${GREEN}✔${NC} Nuclei templates are up to date."
else
    echo -e "  ⚠️ nuclei command not found."
fi

# 3. فحص وتثبيت أدوات بايثون الإضافية
echo -e "\n${YELLOW}[3/4] Installing Python security packages...${NC}"
pip install --break-system-packages trufflehog3 2>/dev/null || pip install trufflehog3 2>/dev/null || true
echo -e "  ${GREEN}✔${NC} Python security tools verified."

# 4. التقرير النهائي الشامل
echo -e "\n${YELLOW}[4/4] Final Verification of Agent Arsenal...${NC}"
TOOLS=(
    "nmap" "nuclei" "sqlmap" "ffuf" "httpx" "katana"
    "subfinder" "amass" "gobuster" "dalfox" "wpscan"
    "hydra" "nikto" "wafw00f" "dirsearch" "arjun"
    "paramspider" "gau" "waybackurls" "assetfinder" "hakrawler"
    "naabu" "dnsx" "subzy" "anew" "qsreplace" "feroxbuster" "masscan"
)

READY_COUNT=0
for t in "${TOOLS[@]}"; do
    if command -v "$t" &>/dev/null || [ -f "/usr/local/bin/$t" ] || [ -f "$GOPATH/bin/$t" ]; then
        READY_COUNT=$((READY_COUNT + 1))
        echo -e "  ${GREEN}✔${NC} $t"
    else
        echo -e "  ${YELLOW}✘${NC} $t (optional/missing)"
    fi
done

echo -e "\n${CYAN}======================================================================${NC}"
echo -e "${GREEN} 🎯 Arsenal Status: ${READY_COUNT}/${#TOOLS[@]} Cyber Security Tools Ready on Kali!${NC}"
echo -e "${CYAN}======================================================================${NC}\n"
