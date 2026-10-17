#!/usr/bin/env bash
# ============================================================
#  HunterAI — Kali Linux Full Tool Installation Script
#  Run once:  chmod +x install_tools_kali.sh && ./install_tools_kali.sh
#
#  ما يضيفه هذا الإصدار (لمنع "الوكيل يُキذّذب" عن الأدوات):
#  1. يُثبت الأدوات الناقصة من المنهجية (subfinder, httpx, katana, nuclei, ffuf, ...).
#  2. يُverify كل أداة بعد التثبيت عبر `--version`/`--help` — لا يُدرّج أداة كعاملة إلا إذا شغلَت فعليًا.
#  3. إذا فشلت أداة "مطلوبة" (REQUIRED_TOOLS)، ينتهي السكربت برمز خروج غيرصفر (إلا مع --no-strict).
#  4. يُشغّل scripts/verify_kali_toolchain.py --strict في النهاية للتقرير الموحّد (الأدوات + طرازات Ollama).
# ============================================================
set -uo pipefail

STRICT=1
for arg in "$@"; do
  case "$arg" in
    --no-strict) STRICT=0 ;;
    --strict)    STRICT=1 ;;
  esac
done

GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
NC="\033[0m"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FAILED_TOOLS=()

echo -e "${GREEN}[HunterAI] Kali Offensive Toolkit Installer + Verification${NC}"
echo -e "${YELLOW}Strict mode: $([ "$STRICT" = 1 ] && echo ON || echo OFF)${NC}"

# ── دالة التحقق: تُreturn 0 إذا الأداة تعمل فعليًا ─────────────────────────
verify_tool() {
  local tool="$1"
  local bin
  bin="$(command -v "$tool" 2>/dev/null || true)"
  if [ -z "$bin" ]; then
    echo -e "  [MISS] $tool — not on PATH"
    return 1
  fi
  # جرّب أوامر الإصدار الشائعة؛ أي مخرج合法 يعني الأداة تعمل.
  for arg in --version -V version --help -h; do
    if "$bin" "$arg" >/dev/null 2>&1; then
      echo -e "  [OK]   $tool ($bin)"
      return 0
    fi
  done
  # بعض الأدوات تُreturn exit non-zero على --help لكنها لا تزال تعمل (مثل nuclei القدامى).
  if "$bin" >/dev/null 2>&1; then
    echo -e "  [OK]   $tool ($bin, runs without args)"
    return 0
  fi
  echo -e "  [FAIL] $tool — found at $bin but does not run"
  return 1
}

register_fail() { FAILED_TOOLS+=("$1"); }

# ── Go environment ──────────────────────────────────────────────────────────
export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$PATH:/usr/local/go/bin:$GOPATH/bin"
if ! grep -q "export GOPATH=" ~/.bashrc 2>/dev/null; then
  echo "export GOPATH=\$HOME/go" >> ~/.bashrc
  echo "export PATH=\$PATH:/usr/local/go/bin:\$GOPATH/bin" >> ~/.bashrc
fi

# ── Go-based recon / web tools ──────────────────────────────────────────────
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
  "github.com/jaeles-project/gospider@latest"
  "github.com/tomnomnom/dnsx/cmd/dnsx@latest"
  "github.com/penetration-testing-tools/naabu@latest"
)
for pkg in "${go_tools[@]}"; do
  tool="$(basename "$pkg" | cut -d'@' -f1)"
  if command -v "$tool" &>/dev/null || [ -f "$GOPATH/bin/$tool" ]; then
    echo -e "  SKIP $tool already installed"
  else
    echo -e "  INSTALL $tool ..."
    if go install -v "$pkg" >/dev/null 2>&1; then
      echo -e "  OK $tool installed"
    else
      echo -e "  FAIL $tool go install failed"
      register_fail "$tool"
    fi
  fi
done

if ! echo "$PATH" | grep -q "$GOPATH/bin"; then
  echo "export PATH=\$PATH:$GOPATH/bin" >> ~/.bashrc
  echo "export PATH=\$PATH:$GOPATH/bin" >> ~/.zshrc 2>/dev/null || true
  export PATH="$PATH:$GOPATH/bin"
fi

# ── APT-based tools ─────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[+] Installing APT tools...${NC}"
sudo apt-get update -qq 2>/dev/null || true
apt_tools=(nmap sqlmap amass nikto feroxbuster dnsrecon theharvester wpscan curl gobuster masscan)
for tool in "${apt_tools[@]}"; do
  if command -v "$tool" &>/dev/null; then
    echo "  SKIP $tool"
  else
    if sudo apt-get install -y "$tool" >/dev/null 2>&1; then
      echo -e "  OK $tool installed"
    else
      echo -e "  FAIL $tool apt install failed"
      register_fail "$tool"
    fi
  fi
done

# ── Python-based tools ──────────────────────────────────────────────────────
echo -e "\n${YELLOW}[+] Installing Python tools...${NC}"
pip_tools=(arjun dirsearch trufflehog wafw00f)
for tool in "${pip_tools[@]}"; do
  if command -v "$tool" &>/dev/null; then
    echo "  SKIP $tool"
  else
    if pip install --break-system-packages "$tool" >/dev/null 2>&1 || pip install "$tool" >/dev/null 2>&1; then
      echo -e "  OK $tool installed"
    else
      echo -e "  FAIL $tool pip install failed"
      register_fail "$tool"
    fi
  fi
done

# ── SecLists wordlists ──────────────────────────────────────────────────────
echo -e "\n${YELLOW}[+] Checking SecLists...${NC}"
if [ -d "/usr/share/seclists" ] || [ -d "/home/kali/wordlist/SecLists" ] || [ -d "$HOME/wordlist/SecLists" ]; then
  echo "  SecLists already available"
else
  sudo apt-get install -y seclists >/dev/null 2>&1 || git clone --depth=1 https://github.com/danielmiessler/SecLists.git ~/wordlist/SecLists 2>/dev/null || true
fi

# ── Nuclei templates ────────────────────────────────────────────────────────
if command -v nuclei &>/dev/null || [ -f "$GOPATH/bin/nuclei" ]; then
  echo -e "\n${YELLOW}[+] Updating Nuclei templates...${NC}"
  nuclei -update-templates -silent >/dev/null 2>&1 || true
fi

# ── pós-install verification for every known tool ───────────────────────────
echo -e "\n${GREEN}===== POST-INSTALL TOOL VERIFICATION =====${NC}"
ALL_TOOLS=(subfinder httpx katana nuclei ffuf gau waybackurls assetfinder httprobe
           hakrawler subzy dalfox kxss gobuster gospider dnsx naabu
           nmap nikto sqlmap amass feroxbuster dnsrecon theHarvester arjun dirsearch wpscan curl masscan)
for tool in "${ALL_TOOLS[@]}"; do
  if ! verify_tool "$tool"; then
    register_fail "$tool"
  fi
done

# ── Unified verification (tools + Ollama models) ────────────────────────────
echo -e "\n${YELLOW}[+] Running unified readiness check...${NC}"
if [ -f "$ROOT_DIR/scripts/verify_kali_toolchain.py" ]; then
  if command -v python3 &>/dev/null; then
    python3 "$ROOT_DIR/scripts/verify_kali_toolchain.py" --strict || register_fail "verify_kali_toolchain"
  else
    echo -e "  [WARN] python3 not found; skipping unified check"
  fi
else
  echo -e "  [WARN] scripts/verify_kali_toolchain.py not found"
fi

# ── Final report ────────────────────────────────────────────────────────────
echo -e "\n${GREEN}===== FINAL REPORT =====${NC}"
if [ "${#FAILED_TOOLS[@]}" -eq 0 ]; then
  echo -e "${GREEN}[✓] All tools verified and ready.${NC}"
  echo -e "Run: python main.py -t https://target.com --mode full"
  exit 0
else
  echo -e "${RED}[✗] The following tools failed verification:${NC}"
  for t in "${FAILED_TOOLS[@]}"; do echo -e "  - $t"; done
  if [ "$STRICT" = 1 ]; then
    echo -e "${RED}Exiting non-zero so the agent does not start with a broken toolchain.${NC}"
    exit 1
  else
    echo -e "${YELLOW}Continuing (--no-strict), but some scans may fail.${NC}"
    exit 0
  fi
fi
