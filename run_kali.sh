#!/bin/bash
# ==============================================================================
# PentestAI Unified — Run on Kali Linux
# تشغيل خادم الويب وواجهة الذكاء الاصطناعي على كالي لينكس بضغطة زر واحدة
# ==============================================================================

set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}"
echo "======================================================================"
echo "   🚀 Starting PentestAI Unified Framework on Kali Linux"
echo "======================================================================"
echo -e "${NC}"

# 1. تفعيل البيئة الافتراضية
if [ -d "venv" ]; then
    echo -e "${GREEN}[+] Activating virtual environment (venv)...${NC}"
    source venv/bin/activate
elif [ -d "../venv" ]; then
    source ../venv/bin/activate
fi

# 2. التأكد من ملف .env
if [ ! -f ".env" ] && [ -f ".env.example" ]; then
    echo -e "${YELLOW}[!] .env not found, copying from .env.example...${NC}"
    cp .env.example .env
fi

# 3. تشغيل الخادم وفتح المتصفح تلقائياً
echo -e "${GREEN}[+] Starting Web Dashboard on http://0.0.0.0:7070${NC}"
echo -e "${CYAN}[*] Opening browser at: http://localhost:7070 ...${NC}"

if command -v xdg-open &> /dev/null; then
    (sleep 2 && xdg-open http://localhost:7070 2>/dev/null) &
elif command -v firefox &> /dev/null; then
    (sleep 2 && firefox http://localhost:7070 2>/dev/null) &
fi

python3 main.py --web

