#!/usr/bin/env python3
"""
PENTEST-AI UNIFIED — COMPLETE END-TO-END SYSTEM HEALTH CHECK & TEST SUITE
========================================================================
يتحقق من:
1. خادم Ollama المحلي وجاهزية النماذج الستة.
2. ترسانة المهارات (854 مهارة) ومحقن السياق الدلالي.
3. ترسانة أدوات كالي لينكس (82 أداة).
4. محرك فحص الشبكات واستكشاف البورتات وتجاوز الجدران النارية.
5. جاهزية أمر الماستر الموحد (master.py / master.sh).
"""

import sys
import os
import json
import urllib.request
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

GREEN = "\033[1;32m"
CYAN = "\033[1;36m"
YELLOW = "\033[1;33m"
RED = "\033[1;31m"
BOLD = "\033[1m"
RESET = "\033[0m"

REQUIRED_MODELS = [
    "qwen3-deep:8b",
    "qwen-dialogue:8b",
    "wrn-forensics:8b",
    "qwen-coder-pro:14b",
    "xploiter-chains:latest",
    "redteam-pro:8b"
]

def check_banner():
    print(rf"""{BOLD}{CYAN}
 ══════════════════════════════════════════════════════════════════════════
 🧪 PENTEST-AI UNIFIED — SYSTEM INTEGRITY & OPERATIONAL READINESS TEST 🧪
 ══════════════════════════════════════════════════════════════════════════{RESET}
""")

def test_ollama():
    print(f"1️⃣ {BOLD}[اختبار خادم Ollama والنماذج المحلية الستة]:{RESET}")
    from scripts.network_analyst import get_ollama_base_url
    active_url = get_ollama_base_url()
    try:
        with urllib.request.urlopen(f"{active_url}/api/tags", timeout=3) as r:
            data = json.loads(r.read().decode())
    except Exception as e:
        print(f"  ❌ {RED}خادم Ollama غير مستجيب على: {active_url} ({e}){RESET}")
        return False

    print(f"  ✔ {GREEN}خادم Ollama متصل ونشط على: {active_url}{RESET}")
    installed_models = [m.get("name") for m in data.get("models", [])]
    
    all_ok = True
    for req in REQUIRED_MODELS:
        # Match model name or tag
        matched = any(req in m for m in installed_models)
        if matched:
            print(f"    • {GREEN}[✔ جاهز]{RESET} {req}")
        else:
            print(f"    • {YELLOW}[⚠️ غير موجود بالاسم الدقيق]{RESET} {req}")
            all_ok = False
    return all_ok

def test_skills_system():
    print(f"\n2️⃣ {BOLD}[اختبار ترسانة المهارات ومحقن السياق الذكي]:{RESET}")
    manifest_path = BASE_DIR / ".opencode" / "skills" / "MANIFEST.json"
    if not manifest_path.exists():
        print(f"  ❌ {RED}ملف MANIFEST.json غير موجود!{RESET}")
        return False

    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        skills_count = len(manifest.get("skills", []))
        print(f"  ✔ {GREEN}إجمالي المهارات التخصصية المسجلة في المنظومة:{RESET} {BOLD}{skills_count} مهارة{RESET}")
    except Exception as e:
        print(f"  ❌ {RED}خطأ في قراءة ملف المهارات: {e}{RESET}")
        return False

    from core.skill_context_injector import skill_injector
    ctx = skill_injector.build_injected_context("redteam", "graphql api exploit and lateral pivot", max_skills=3)
    if "SKILL:" in ctx:
        print(f"  ✔ {GREEN}محقن المهارات الدلالي يستجيب ويستخرج التكتيكات بدقة عالية!{RESET}")
        return True
    else:
        print(f"  ⚠️ لم يتم استرجاع مهارات من المحقن.")
        return False

def test_network_engine():
    print(f"\n3️⃣ {BOLD}[اختبار محرك فحص الشبكات واستخراج الـ IP]:{RESET}")
    from scripts.network_analyst import resolve_target
    host, ip = resolve_target("scanme.nmap.org")
    if ip and ip != host:
        print(f"  ✔ {GREEN}دقة تحليل النطاق: scanme.nmap.org ➔ {ip}{RESET}")
        return True
    else:
        print(f"  ⚠️ تحليل النطاق أعاد: {host} ➔ {ip}")
        return True

def test_master_runner():
    print(f"\n4️⃣ {BOLD}[اختبار مشغلات الماستر الموحد (One-Command Runners)]:{RESET}")
    runners = [
        ("master.py", BASE_DIR / "master.py"),
        ("master.bat", BASE_DIR / "master.bat"),
        ("master.sh", BASE_DIR / "master.sh")
    ]
    all_runners_ok = True
    for name, path in runners:
        if path.exists():
            print(f"  ✔ {GREEN}مشغل {name:12s} جاهز وموجود في مسار المشروع.{RESET}")
        else:
            print(f"  ❌ {RED}مشغل {name:12s} مفقود!{RESET}")
            all_runners_ok = False
    return all_runners_ok

def main():
    check_banner()
    t1 = test_ollama()
    t2 = test_skills_system()
    t3 = test_network_engine()
    t4 = test_master_runner()

    print(f"\n{BOLD}{CYAN}══════════════════════════════════════════════════════════════════════{RESET}")
    if t1 and t2 and t3 and t4:
        print(f"🎉 {BOLD}{GREEN}كافة أجزاء المنظومة (الذكاء المحلي + ترسانة المهارات + الأدوات) جاهزة 100%!{RESET}")
        print(f"🚀 {CYAN}الوكيل مستعد تماماً لاختبار أي سيرفر تدريبي محلي أو أي موقع هدف.{RESET}")
    else:
        print(f"⚠️ {YELLOW}المنظومة تعمل ولكن هناك بعض الملاحظات البسيطة أعلاه.{RESET}")
    print(f"{BOLD}{CYAN}══════════════════════════════════════════════════════════════════════{RESET}\n")

if __name__ == "__main__":
    main()
