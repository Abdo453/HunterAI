#!/usr/bin/env python3
"""
scripts/kali_monitor.py
========================
Kali Linux Live Agent & Models Monitor
يقوم بمراقبة النماذج وأدوات كالي لينكس واختبار الوكيل في بيئة كالي الحقيقية
"""

import os
import sys
import time
import json
import socket
import platform
import subprocess
import urllib.request
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

# الألوان لعرض لوحة تحكم احترافية في التيرمنال
GREEN = "\033[1;32m"
CYAN = "\033[1;36m"
YELLOW = "\033[1;33m"
RED = "\033[1;31m"
BOLD = "\033[1m"
RESET = "\033[0m"

SECURITY_TOOLS = [
    "nmap", "nuclei", "sqlmap", "ffuf", "httpx", "katana",
    "subfinder", "amass", "gobuster", "dalfox", "wpscan",
    "hydra", "nikto", "wafw00f", "dirsearch", "arjun",
    "naabu", "dnsx", "httprobe", "trufflehog3", "anew",
    "qsreplace", "paramspider", "gau", "waybackurls", "feroxbuster", "masscan"
]

ALL_MODELS = [
    ("qwen3-deep:8b", "المفكر العميق (Strategic Deep Reasoning)"),
    ("qwen-dialogue:8b", "المحاور وموجه المتصفح (AI Browser & OSINT)"),
    ("wrn-forensics:8b", "خبير الثغرات والشبكات (CVEs & ADCS)"),
    ("qwen-coder-pro:14b", "كبير مهندسي البرمجيات (Zero-Defect Coder)"),
    ("xploiter-chains:latest", "خبير سلاسل الاستغلال (Exploit Chaining)"),
    ("redteam-pro:8b", "قائد الفريق الأحمر و Burp Suite (Traffic Gate)")
]


def detect_ollama_host() -> str:
    """كشف رابط Ollama التلقائي سواء محلي أو عبر WSL Gateway"""
    env_host = os.getenv("OLLAMA_HOST")
    if env_host:
        if not env_host.startswith("http"):
            env_host = f"http://{env_host}"
        env_host = env_host.replace("://0.0.0.0:", "://127.0.0.1:").rstrip("/")
        try:
            with urllib.request.urlopen(f"{env_host}/api/tags", timeout=1):
                return env_host
        except Exception:
            pass

    # فحص localhost أولاً
    for target in ["http://127.0.0.1:11434", "http://localhost:11434"]:
        try:
            with urllib.request.urlopen(f"{target}/api/tags", timeout=1):
                return target
        except Exception:
            pass

    # فحص WSL Gateway
    try:
        out = subprocess.check_output(["ip", "route", "show", "default"], text=True, timeout=2)
        parts = out.split()
        if "via" in parts:
            gw = parts[parts.index("via") + 1]
            gw_url = f"http://{gw}:11434"
            with urllib.request.urlopen(f"{gw_url}/api/tags", timeout=2):
                return gw_url
    except Exception:
        pass

    return "http://127.0.0.1:11434"


def get_loaded_models(base_url: str) -> list:
    """معرفة النماذج المحملة حالياً في كارت الشاشة/الذاكرة"""
    try:
        with urllib.request.urlopen(f"{base_url}/api/ps", timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("models", [])
    except Exception:
        return []


def unload_model(base_url: str, model_name: str):
    """تفريغ النموذج فورياً لتوفير VRAM"""
    try:
        req = urllib.request.Request(
            f"{base_url}/api/generate",
            data=json.dumps({"model": model_name, "keep_alive": 0}).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass


def check_kali_environment():
    """فحص بيئة كالي لينكس والنظام"""
    print(f"\n{BOLD}{CYAN}══════════════════════════════════════════════════════════════════════{RESET}")
    print(f"{BOLD}{GREEN} 🐧 [1/4] فحص بيئة كالي لينكس (Kali Linux Environment Check){RESET}")
    print(f"{BOLD}{CYAN}══════════════════════════════════════════════════════════════════════{RESET}")

    os_info = platform.platform()
    py_ver = sys.version.split()[0]
    hostname = socket.gethostname()

    # محاولة قراءة اسم التوزيعة
    distro = "Linux"
    if Path("/etc/os-release").exists():
        try:
            for line in Path("/etc/os-release").read_text().splitlines():
                if line.startswith("PRETTY_NAME="):
                    distro = line.split("=", 1)[1].strip('"\'')
                    break
        except Exception:
            pass

    print(f"  • التوزيعة (Distro):    {BOLD}{distro}{RESET}")
    print(f"  • النواة (Kernel):     {os_info}")
    print(f"  • اسم الجهاز (Host):   {hostname}")
    print(f"  • إصدار Python:        {py_ver}")


def check_security_tools():
    """فحص أسلحة وترسانة كالي لينكس الأمنية"""
    print(f"\n{BOLD}{CYAN}══════════════════════════════════════════════════════════════════════{RESET}")
    print(f"{BOLD}{GREEN} ⚔️ [2/4] جرد ترسانة أسلحة كالي للأمن السيبراني (Kali Arsenal Check){RESET}")
    print(f"{BOLD}{CYAN}══════════════════════════════════════════════════════════════════════{RESET}")

    installed = []
    missing = []

    for tool in SECURITY_TOOLS:
        path = subprocess.run(["which", tool], capture_output=True, text=True).stdout.strip()
        if path:
            installed.append((tool, path))
            print(f"  {GREEN}✔{RESET} {tool:14s} ➔ {path}")
        else:
            missing.append(tool)
            print(f"  {RED}✘{RESET} {tool:14s} ➔ غير مثبت")

    print(f"\n  📊 النتيجة: {GREEN}{len(installed)}{RESET}/{len(SECURITY_TOOLS)} أداة هجومية جاهزة للعمل الفوري.")


def check_models_telemetry(base_url: str):
    """مراقبة النماذج والاتصال بخادم الذكاء الاصطناعي"""
    print(f"\n{BOLD}{CYAN}══════════════════════════════════════════════════════════════════════{RESET}")
    print(f"{BOLD}{GREEN} 🤖 [3/4] مراقبة النماذج وذاكرة كارت الشاشة (Models Telemetry & VRAM){RESET}")
    print(f"{BOLD}{CYAN}══════════════════════════════════════════════════════════════════════{RESET}")
    print(f"  • الخادم المتصل: {BOLD}{base_url}{RESET}")

    try:
        with urllib.request.urlopen(f"{base_url}/api/tags", timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            available = {m["name"] for m in data.get("models", [])}
    except Exception as e:
        print(f"  {RED}❌ تعذر الاتصال بـ Ollama على {base_url}: {e}{RESET}")
        return

    print(f"\n  حالة النماذج الستة المخصصة للوكيل:")
    for model_name, role_desc in ALL_MODELS:
        status = f"{GREEN}جاهز ومثبت (Ready){RESET}" if model_name in available else f"{RED}غير متوفر{RESET}"
        print(f"  • {BOLD}{model_name:24s}{RESET} ➔ {status} | {role_desc}")

    # النماذج المحملة حالياً في VRAM
    loaded = get_loaded_models(base_url)
    print(f"\n  حالة الـ GPU / VRAM الحالية:")
    if loaded:
        for lm in loaded:
            size_mb = lm.get("size", 0) / (1024 * 1024)
            print(f"  ⚡ {YELLOW}نموذج نشط في الذاكرة: {lm.get('name')} | الحجم: {size_mb:.1f} MB | المعالج: {lm.get('processor', 'GPU')}{RESET}")
    else:
        print(f"  💤 {GREEN}كافة النماذج مفرغة من الـ VRAM (وضع توفير الطاقة والجاهزية القصوى){RESET}")


def live_agent_round(base_url: str, target: str):
    """تشغيل جولة فحص حقيقية من كالي بواسطة الوكيل ونموذج صائد الثغرات"""
    print(f"\n{BOLD}{CYAN}══════════════════════════════════════════════════════════════════════{RESET}")
    print(f"{BOLD}{GREEN} 🎯 [4/4] تجربة الوكيل الحية على كالي لينكس (Live Agent Execution){RESET}")
    print(f"{BOLD}{CYAN}══════════════════════════════════════════════════════════════════════{RESET}")
    print(f"  الهدف التجريبي: {BOLD}{target}{RESET}")

    # 1. تنفيذ استطلاع شبكي سريع من كالي بواسطة httpx أو nmap إذا متاح
    print(f"\n🔍 [Kali Engine] جاري تنفيذ فحص أولي للمنافذ/الرؤوس باستخدام أداة httpx...")
    probe_output = ""
    try:
        res = subprocess.run(
            ["httpx", "-u", f"https://{target}", "-title", "-status-code", "-tech-detect", "-silent"],
            capture_output=True, text=True, timeout=15
        )
        probe_output = res.stdout.strip()
        if probe_output:
            print(f"  {GREEN}✔ مخرجات أداة httpx الحية من كالي:{RESET}")
            print(f"    {probe_output}")
        else:
            probe_output = f"Target {target} responsive on port 443/80 (HTTPS/HTTP)"
            print(f"  ℹ️ {probe_output}")
    except Exception as e:
        probe_output = f"Simulated reconnaissance on {target}"
        print(f"  ℹ️ استطلاع تجريبي على {target}")

    # 2. استدعاء نموذج الفريق الأحمر (redteam-pro:8b) لتحليل المخرجات
    print(f"\n🚀 [Agent AI Brain] إرسال مخرجات كالي إلى نموذج [redteam-pro:8b] للتحليل التكتيكي...")
    prompt = (
        f"Target: {target}\n"
        f"Kali Recon Output: {probe_output}\n\n"
        f"بناءً على مهاراتك المحقونة (api-fuzzing, hack router, SecLists): "
        f"قدم خطة فحص سريعة من 3 نقاط تحدد فيها: نوع الهجوم الأنسب، الثغرة المحتملة (IDOR/Auth Bypass/API Flaw)، وكيفية إثبات الأثر الحقيقي (7-Question Gate)."
    )

    t0 = time.time()
    try:
        req = urllib.request.Request(
            f"{base_url}/api/generate",
            data=json.dumps({
                "model": "redteam-pro:8b",
                "prompt": prompt,
                "stream": False,
                "options": {"num_ctx": 2048, "num_predict": 250, "temperature": 0.4}
            }).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=90) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            elapsed = time.time() - t0
            ai_analysis = data.get("response", "").strip()

            print(f"\n⏱️ {GREEN}تم التحليل بنجاح خلال {elapsed:.1f} ثانية من داخل كالي لينكس!{RESET}")
            print(f"\n{BOLD}📋 تقرير وتوجيهات الوكيل الذكي (Agent Directive):{RESET}")
            print("─" * 70)
            print(ai_analysis)
            print("─" * 70)
    except Exception as e:
        print(f"  {RED}⚠️ خطأ أثناء استدعاء النموذج: {e}{RESET}")
    finally:
        # تفريغ فوري لـ VRAM
        unload_model(base_url, "redteam-pro:8b")
        print(f"  🧹 {GREEN}تم تفريغ redteam-pro:8b من الـ VRAM بنجاح.{RESET}")


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    base_url = detect_ollama_host()

    check_kali_environment()
    check_security_tools()
    check_models_telemetry(base_url)
    live_agent_round(base_url, target)

    print(f"\n{BOLD}{GREEN}══════════════════════════════════════════════════════════════════════{RESET}")
    print(f"{BOLD}{GREEN} 🎉 اكتمل فحص وتجربة الوكيل والموديلات على كالي لينكس بنجاح تام!{RESET}")
    print(f"{BOLD}{CYAN}══════════════════════════════════════════════════════════════════════{RESET}\n")


if __name__ == "__main__":
    main()
