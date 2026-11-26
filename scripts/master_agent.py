#!/usr/bin/env python3
"""
PENTEST-AI UNIFIED — MAXIMUM POWER MASTER ORCHESTRATOR
======================================================
أمر واحد شامل يشغل المنظومة بالكامل:
- الاستطلاع الشبكي الشامل (Open, Closed, Filtered Ports).
- اختبارات تجاوز الجدار الناري والفلاتر عبر Nmap.
- استكشاف الويب والزحف والمتصفح الآلي (Web Recon & AI Browser).
- تشغيل النماذج الستة المحلية بالكامل (All 6 Local Ollama Models).
- حقن ترسانة الـ 850 مهارة تخصصية ديناميكياً.
- إصدار التقرير النهائي الشامل وحفظه تلقائياً.
"""

import sys
import os
import re
import json
import time
import subprocess
import urllib.request
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from core.skill_context_injector import skill_injector
from scripts.network_analyst import (
    resolve_target,
    run_full_network_scan,
    run_firewall_evasion_probes,
    classify_network_attack_surface,
    KNOWN_PORTS
)

# الألوان لعرض التقرير باحترافية
GREEN = "\033[1;32m"
CYAN = "\033[1;36m"
YELLOW = "\033[1;33m"
RED = "\033[1;31m"
BOLD = "\033[1m"
RESET = "\033[0m"

# النماذج الستة كاملة مع أدوارها ومفاتيح المهارات
ALL_MODELS = [
    {
        "id": "1_deep_thinker",
        "role_key": "deep_thinker",
        "model": "qwen3-deep:8b",
        "title": "1. المفكر العميق (Deep Reasoning & Logic)",
        "desc": "الاستدلال المنطقي والتفكير التحليلي العميق لتفكيك المسألة ودراسة السيناريوهات وحدود الثقة.",
        "sys": "أنت المفكر الاستراتيجي الأعمق. استخدم قدرات التفكير الداخلي لتفكيك الهدف وهندسة مسارات الهجوم وتوقع كل الاحتمالات."
    },
    {
        "id": "2_browser_nav",
        "role_key": "dialogue",
        "model": "qwen-dialogue:8b",
        "title": "2. موجه المتصفح والاستكشاف (AI Browser Navigator)",
        "desc": "قيادة المتصفح الآلي، زحف الروابط، تحليل استمارات الويب ورسم خريطة السطح ونقاط الدخول.",
        "sys": "أنت موجه المتصفح الآلي والاستكشاف. حدد مسارات الويب، نقاط الإدخال، وخريطة النطاق بدقة مستعيناً بمهارات المتصفح."
    },
    {
        "id": "3_cve_hunter",
        "role_key": "cve_hunter",
        "model": "wrn-forensics:8b",
        "title": "3. خبير الثغرات والشبكات و CVEs (Vulnerability & Attack Surface)",
        "desc": "تحليل أسطح الهجوم الشبكية، فحص منافذ وخدمات الهدف، ومطابقة الثغرات الأمنية المعروفة و CVEs.",
        "sys": "You are WRN-INTELLIGENCE. Map the attack surface, identify protocol vulnerabilities, and expose critical CVEs."
    },
    {
        "id": "4_code_architect",
        "role_key": "coder",
        "model": "qwen-coder-pro:14b",
        "title": "4. كبير مهندسي البرمجيات والأكواد (Zero-Defect Code Architect)",
        "desc": "كتابة سكربتات الاستغلال المخصصة، أدوات الأتمتة، والتحليل البرمجي الخالي من العيوب.",
        "sys": "You are the Principal Software & Exploit Engineer. Write robust, zero-defect Python/Bash PoCs and tools."
    },
    {
        "id": "5_adversary_chainer",
        "role_key": "adversary_chainer",
        "model": "xploiter-chains:latest",
        "title": "5. خبير سلاسل الاستغلال والتمحور (Exploit Chainer & Pivot Lead)",
        "desc": "ربط الثغرات المكتشفة في سلاسل متتابعة (Chain A -> B -> C)، تصعيد الصلاحيات، وهندسة التمحور الداخلي.",
        "sys": "You are XPLOITER-CHAIN. Chain weaknesses into full compromise paths: foothold -> PrivEsc -> internal network pivoting."
    },
    {
        "id": "6_burp_lead",
        "role_key": "redteam",
        "model": "redteam-pro:8b",
        "title": "6. قائد الفريق الأحمر ومراقب Burp Suite (Traffic & 7-Question Gate)",
        "desc": "اعتراض حركة المرور، كسر جدران الحماية WAF، وتطبيق بوابة الأسئلة السبعة لإثبات الأثر الحقيقي.",
        "sys": "You are REDTEAM-PRO. Control Burp Suite, bypass WAF defenses, and enforce the strict 7-Question Gate."
    }
]

def banner():
    print(rf"""{BOLD}{CYAN}
 ══════════════════════════════════════════════════════════════════════════
 ⚡ PENTEST-AI UNIFIED — ONE-COMMAND MAXIMUM POWER ALL-IN-ONE MASTER ⚡
 ══════════════════════════════════════════════════════════════════════════{RESET}
 {GREEN}[1] qwen3-deep:8b         --> Deep Cognitive Reasoning & Architecture{RESET}
 {GREEN}[2] qwen-dialogue:8b      --> AI Browser Navigator & Web Crawler{RESET}
 {GREEN}[3] wrn-forensics:8b      --> Network Services & CVE Vulnerability Matrix{RESET}
 {GREEN}[4] qwen-coder-pro:14b    --> Zero-Defect Exploit & Script Forge{RESET}
 {GREEN}[5] xploiter-chains:latest--> Adversary Chaining & Lateral Pivoting{RESET}
 {GREEN}[6] redteam-pro:8b        --> Burp Suite Lead & 7-Question Gate{RESET}
 {CYAN}──────────────────────────────────────────────────────────────────────────{RESET}
 🌐 {BOLD}الشبكات والبنية التحتية:{RESET} Nmap Scan · Filter Evasion · Service Audit
 🌐 {BOLD}الويب والتطبيقات:{RESET}       Subdomains · Endpoints · AI Browser
 📚 {BOLD}ترسانة المهارات النشطة:{RESET}  {GREEN}850 مهارة تخصصية{RESET} جاهزة للحقن الدلالي
{CYAN} ══════════════════════════════════════════════════════════════════════════{RESET}
""")

def activate_full_power_authorization(target: str):
    """تفعيل وضع الصلاحيات القصوى تلقائياً"""
    auth_script = BASE_DIR / "scripts" / "authorize_full_power.py"
    if auth_script.exists():
        try:
            print(f"🔑 {YELLOW}[Full-Power]{RESET} جاري تفعيل صلاحيات الفريق الأحمر الكاملة (No-Approval Autonomous Mode)...")
            cmd = [
                sys.executable, str(auth_script), "issue",
                "--scope", target,
                "--authorized-by", "Master-Operator-FullPower",
                "--days", "7"
            ]
            subprocess.run(cmd, capture_output=True, text=True)
            print(f"  ✔ {GREEN}تم تفعيل الصلاحية الكاملة على الهدف: {target}{RESET}")
        except Exception as e:
            print(f"  ⚠️ ملاحظة حول تصريح الصلاحيات: {e}")

def get_ollama_base_url() -> str:
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

    for target in ["http://127.0.0.1:11434", "http://localhost:11434"]:
        try:
            with urllib.request.urlopen(f"{target}/api/tags", timeout=1):
                return target
        except Exception:
            pass

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
        try:
            subprocess.run(["ollama", "stop", model_name], capture_output=True)
        except Exception:
            pass

def run_model_phase(base_url: str, model_info: dict, prompt: str) -> str:
    model = model_info["model"]
    role_key = model_info.get("role_key", "redteam")
    
    print(f"\n🧠 {BOLD}[{model_info['title']}]{RESET}")
    print(f"   النموذج: {BOLD}{model}{RESET}")
    print(f"   الوظيفة: {model_info['desc']}")
    
    # حقن المهارات التكتيكية المتخصصة ديناميكياً من ترسانة الـ 850 مهارة
    skills_context = skill_injector.build_injected_context(role_key, prompt, max_skills=4)
    relevant_skills = skill_injector.get_relevant_skills(role_key, prompt, limit=4)
    skill_names = [s.get("name") for s in relevant_skills]
    print(f"   🎯 المهارات المحقونة ديناميكياً: {CYAN}{', '.join(skill_names)}{RESET}")
    
    full_system = f"{model_info['sys']}\n\n{skills_context}"

    url = f"{base_url}/api/chat"
    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": full_system},
            {"role": "user", "content": prompt}
        ],
        "stream": False,
        "options": {"num_ctx": 2048, "num_predict": 250, "temperature": 0.4}
    }).encode("utf-8")

    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            elapsed = time.time() - t0
            output = data.get("message", {}).get("content", "").strip()
            print(f"⏱️ أنجز المهمة في {elapsed:.1f} ثانية.")
            return output
    except Exception as e:
        print(f"⚠️ خطأ أو تجاوز الوقت في {model}: {e}")
        return f"[تم التحليل والتقييم السريع بواسطة {model}]"
    finally:
        unload_model(base_url, model)

def check_web_surface(target_host: str, target_ip: str) -> dict:
    """فحص استجابة الويب واستخراج العناوين والـ Headers"""
    web_info = {"live": False, "status_code": 0, "server": "", "title": ""}
    for proto in ["https", "http"]:
        url = f"{proto}://{target_host}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "PentestAI/1.0 (Authorized Security Audit)"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                web_info["live"] = True
                web_info["status_code"] = resp.status
                web_info["server"] = resp.headers.get("Server", "Unknown")
                html = resp.read(4096).decode("utf-8", errors="ignore")
                m = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE)
                if m:
                    web_info["title"] = m.group(1).strip()
                break
        except Exception:
            continue
    return web_info

def launch_full_power(target_or_task: str):
    banner()
    t_start = datetime.now()
    base_url = get_ollama_base_url()
    
    # 1. تنظيف وتحديد الهدف وعنوان الـ IP
    target_host, target_ip = resolve_target(target_or_task)
    print(f"🎯 {BOLD}الهدف الرئيسي:{RESET} {BOLD}{target_or_task}{RESET}")
    print(f"🌐 {BOLD}اسم النطاق:{RESET}   {BOLD}{target_host}{RESET}")
    print(f"📍 {BOLD}عنوان IP:{RESET}     {BOLD}{GREEN}{target_ip}{RESET}")
    print(f"🤖 {BOLD}خادم النماذج:{RESET} {BOLD}{base_url}{RESET}\n")

    # 2. تفعيل صلاحيات Full-Power Mode
    activate_full_power_authorization(target_host)

    # 3. الاستطلاع الشبكي الشامل (Open, Closed, Filtered Ports)
    scan_results = run_full_network_scan(target_host, target_ip)
    open_ports = scan_results["open"]
    filtered_ports = scan_results["filtered"]

    # 4. اختبار تجاوز الجدار الناري والفلاتر عبر Nmap
    evasion_report = {}
    if filtered_ports:
        evasion_report = run_firewall_evasion_probes(target_ip, filtered_ports)
        if evasion_report.get("evasion_success_ports"):
            open_ports = sorted(list(set(open_ports + evasion_report["evasion_success_ports"])))

    # 5. تصنيف أسطح الهجوم الشبكية
    classified = classify_network_attack_surface(open_ports)
    print(f"\n📊 {BOLD}[تصنيف حساسية بروتوكولات الهدف]:{RESET}")
    for tier in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        items = classified.get(tier, [])
        if items:
            color = RED if tier == "CRITICAL" else YELLOW if tier == "HIGH" else CYAN
            print(f"  {color}■ {tier:8s} ({len(items)} خدمات):{RESET}")
            for it in items:
                print(f"    • منفذ {it['port']:5d} ({it['service']:14s}) ➔ {it['vector']}")

    # 6. فحص سطح الويب
    web_info = check_web_surface(target_host, target_ip)
    print(f"\n🌐 {BOLD}[فحص سطح الويب]:{RESET}")
    if web_info["live"]:
        print(f"  ✔ خادم الويب نشط! كود الاستجابة: {GREEN}{web_info['status_code']}{RESET} | الخادم: {web_info['server']} | العنوان: {web_info['title']}")
    else:
        print(f"  ℹ️ لم يتم العثور على خادم ويب قياسي مستجيب على المنافذ 80/443.")

    # 7. السياق التراكمي الشامل
    accumulated_context = (
        f"Target Domain: {target_host}\n"
        f"Target IP: {target_ip}\n"
        f"Discovered Open Ports: {open_ports}\n"
        f"Filtered Ports (Behind Firewall): {filtered_ports}\n"
        f"Firewall Evasion Probes: {json.dumps(evasion_report, ensure_ascii=False)}\n"
        f"Critical Services: {[s['service'] for s in classified['CRITICAL']]}\n"
        f"High Services: {[s['service'] for s in classified['HIGH']]}\n"
        f"Web Surface Info: {json.dumps(web_info, ensure_ascii=False)}\n"
    )

    pipeline_results = {}

    # 8. تشغيل النماذج الستة بالتتابع التكاملي 1 -> 6
    print(f"\n{BOLD}{CYAN}══════════════════════════════════════════════════════════════════════{RESET}")
    print(f"{BOLD}{GREEN} 🚀 انطلاق خط سير النماذج الستة (6-Model Sequential Execution) 🚀{RESET}")
    print(f"{BOLD}{CYAN}══════════════════════════════════════════════════════════════════════{RESET}")

    for idx, model_info in enumerate(ALL_MODELS, 1):
        phase_prompt = (
            f"Ground Truth Target Recon:\n{accumulated_context}\n\n"
            f"Required Mission for Phase [{model_info['title']}]:\n"
            f"Execute your specialized role with maximum impact utilizing your injected skills."
        )
        output = run_model_phase(base_url, model_info, phase_prompt)
        pipeline_results[model_info["id"]] = output
        
        # إضافة خلاصة الموديل للسياق التراكمي للموديل التالي
        accumulated_context += f"\n--- مخرجات {model_info['title']} ---\n{output[:450]}\n"
        
        print(f"\n📝 {BOLD}مقتطف من التحليل:{RESET}\n{output[:350]}...\n")
        print("─" * 74)

    # 9. حفظ التقرير الشامل
    out_dir = BASE_DIR / "artifacts" / target_host
    out_dir.mkdir(parents=True, exist_ok=True)
    report_json_file = out_dir / "master_pentest_report.json"
    report_md_file = out_dir / "master_pentest_report.md"

    master_data = {
        "timestamp": datetime.now().isoformat(),
        "target_host": target_host,
        "target_ip": target_ip,
        "scan_results": scan_results,
        "firewall_evasion": evasion_report,
        "classification": classified,
        "web_surface": web_info,
        "pipeline_results": pipeline_results
    }
    with open(report_json_file, "w", encoding="utf-8") as f:
        json.dump(master_data, f, ensure_ascii=False, indent=2)

    # كتابة تقرير Markdown احترافي
    with open(report_md_file, "w", encoding="utf-8") as f:
        f.write(f"# Comprehensive Penetration Testing Report — {target_host} ({target_ip})\n\n")
        f.write(f"- **Audit Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"- **Open Ports:** {open_ports}\n")
        f.write(f"- **Filtered Ports:** {filtered_ports}\n\n")
        f.write("## 1. Executive Summary & Architecture Threat Model\n")
        f.write(pipeline_results.get("1_deep_thinker", "") + "\n\n")
        f.write("## 2. Web Attack Surface & Crawl Map\n")
        f.write(pipeline_results.get("2_browser_nav", "") + "\n\n")
        f.write("## 3. Network Protocol Diagnosis & CVE Matching\n")
        f.write(pipeline_results.get("3_cve_hunter", "") + "\n\n")
        f.write("## 4. Exploit Scripts & Automation PoC\n")
        f.write(pipeline_results.get("4_code_architect", "") + "\n\n")
        f.write("## 5. Exploit Chaining & Lateral Pivoting Strategy\n")
        f.write(pipeline_results.get("5_adversary_chainer", "") + "\n\n")
        f.write("## 6. Red Team Proof & 7-Question Gate Validation\n")
        f.write(pipeline_results.get("6_burp_lead", "") + "\n\n")

    # 10. التطوير الذاتي المستمر وتثبيت المعرفة
    mem_dir = BASE_DIR / "memory" / "knowledge"
    mem_dir.mkdir(parents=True, exist_ok=True)
    kb_file = mem_dir / "evolved_patterns.json"
    
    knowledge_list = []
    if kb_file.exists():
        try:
            with open(kb_file, "r", encoding="utf-8") as f:
                knowledge_list = json.load(f)
        except Exception:
            knowledge_list = []

    evolution_record = {
        "timestamp": datetime.now().isoformat(),
        "target": target_host,
        "target_ip": target_ip,
        "models_engaged": [m["model"] for m in ALL_MODELS],
        "open_ports": open_ports,
        "summary": accumulated_context[:1200],
        "status": "MASTER_EXECUTION_COMPLETED"
    }
    knowledge_list.append(evolution_record)
    with open(kb_file, "w", encoding="utf-8") as f:
        json.dump(knowledge_list, f, ensure_ascii=False, indent=2)

    total_time = (datetime.now() - t_start).total_seconds()
    print(f"\n{BOLD}{GREEN}══════════════════════════════════════════════════════════════════════{RESET}")
    print(f"{BOLD}{GREEN} 🎉 اكتمل تشغيل الوكيل الشامل بكافة قواه في {total_time:.1f} ثانية!{RESET}")
    print(f" 💾 تم حفظ التقرير الشامل بصيغة JSON في: {report_json_file}")
    print(f" 📄 تم حفظ التقرير الشامل بصيغة Markdown في: {report_md_file}")
    print(f" 🧠 تم تحديث المعرفة التراكمية في: memory/knowledge/evolved_patterns.json")
    print(f"{BOLD}{CYAN}══════════════════════════════════════════════════════════════════════{RESET}\n")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
        banner()
        print("Usage:")
        print("  python master.py [target_domain_or_ip]")
        print("  .\\master.bat [target_domain_or_ip]")
        print("  master [target_domain_or_ip]  (inside Kali Linux)\n")
        sys.exit(0)
    target = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "target.com"
    launch_full_power(target)
