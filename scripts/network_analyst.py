#!/usr/bin/env python3
"""
PENTEST-AI — COGNITIVE NETWORK AUDITOR & NMAP EVASION ENGINE
============================================================
المحرك الذكي لفحص شبكات الأهداف والبنية التحتية، يدعم:
1. قبول أي نطاق (Domain)، موقع ويب (URL)، أو عنوان IP.
2. الكشف التلقائي عن الـ IP عبر DNS Resolution.
3. فحص البورتات المفتوحة (Open)، المقفولة (Closed)، والمفلترة (Filtered).
4. الفحص التلقائي لتقنيات تجاوز الجدار الناري واختبار الفلاتر (Nmap Firewall Evasion Probes).
5. التشخيص الذكي للبروتوكولات وبناء سلاسل التمحور الداخلي (Pivoting).
"""

import sys
import os
import json
import socket
import subprocess
import re
import urllib.request
import time
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from core.skill_context_injector import skill_injector

# الألوان لعرض التقرير باحترافية
GREEN = "\033[1;32m"
CYAN = "\033[1;36m"
YELLOW = "\033[1;33m"
RED = "\033[1;31m"
BOLD = "\033[1m"
RESET = "\033[0m"

# مصفوفة البروتوكولات وتصنيفها
KNOWN_PORTS = {
    21:   {"service": "FTP",        "tier": "HIGH",     "vector": "Anonymous Bind, vsftpd backdoor, cleartext credentials"},
    22:   {"service": "SSH",        "tier": "MEDIUM",   "vector": "Weak key exchange, brute-force, OpenSSH CVEs"},
    23:   {"service": "Telnet",     "tier": "HIGH",     "vector": "Unencrypted communication, credential sniffing, default creds"},
    25:   {"service": "SMTP",       "tier": "MEDIUM",   "vector": "VRFY/EXPN user enumeration, open relay mail transit"},
    53:   {"service": "DNS",        "tier": "LOW",      "vector": "AXFR zone transfer, cache poisoning, amplification"},
    80:   {"service": "HTTP",       "tier": "HIGH",     "vector": "Web apps, CMS flaws, unauthenticated API endpoints"},
    111:  {"service": "RPC/Rpcbind","tier": "HIGH",     "vector": "RPC dump, service mapping, NFS export discovery"},
    139:  {"service": "NetBIOS-SSN","tier": "CRITICAL", "vector": "SMBv1 exposure, null session enumeration, SambaCry"},
    445:  {"service": "SMB/MS-DS",  "tier": "CRITICAL", "vector": "MS17-010 EternalBlue, anonymous shares, signing disabled"},
    512:  {"service": "rexec",      "tier": "CRITICAL", "vector": "Legacy remote exec, .rhosts authentication bypass"},
    513:  {"service": "rlogin",     "tier": "CRITICAL", "vector": "Cleartext rlogin trust relationships, root login"},
    514:  {"service": "rsh",        "tier": "CRITICAL", "vector": "Remote shell trust abuse without password"},
    1099: {"service": "Java RMI",   "tier": "CRITICAL", "vector": "RMI registry object deserialization / BaRMIe"},
    1524: {"service": "Ingreslock", "tier": "CRITICAL", "vector": "Known root bind shell / backdoor listener"},
    2049: {"service": "NFS",        "tier": "CRITICAL", "vector": "Unrestricted export shares, no_root_squash mount"},
    2121: {"service": "ProFTPD",    "tier": "HIGH",     "vector": "ProFTPD 1.3.x mod_copy command execution"},
    3306: {"service": "MySQL",      "tier": "HIGH",     "vector": "Remote DB access, root blank password, UDF injection"},
    5432: {"service": "PostgreSQL", "tier": "HIGH",     "vector": "Default postgres credentials, copy to program command execution"},
    5900: {"service": "VNC",        "tier": "CRITICAL", "vector": "VNC null authentication, default 6-char password"},
    6667: {"service": "UnrealIRCd", "tier": "CRITICAL", "vector": "UnrealIRCd 3.2.8.1 backdoor command execution"},
    8009: {"service": "Apache AJP", "tier": "HIGH",     "vector": "Ghostcat (CVE-2020-1938) arbitrary file read / inclusion"},
    8180: {"service": "Tomcat HTTP","tier": "HIGH",     "vector": "Tomcat manager/html default credential deployment"}
}


def resolve_target(raw_target: str) -> tuple:
    """تنظيف الهدف واستخراج النطاق وعنوان IP المقابل تلقائياً"""
    clean = re.sub(r"^https?://", "", raw_target).split("/")[0].split(":")[0].strip()
    try:
        resolved_ip = socket.gethostbyname(clean)
    except Exception:
        resolved_ip = clean
    return clean, resolved_ip


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
        pass


def run_full_network_scan(target_host: str, target_ip: str) -> dict:
    """
    فحص شبكي متقدم يشمل:
    - المنافذ المفتوحة (Open)
    - المنافذ المفلترة (Filtered - خلف جدار ناري)
    - المنافذ المغلقة (Closed)
    """
    print(f"\n🔍 {CYAN}[الاستطلاع الشبكي الشامل]{RESET} جاري فحص الهدف: {BOLD}{target_host} ({target_ip}){RESET}...")
    
    results = {
        "open": [],
        "filtered": [],
        "closed_count": 0,
        "scan_tool": "nmap"
    }

    # 1. فحص Nmap السريع والذكي مع تعطيل ping (-Pn) لعدم الوقوع في حجب ICMP
    nmap_target = target_ip if target_ip else target_host
    try:
        cmd = ["nmap", "-sS", "-Pn", "-T4", "--top-ports", "100", "-oG", "-", nmap_target]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
        
        for line in res.stdout.splitlines():
            if "Ports:" in line:
                # Ports: 21/open/tcp//ftp///, 22/open/tcp//ssh///, 80/filtered/tcp//http///
                port_entries = line.split("Ports:")[1].split(",")
                for entry in port_entries:
                    parts = entry.strip().split("/")
                    if len(parts) >= 2:
                        p_num = int(parts[0])
                        p_state = parts[1].lower()
                        if p_state == "open":
                            results["open"].append(p_num)
                        elif p_state == "filtered":
                            results["filtered"].append(p_num)
                        elif p_state == "closed":
                            results["closed_count"] += 1
    except Exception:
        results["scan_tool"] = "naabu/socket_fallback"

    # 2. محاولة Naabu إذا فشل Nmap في جمع المنافذ المفتوحة
    if not results["open"]:
        try:
            res = subprocess.run(["naabu", "-host", target_host, "-top-ports", "100", "-silent"],
                                 capture_output=True, text=True, timeout=15)
            for line in res.stdout.splitlines():
                line = line.strip()
                if ":" in line:
                    p_str = line.split(":")[-1]
                    if p_str.isdigit():
                        results["open"].append(int(p_str))
        except Exception:
            pass

    # 3. Fallback عبر Direct Sockets إذا لم تتوفر الأدوات
    if not results["open"] and not results["filtered"]:
        print(f"  ℹ️ جاري الفحص المباشر عبر مقابس TCP Socket...")
        common_test = [21, 22, 23, 25, 53, 80, 111, 139, 443, 445, 512, 513, 514, 1099, 1524, 2049, 3306, 5432, 5900, 6667, 8009, 8080, 8443]
        for p in common_test:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.4)
            code = s.connect_ex((target_ip, p))
            if code == 0:
                results["open"].append(p)
            elif code in (10035, 10060, 11):  # Timeout / Resource temporarily unavailable -> Filtered
                results["filtered"].append(p)
            else:
                results["closed_count"] += 1
            s.close()

    results["open"] = sorted(list(set(results["open"])))
    results["filtered"] = sorted(list(set(results["filtered"])))

    # طباعة ملخص المنافذ
    print(f"  ✔ {GREEN}المنافذ المفتوحة (Open):{RESET} {results['open'] if results['open'] else '(لا توجد)'}")
    if results["filtered"]:
        print(f"  🛡️ {YELLOW}المنافذ المفلترة (Filtered - خلف جدار ناري):{RESET} {results['filtered']}")
    print(f"  🔒 المنافذ المغلقة (Closed): {results['closed_count']} منفذ")

    return results


def run_firewall_evasion_probes(target_ip: str, filtered_ports: list) -> dict:
    """
    اختبار تقنيات تجاوز وتفادي الفلاتر وجدران الحماية (Nmap Firewall Evasion Probes)
    عند اكتشاف بورتات بحالة 'filtered'
    """
    if not filtered_ports:
        return {}

    test_ports_str = ",".join(str(p) for p in filtered_ports[:10])
    print(f"\n🛡️ {BOLD}{YELLOW}[اختبارات تجاوز الفلتر والجدار الناري عبر Nmap على البورتات: {test_ports_str}]{RESET}...")
    
    evasion_report = {
        "ports_tested": filtered_ports[:10],
        "ack_scan_state": "Not Run",
        "dns_source_bypass": "Not Run",
        "fragmentation_bypass": "Not Run",
        "evasion_success_ports": []
    }

    # 1. فحص TCP ACK (-sA) لكشف نوع الجدار الناري (Stateful vs Stateless Packet Filter)
    try:
        cmd_ack = ["nmap", "-sA", "-Pn", "-p", test_ports_str, "-oG", "-", target_ip]
        res_ack = subprocess.run(cmd_ack, capture_output=True, text=True, timeout=20)
        if "unfiltered" in res_ack.stdout.lower():
            evasion_report["ack_scan_state"] = "Stateless Packet Filter Detected (Unfiltered ACK responses received!)"
        else:
            evasion_report["ack_scan_state"] = "Stateful Firewall Detected (Filtered responses to ACK)"
    except Exception as e:
        evasion_report["ack_scan_state"] = f"Probe error: {e}"

    # 2. انتحال منفذ المصدر DNS Port 53 (--source-port 53)
    try:
        cmd_dns = ["nmap", "-sS", "-Pn", "--source-port", "53", "-p", test_ports_str, "-oG", "-", target_ip]
        res_dns = subprocess.run(cmd_dns, capture_output=True, text=True, timeout=20)
        opened = [int(m.group(1)) for m in re.finditer(r"(\d+)/open/tcp", res_dns.stdout)]
        if opened:
            evasion_report["dns_source_bypass"] = f"SUCCESS: Ports {opened} opened using source-port 53 bypass!"
            evasion_report["evasion_success_ports"].extend(opened)
        else:
            evasion_report["dns_source_bypass"] = "Blocked (Source-port 53 did not change filter state)"
    except Exception as e:
        evasion_report["dns_source_bypass"] = f"Probe error: {e}"

    # 3. تجزئة الحزم عبر Packet Fragmentation (-f)
    try:
        cmd_frag = ["nmap", "-sS", "-Pn", "-f", "-p", test_ports_str, "-oG", "-", target_ip]
        res_frag = subprocess.run(cmd_frag, capture_output=True, text=True, timeout=20)
        opened_frag = [int(m.group(1)) for m in re.finditer(r"(\d+)/open/tcp", res_frag.stdout)]
        if opened_frag:
            evasion_report["fragmentation_bypass"] = f"SUCCESS: Ports {opened_frag} opened using 8-byte packet fragmentation (-f)!"
            evasion_report["evasion_success_ports"].extend(opened_frag)
        else:
            evasion_report["fragmentation_bypass"] = "Blocked (Packet inspection reassembles fragments)"
    except Exception as e:
        evasion_report["fragmentation_bypass"] = f"Probe error: {e}"

    evasion_report["evasion_success_ports"] = sorted(list(set(evasion_report["evasion_success_ports"])))
    print(f"  • تشخيص الجدار الناري: {CYAN}{evasion_report['ack_scan_state']}{RESET}")
    print(f"  • تجربة DNS Port 53:   {CYAN}{evasion_report['dns_source_bypass']}{RESET}")
    print(f"  • تجربة Fragmentation: {CYAN}{evasion_report['fragmentation_bypass']}{RESET}")
    
    return evasion_report


def classify_network_attack_surface(open_ports: list) -> dict:
    """تصنيف أسطح الهجوم الشبكية وترتيبها حسب الحساسية"""
    classified = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}

    for p in open_ports:
        info = KNOWN_PORTS.get(p, {"service": f"Port-{p}", "tier": "MEDIUM", "vector": "Unclassified network protocol"})
        classified[info["tier"]].append({
            "port": p,
            "service": info["service"],
            "vector": info["vector"]
        })

    return classified


def consult_network_model(base_url: str, model: str, role_key: str, prompt: str, title: str) -> str:
    """استشارة النموذج المحلي مع حقن مهارات الشبكات التخصصية"""
    print(f"\n🧠 {BOLD}[{title}]{RESET}")
    print(f"   النموذج: {BOLD}{model}{RESET}")

    skills_context = skill_injector.build_injected_context(role_key, prompt, max_skills=4)
    relevant_skills = skill_injector.get_relevant_skills(role_key, prompt, limit=4)
    skill_names = [s.get("name") for s in relevant_skills]
    print(f"   🎯 مهارات الشبكات المحقونة: {CYAN}{', '.join(skill_names)}{RESET}")

    url = f"{base_url}/api/chat"
    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": f"You are an Elite Network Penetration Testing & Firewall Evasion Specialist.\n\n{skills_context}"},
            {"role": "user", "content": prompt}
        ],
        "stream": False,
        "options": {"num_ctx": 2048, "num_predict": 350, "temperature": 0.4}
    }).encode("utf-8")

    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            elapsed = time.time() - t0
            output = data.get("message", {}).get("content", "").strip()
            print(f"⏱️ أنجز التحليل في {elapsed:.1f} ثانية.")
            return output
    except Exception as e:
        print(f"⚠️ خطأ أثناء استدعاء {model}: {e}")
        return f"[تم التحليل السريع للشبكة بواسطة {model}]"
    finally:
        unload_model(base_url, model)


def main():
    raw_target = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.14"
    target_host, target_ip = resolve_target(raw_target)
    base_url = get_ollama_base_url()

    print(f"\n{BOLD}{CYAN}══════════════════════════════════════════════════════════════════════{RESET}")
    print(f"{BOLD}{GREEN} 🌐 PENTEST-AI — COGNITIVE NETWORK AUDITOR & NMAP EVASION ENGINE 🌐{RESET}")
    print(f"{BOLD}{CYAN}══════════════════════════════════════════════════════════════════════{RESET}")
    print(f"  • الهدف المدخل: {BOLD}{raw_target}{RESET}")
    print(f"  • اسم النطاق:   {BOLD}{target_host}{RESET}")
    print(f"  • عنوان IP:     {BOLD}{GREEN}{target_ip}{RESET}")
    print(f"  • خادم الذكاء:  {BOLD}{base_url}{RESET}")

    # 1. الاستطلاع الشامل للمنافذ (Open, Filtered, Closed)
    scan_results = run_full_network_scan(target_host, target_ip)
    open_ports = scan_results["open"]
    filtered_ports = scan_results["filtered"]

    if not open_ports and not filtered_ports:
        print(f"{RED}❌ لم يتم العثور على أي منافذ استجابة على {target_host} ({target_ip}). تأكد من عمل الهدف والشبكة.{RESET}")
        return

    # 2. اختبار تجاوز الجدار الناري والفلاتر إذا وجدت منافذ مفلترة
    evasion_report = {}
    if filtered_ports:
        evasion_report = run_firewall_evasion_probes(target_ip, filtered_ports)
        if evasion_report.get("evasion_success_ports"):
            open_ports = sorted(list(set(open_ports + evasion_report["evasion_success_ports"])))

    # 3. تصنيف أسطح الهجوم للمنافذ المفتوحة
    classified = classify_network_attack_surface(open_ports)
    print(f"\n{BOLD}📊 [تصنيف حساسية بروتوكولات الشبكة]:{RESET}")
    for tier in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        items = classified.get(tier, [])
        if items:
            color = RED if tier == "CRITICAL" else YELLOW if tier == "HIGH" else CYAN
            print(f"  {color}■ {tier:8s} ({len(items)} خدمات):{RESET}")
            for it in items:
                print(f"    • منفذ {it['port']:5d} ({it['service']:14s}) ➔ {it['vector']}")

    # 4. تشخيص الخدمات بواسطة wrn-forensics:8b
    wrn_prompt = (
        f"Target Domain: {target_host}\n"
        f"Target IP: {target_ip}\n"
        f"Open Ports: {open_ports}\n"
        f"Filtered Ports (Behind Firewall/Filter): {filtered_ports}\n"
        f"Firewall Probes Info: {json.dumps(evasion_report, ensure_ascii=False)}\n"
        f"Critical Services: {[s['service'] for s in classified['CRITICAL']]}\n"
        f"High Services: {[s['service'] for s in classified['HIGH']]}\n\n"
        f"Using your deep network protocol matrix and injected network skills (network-services-pentest, metasploit-automation, linux-privesc-arsenal):\n"
        f"1. Select the TOP 3 most vulnerable network services to verify first.\n"
        f"2. Provide exact Kali verification commands (e.g. netexec, nmap --script, rpcinfo, smbclient, showmount -e, vncviewer) for each service.\n"
        f"3. If filtered ports exist, provide advanced Nmap evasion commands (e.g. -f, --mtu, --source-port, -sA, -D) to probe them."
    )
    wrn_res = consult_network_model(
        base_url,
        "wrn-forensics:8b",
        "cve_hunter",
        wrn_prompt,
        "المرحلة 1: تشخيص الخدمات وثغرات البروتوكولات (wrn-forensics:8b)"
    )
    print(f"\n{BOLD}📋 تقرير تشخيص البروتوكولات:{RESET}")
    print("─" * 70)
    print(wrn_res)
    print("─" * 70)

    # 5. بناء سلاسل الاستغلال والتحرك الجانبي بواسطة xploiter-chains:latest
    xploiter_prompt = (
        f"Target Domain: {target_host} ({target_ip})\n"
        f"Identified Vulnerability Surface:\n{wrn_res[:600]}\n"
        f"Filtered Ports / Firewall: {filtered_ports}\n\n"
        f"Apply your Network Pivot & Lateral Movement playbook (infrastructure-pivoting, metasploit-automation, linux-privesc-arsenal):\n"
        f"1. Propose an end-to-end compromise chain: Initial Network Foothold -> PrivEsc (GTFOBins/sudo/cron) -> Lateral Movement.\n"
        f"2. How would an attacker pivot from this host into other internal subnets (e.g. SOCKS5, SSH -D, Chisel, Ligolo-ng)?\n"
        f"3. State remediation advice to harden these network services and firewall filtering."
    )
    xploiter_res = consult_network_model(
        base_url,
        "xploiter-chains:latest",
        "adversary_chainer",
        xploiter_prompt,
        "المرحلة 2: بناء سلاسل التحرك الجانبي والـ Pivot (xploiter-chains:latest)"
    )
    print(f"\n{BOLD}⛓️ مسار وسلاسل التحرك الجانبي المقترحة:{RESET}")
    print("─" * 70)
    print(xploiter_res)
    print("─" * 70)

    # 6. حفظ التقرير في مجلد الـ artifacts
    out_dir = BASE_DIR / "artifacts" / target_host
    out_dir.mkdir(parents=True, exist_ok=True)
    report_file = out_dir / "network_audit_report.json"
    audit_data = {
        "timestamp": datetime.now().isoformat(),
        "target_host": target_host,
        "target_ip": target_ip,
        "open_ports": open_ports,
        "filtered_ports": filtered_ports,
        "closed_count": scan_results["closed_count"],
        "firewall_evasion": evasion_report,
        "classification": classified,
        "wrn_analysis": wrn_res,
        "pivot_chain": xploiter_res
    }
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(audit_data, f, ensure_ascii=False, indent=2)

    print(f"\n{BOLD}{GREEN}══════════════════════════════════════════════════════════════════════{RESET}")
    print(f"{BOLD}{GREEN} 🎉 اكتمل التدقيق الشبكي الشامل بنجاح! تم حفظ التقرير في:{RESET}")
    print(f"    {report_file}")
    print(f"{BOLD}{CYAN}══════════════════════════════════════════════════════════════════════{RESET}\n")


if __name__ == "__main__":
    main()
