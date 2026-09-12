"""
Bug Bounty & Recon Methodology Engine
"Full Spectrum Methodology: 7-Step Bug Bounty Playbook"

يحتوي على خلاصة وتطبيق أفضل ممارسات الـ Bug Bounty العالمية:
1. Subdomain Discovery (Passive + Active + VHost Fuzzing + CT Logs)
2. Subdomain Takeover & Alive Filtering (Subzy, Httpx, Anew)
3. Infrastructure & Origin IP Discovery (ASN, CIDR, Reverse IP, Censys, Shodan)
4. URL & Endpoint Discovery Pipeline (Waybackurls, Katana, GAU, GoSpider, ParamSpider)
5. JS Mining & Secret Discovery (Subjs, Mantra, Regexes, Token Leaks)
6. Parameter Mining & Sensitive File Hunting (Arjun GET/POST, 403 Bypass, Sensitive Extensions, WP Exposures)
7. Targeted Exploitation & Probing (Nuclei Exposures, SQLMap with auto-post data & 403 ignore, Smuggler, PoC)
"""
import asyncio
import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set
from urllib.parse import urlparse, urljoin
import httpx

log = logging.getLogger("playbooks.bug_bounty")

# ── 1. Sensitive Extensions Regex Pattern ─────────────────────────────────────
SENSITIVE_EXTENSIONS_PATTERN = re.compile(
    r"(?:\.|\b)(xls|xlsx|csv|sql|db|bak|backup|old|tar\.gz|tgz|zip|7z|rar|pdf|doc|docx|"
    r"pptx|txt|log|ini|conf|config|env|json|xml|yml|yaml|pem|key|crt|ssh|git|"
    r"htaccess|htpasswd|php|swp|swo|dump|dmp|ds_store|"
    r"env\.(?:local|prod|dev|test|example|sample|development|production|staging|backup|old|save|tmp|temp|log|json|yaml|xml|conf|cfg|settings|secret|keys|credentials|tokens|api|database|mysql|postgres|redis|mongo|aws|s3|gcp|azure|docker|k8s|vault)|"
    r"vscode|idea|gitignore|gitconfig|gitmodules|gitattributes|gitkeep|gitlab-ci\.yml|"
    r"travis\.yml|circleci|dockerignore|dockerfile|docker-compose\.yml|npmrc|yarnrc|"
    r"bowerrc|eslintrc|eslintignore|prettierrc|prettierignore|stylelintrc|stylelintignore|"
    r"htgroup|htusers|htdigest|htdbm|htpasswds|"
    r"htaccess\.(?:bak|old|backup|save|tmp|temp|log|json|yaml|xml|conf|cfg|settings|secret))(?=$|[/?#&])",
    re.IGNORECASE
)

# ── 2. 403 Bypass Headers List ────────────────────────────────────────────────
BYPASS_403_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-Host": "127.0.0.1"},
    {"X-Host": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Forwarded-Server": "127.0.0.1"},
    {"X-HTTP-Method-Override": "GET"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
]

# ── 3. WordPress Specific Exposure Endpoints ─────────────────────────────────
WORDPRESS_EXPOSURE_PATHS = [
    "/wp-json/wp/v2/users",
    "/wp-json/?rest_route=/wp/v2/users/",
    "/index.php?rest_route=/wp-json/wp/v2/users",
    "/index.php?rest_route=/wp/v2/users",
    "/author-sitemap.xml",
    "/wp-content/debug.log",
    "/wp-login.php?action=register",
    "/wp-content/uploads/",
    "/xmlrpc.php",
]

# ── 4. Google & GitHub Dork Templates ─────────────────────────────────────────
GOOGLE_DORK_TEMPLATES = [
    'site:*.{domain} intext:"docs.google.com/spreadsheets"',
    'site:docs.google.com/spreadsheets "{domain}"',
    'site:docs.google.com/spreadsheets "password" "{domain}"',
    'site:docs.google.com/spreadsheets "@{domain}"',
    'site:{domain} ext:sql | ext:db | ext:env | ext:log | ext:bak',
    'site:{domain} inurl:login | inurl:admin | inurl:dashboard',
    'site:{domain} inurl:wp-content | inurl:wp-includes',
    'site:{domain} "index of /"',
]

# ── 5. Secret Hunting Regexes ────────────────────────────────────────────────
SECRET_REGEX_PATTERNS = {
    "generic_api_key": re.compile(r"(?i)(?:api[_-]?key|access[_-]?token|secret[_-]?key)[\s:=]+['\"]([a-zA-Z0-9_\-]{16,64})['\"]"),
    "aws_access_key": re.compile(r"\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b"),
    "jwt_token": re.compile(r"ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"),
    "slack_token": re.compile(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*"),
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z\-_]{30,45}\b"),
    "firebase_url": re.compile(r"https://[a-zA-Z0-9_-]+\.firebaseio\.com"),
}


class BugBountyMethodology:
    """
    محرك منهجية البق بونتي المتكاملة
    ينفّذ ويوفر الاستراتيجيات والأدلة والـ Playbooks لجميع مراحل الفحص
    """

    def __init__(self, tool_manager=None, resource_manager=None):
        self.tm = tool_manager
        self.rm = resource_manager

    # ── Step 1: Passive & CT Subdomain Extraction ────────────────────────────

    async def fetch_crtsh_subdomains(self, domain: str) -> List[str]:
        """استخراج النطاقات الفرعية عبر Certificate Transparency (crt.sh)"""
        clean_domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
        subdomains: Set[str] = set()
        try:
            url = f"https://crt.sh/?q=%25.{clean_domain}&output=json"
            async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    for entry in data:
                        name_val = entry.get("name_value", "")
                        for line in name_val.splitlines():
                            line = line.strip().lstrip("*.")
                            if clean_domain in line and re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', line):
                                subdomains.add(line)
        except Exception as e:
            log.debug(f"crt.sh fetch error for {clean_domain}: {e}")
        return sorted(list(subdomains))

    # ── Step 2: Sensitive Files and Extension Filtering ───────────────────────

    def filter_sensitive_urls(self, urls: List[str]) -> List[str]:
        """فلترة الروابط لاكتشاف الملفات الحساسة والتسريبات والـ Backups"""
        sensitive = []
        for u in urls:
            if SENSITIVE_EXTENSIONS_PATTERN.search(u):
                sensitive.append(u)
        return list(dict.fromkeys(sensitive))

    # ── Step 3: JS Secrets and API Keys Extractor ────────────────────────────

    def extract_secrets_from_js(self, js_content: str, source_url: str = "") -> List[Dict[str, Any]]:
        """استخراج المفاتيح والأسرار والرموز من ملفات الجافاسكريبت عبر الـ Regex"""
        findings = []
        for secret_type, pattern in SECRET_REGEX_PATTERNS.items():
            for match in pattern.finditer(js_content):
                val = match.group(0)
                start = max(0, match.start() - 60)
                end = min(len(js_content), match.end() + 60)
                snippet = js_content[start:end].replace("\n", " ").strip()
                findings.append({
                    "type": secret_type,
                    "matched_value": val[:40] + "..." if len(val) > 40 else val,
                    "context": snippet,
                    "source": source_url,
                    "severity": "High" if "key" in secret_type or "token" in secret_type else "Medium"
                })
        return findings

    # ── Step 4: 403 Bypass Testing Logic ─────────────────────────────────────

    async def test_403_bypass(self, target_url: str) -> List[Dict[str, Any]]:
        """محاولة تجاوز صفحات 403 Forbidden باستخدام هيدرز التجاوز الشهيرة"""
        bypasses = []
        try:
            async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
                # Base check
                base_resp = await client.get(target_url)
                if base_resp.status_code != 403:
                    return []

                # Test headers
                for hdr in BYPASS_403_HEADERS:
                    resp = await client.get(target_url, headers=hdr)
                    if resp.status_code in (200, 204, 301, 302, 307):
                        bypasses.append({
                            "url": target_url,
                            "successful_header": hdr,
                            "original_status": 403,
                            "bypassed_status": resp.status_code,
                            "content_length": len(resp.content),
                            "severity": "High",
                            "title": f"403 Forbidden Bypass confirmed via {list(hdr.keys())[0]}"
                        })
        except Exception as e:
            log.debug(f"403 bypass error on {target_url}: {e}")
        return bypasses

    # ── Step 5: WordPress Exposure Checks ────────────────────────────────────

    async def check_wordpress_exposures(self, base_url: str) -> List[Dict[str, Any]]:
        """فحص نقاط الـ Exposure الخاصة بـ WordPress (Users, Debug logs, Uploads)"""
        exposures = []
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        try:
            async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
                for path in WORDPRESS_EXPOSURE_PATHS:
                    target = urljoin(origin, path)
                    try:
                        resp = await client.get(target)
                        if resp.status_code == 200:
                            # Verify valid content
                            if path.endswith("users") and ("slug" in resp.text or "name" in resp.text):
                                exposures.append({
                                    "type": "wp_users_exposure",
                                    "url": target,
                                    "severity": "Medium",
                                    "title": "WordPress User Enumeration Endpoint Exposed",
                                    "evidence": resp.text[:300]
                                })
                            elif "debug.log" in path and len(resp.content) > 10:
                                exposures.append({
                                    "type": "wp_debug_log_leak",
                                    "url": target,
                                    "severity": "High",
                                    "title": "WordPress debug.log Exposed (Sensitive Data Leak)",
                                    "evidence": resp.text[:300]
                                })
                            elif resp.status_code == 200 and len(resp.content) > 20:
                                exposures.append({
                                    "type": "wp_exposed_path",
                                    "url": target,
                                    "severity": "Low",
                                    "title": f"Exposed WordPress Path: {path}",
                                    "evidence": f"Status 200 OK ({len(resp.content)} bytes)"
                                })
                    except Exception:
                        pass
        except Exception as e:
            log.debug(f"WP exposure check error on {origin}: {e}")
        return exposures

    # ── Step 6: Google Dorks Builder ─────────────────────────────────────────

    def generate_dorks(self, domain: str) -> List[str]:
        """توليد Google Dorks مخصصة للهدف للبحث عن Google Sheets والـ Secrets"""
        clean = domain.replace("https://", "").replace("http://", "").split("/")[0]
        return [t.format(domain=clean) for t in GOOGLE_DORK_TEMPLATES]

    # ── Step 7: Methodologies & Knowledge Registration ───────────────────────

    def register_methodology_in_kb(self, kb) -> int:
        """تسجيل المنهجية الكاملة كتقنيات وسلاسل هجومية في قاعدة المعرفة"""
        registered = 0
        playbook_techniques = [
            {
                "name": "Subdomain Takeover Enumeration",
                "category": "subdomain_takeover",
                "description": "Check discovered subdomains for dangling CNAME pointers (GitHub Pages, S3, Heroku, Azure) using subzy/dig",
                "tools": ["subzy", "dig", "subfinder", "anew"],
                "steps": [
                    "1. subfinder -d target.com -all -recursive -o subs.txt",
                    "2. cat subs.txt | anew >> unique_subs.txt",
                    "3. subzy run --targets unique_subs.txt --vuln --hide_fails"
                ]
            },
            {
                "name": "403 Forbidden Access Bypass",
                "category": "access_control_bypass",
                "description": "Bypass 403 Forbidden pages using custom header injection (X-Forwarded-For, X-Original-URL, X-Rewrite-URL)",
                "tools": ["ffuf", "dontgo403", "httpx"],
                "steps": [
                    "1. Identify 403 responses via httpx -mc 403",
                    "2. ffuf -u https://target.com/admin -w 403-headers.txt -H 'FUZZ' -mc 200,302",
                    "3. ffuf -u https://target.com/FUZZ -w wordlist.txt -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Original-URL: /FUZZ'"
                ]
            },
            {
                "name": "Sensitive File & Backup Leak Hunting",
                "category": "sensitive_data_exposure",
                "description": "Crawl archive URLs and fuzz directories for sensitive extensions (.env, .sql, .bak, .git, .dump, .json)",
                "tools": ["waybackurls", "gau", "katana", "dirsearch", "anew"],
                "steps": [
                    "1. cat alive_subs.txt | waybackurls >> allurls.txt",
                    "2. katana -list alive_subs.txt -o katana.txt",
                    r"3. grep -E '\.(env|sql|bak|log|conf|key|pem|git)' allurls.txt",
                    "4. dirsearch -u https://target.com -e conf,config,bak,backup,sql,db,env -i 200"
                ]
            },
            {
                "name": "JavaScript Secret & API Key Mining",
                "category": "secret_leakage",
                "description": "Extract JS files using subjs/gospider and mine API keys, JWT tokens, AWS keys using mantra/trufflehog/regex",
                "tools": ["subjs", "mantra", "trufflehog", "nuclei"],
                "steps": [
                    r"1. cat allurls.txt | grep -E '\.js$' | anew js.txt",
                    "2. cat js.txt | mantra",
                    "3. nuclei -l js.txt -t /nuclei-templates/http/exposures/ -o js_leaks.txt"
                ]
            },
            {
                "name": "Parameter Mining & Advanced SQLi / XSS Fuzzing",
                "category": "injection_fuzzing",
                "description": "Mine hidden GET/POST parameters with arjun and test SQLi with sqlmap (random-agent, risk 3, level 5, ignore 403)",
                "tools": ["arjun", "sqlmap", "ffuf", "dalfox"],
                "steps": [
                    "1. arjun -i php_urls.txt >> params.txt",
                    "2. arjun -i php_urls.txt -m post",
                    "3. sqlmap -u 'https://target.com/file.php?id=*' --risk 3 --level 5 --random-agent --banner --batch --dbs --ignore-code 403",
                    "4. sqlmap -u 'https://target.com/api' --data 'id=*&name=*' --dbs --batch"
                ]
            }
        ]

        for pt in playbook_techniques:
            kb.save_technique(
                technique_name=pt["name"],
                category=pt["category"],
                description=pt["description"],
                tools=pt["tools"],
                steps=pt["steps"],
                affected_tech=["all_web"]
            )
            registered += 1

        # Register Google Hacking Database (GHDB) and OSINT Intelligence
        try:
            from core.playbooks.dorking_and_osint_knowledge import DorkingAndOSINTKnowledge
            registered += DorkingAndOSINTKnowledge.register_in_knowledge_base(kb)
        except Exception:
            pass

        kb.flush_vectors()
        return registered
