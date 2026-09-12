"""
Methodology & Command Knowledge Base
محرك المعرفة والمنهجيات الأمنية — يحتوي على كامل أوامر وتقنيات:
- Recon Methodology (Steps 1 to 4: Subdomains, Crawling, JS Secrets, APIs, 403 Bypasses, Dorks)
- Bug Bounty Target Selection Guide (BBP vs VDP, Scopes, Assets)
"""
import re
import json
from typing import List, Dict, Any, Optional
from pathlib import Path


class MethodologyKB:
    """
    قاعدة المعرفة والمنهجيات الخاصة بالـ Pentest والـ Recon والـ PortSwigger Web Security
    """

    def __init__(self, recon_path: Optional[str] = None,
                 target_guide_path: Optional[str] = None,
                 portswigger_path: Optional[str] = None):
        base_dir = Path(__file__).parent.parent
        default_recon = base_dir / "data" / "methodology" / "Recon_Methodology.txt"
        default_target = base_dir / "data" / "methodology" / "target_selection_guide.txt"
        default_portswigger = base_dir / "data" / "knowledge_base" / "intelligence" / "portswigger_methodology_matrix.json"

        self.recon_path = Path(recon_path) if recon_path else default_recon
        self.target_guide_path = Path(target_guide_path) if target_guide_path else default_target
        self.portswigger_path = Path(portswigger_path) if portswigger_path else default_portswigger
        self.recon_raw = ""
        self.target_guide_raw = ""
        self.portswigger_matrix: List[Dict[str, Any]] = []
        self.portswigger_by_topic: Dict[str, Dict[str, Any]] = {}
        self.tools_db: Dict[str, Dict[str, Any]] = {}
        self.steps_db: Dict[str, List[Dict[str, str]]] = {}
        self.load()

    def load(self):
        """تحميل وتحليل ملفات المنهجية"""
        if self.recon_path.exists():
            try:
                self.recon_raw = self.recon_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                pass

        if self.target_guide_path.exists():
            try:
                self.target_guide_raw = self.target_guide_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                pass

        self._parse_recon_methodology()
        self._load_portswigger_methodology()

    def _load_portswigger_methodology(self):
        """تحميل وتصنيف مصفوفة منهجيات PortSwigger Web Security الكاملة (31 فئة)"""
        if not self.portswigger_path.exists():
            return
        try:
            raw = self.portswigger_path.read_text(encoding="utf-8", errors="ignore")
            data = json.loads(raw)
            if isinstance(data, list):
                self.portswigger_matrix = data
                for item in data:
                    topic = item.get("topic", "").lower()
                    if topic:
                        self.portswigger_by_topic[topic] = item

                    category = item.get("category") or f"PORTSWIGGER: {item.get('name', topic)}"
                    tools = item.get("tools", [])
                    step_tools = []
                    for t in tools:
                        step_tools.append({
                            "tool": t.get("tool", "Tool"),
                            "cmd": t.get("cmd", ""),
                            "desc": t.get("desc", item.get("name", ""))
                        })
                    # Add verification strategy as an audit technique entry
                    strat = item.get("verification_strategy")
                    if strat:
                        step_tools.append({
                            "tool": "Verification Strategy",
                            "cmd": f"CWE: {item.get('cwe', 'N/A')} | OWASP: {item.get('owasp_category', 'N/A')}",
                            "desc": strat[:200]
                        })
                    self.steps_db[category] = step_tools
        except Exception:
            pass

    def _parse_recon_methodology(self):
        """تقسيم المنهجية إلى خطوات وأدوات وقواعد بحث"""
        # Step 1: Subdomains & Assets
        self.steps_db["STEP 1: Subdomain & Attack Surface Discovery"] = [
            {"tool": "subfinder", "cmd": "subfinder -d example.com -all -recursive -o Subs01.txt", "desc": "Passive subdomain enumeration from multiple OSINT sources"},
            {"tool": "assetfinder", "cmd": "echo example.com | assetfinder -subs-only > Subs02.txt", "desc": "Fast passive subdomain harvesting"},
            {"tool": "amass", "cmd": "amass enum -d example.com -brute -w wordlist.txt -o Subs03.txt", "desc": "Deep subdomain discovery & active DNS bruteforce"},
            {"tool": "findomain", "cmd": "findomain -t example.com -u Subs05.txt", "desc": "Lightning fast subdomain finder"},
            {"tool": "puredns", "cmd": "puredns bruteforce wordlist.txt example.com -r resolvers.txt", "desc": "High-speed DNS resolver & bruteforcer"},
            {"tool": "ffuf (VHost)", "cmd": 'ffuf -u https://example.com -w wordlist.txt -H "Host: FUZZ.example.com"', "desc": "Virtual Host / Private subdomains fuzzing"},
            {"tool": "crt.sh", "cmd": 'curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r \'.[].name_value\' | sort -u', "desc": "Certificate Transparency logs extraction"},
            {"tool": "asnmap / bgp", "cmd": "asnmap -a AS17012", "desc": "Autonomous System Number (ASN) IP range discovery"},
        ]

        # Step 2: Merge & Filter
        self.steps_db["STEP 2: Merge & Deduplication"] = [
            {"tool": "anew", "cmd": "cat Subs*.txt | anew | tee AllSubs.txt", "desc": "Append unique lines without duplicates"},
        ]

        # Step 3: Alive Probing
        self.steps_db["STEP 3: Alive Host & Technology Probing"] = [
            {"tool": "httpx (Alive)", "cmd": "cat AllSubs.txt | httpx -status-code -content-length -web-server -title -follow-redirects -o AliveSubs.txt", "desc": "Live web server detection with tech & titles"},
            {"tool": "httpx (Filter 200)", "cmd": "cat AllSubs.txt | httpx -status-code -content-length -match-code 200", "desc": "Extract only active 200 OK endpoints"},
            {"tool": "originiphunter", "cmd": "cat domains.txt | originiphunter", "desc": "Discover real Origin IP behind Cloudflare/WAF"},
        ]

        # Step 4: URL & Secret Crawling
        self.steps_db["STEP 4: URL Discovery, JS Secrets & Parameter Fuzzing"] = [
            {"tool": "waybackurls", "cmd": "cat AliveSubs.txt | waybackurls > WB1.txt", "desc": "Historical URL discovery from Wayback Machine"},
            {"tool": "waymore", "cmd": "waymore -i AliveSubs.txt -mode U -l 1000 -from 2021 -oU WM1.txt", "desc": "Aggressive multi-engine URL archive mining"},
            {"tool": "gau / gauplus", "cmd": "gauplus -t 200 -random-agent < AliveSubs.txt > GAU2.txt", "desc": "Fetch known URLs with random user-agents"},
            {"tool": "katana", "cmd": "katana -u AliveSubs.txt -jc -kf all -d 5 -headless -silent > KTN1.txt", "desc": "Next-gen headless web crawler with JS parsing"},
            {"tool": "paramspider", "cmd": "paramspider -d example.com -o PS1.txt", "desc": "Mining parameter URLs for injection testing"},
            {"tool": "qsreplace", "cmd": 'cat AllURLs.txt | grep "=" | qsreplace "FUZZ" | anew | tee ParamURLs.txt', "desc": "Replace query parameters with FUZZ for vulnerability scanning"},
            {"tool": "subjs / mantra", "cmd": "cat js_urls.txt | mantra", "desc": "Extract endpoints and sensitive tokens from JS files"},
            {"tool": "trufflehog", "cmd": "trufflehog filesystem js_urls.txt --json > trufflehog_results.json", "desc": "Automated API key and secret scanning"},
            {"tool": "arjun", "cmd": "arjun -i AllURLs.txt -o arjun.json", "desc": "Hidden HTTP parameter discovery (GET & POST)"},
            {"tool": "nuclei (Exposures)", "cmd": "nuclei -l AliveSubs.txt -t /nuclei-templates/http/exposures -o results.txt", "desc": "Automated vulnerability & sensitive file exposure scanning"},
            {"tool": "ffuf (403 Bypass)", "cmd": 'ffuf -u https://example.com/FUZZ -w wordlist.txt -H "X-Forwarded-For: 127.0.0.1" -H "X-Original-URL: /FUZZ"', "desc": "403 Forbidden bypass using header overrides"},
            {"tool": "kiterunner", "cmd": "kr scan https://api.example.com -A=apiroutes-260227:10000 -x 8 -v info", "desc": "Fast API routing & hidden endpoint brute-force"},
        ]

    def search(self, query: str) -> List[Dict[str, str]]:
        """البحث في أوامر ومنهجيات الـ Recon والـ PortSwigger"""
        q = query.lower()
        results = []
        for step_title, tool_list in self.steps_db.items():
            for item in tool_list:
                tool_name = item.get("tool", "")
                cmd = item.get("cmd", "") or item.get("command", "")
                desc = item.get("desc", "") or item.get("description", "")
                if (q in tool_name.lower() or 
                    q in cmd.lower() or 
                    q in desc.lower() or 
                    q in step_title.lower()):
                    results.append({
                        "step": step_title,
                        "tool": tool_name,
                        "command": cmd,
                        "description": desc
                    })
        return results

    def get_all_steps(self) -> Dict[str, List[Dict[str, str]]]:
        """إرجاع المنهجية الكاملة مقسمة حسب المراحل والفئات"""
        return self.steps_db

    def get_portswigger_matrix(self) -> List[Dict[str, Any]]:
        """إرجاع مصفوفة PortSwigger كاملة بجميع الحقول (31 فئة)"""
        return self.portswigger_matrix

    def get_topic_methodology(self, topic: str) -> Optional[Dict[str, Any]]:
        """الحصول على منهجية فئة محددة بالاسم (مثال: sqli, xss, ssrf, jwt)"""
        t = topic.lower().strip()
        if t in self.portswigger_by_topic:
            return self.portswigger_by_topic[t]
        for item in self.portswigger_matrix:
            if item.get("id") == t or item.get("id") == f"portswigger_{t}":
                return item
            if t in item.get("name", "").lower() or t in item.get("topic", "").lower():
                return item
        return None

    def get_all_categories(self) -> List[str]:
        """قائمة بجميع الفئات المتاحة في قاعدة المنهجيات"""
        return list(self.steps_db.keys())

    def get_target_selection_guide(self) -> str:
        """دليل اختيار الأهداف BBP vs VDP"""
        return self.target_guide_raw if self.target_guide_raw else "Bug Bounty Target Selection: Prioritize clear scope assets, BBP for bounties, and VDP for Hall of Fame."

    def format_methodology_context_for_ai(self, topic: Optional[str] = None) -> str:
        """تجهيز سياق المنهجية لتقديمه لموديلات الذكاء الاصطناعي أثناء التخطيط"""
        if topic:
            item = self.get_topic_methodology(topic)
            if item:
                return (
                    f"### METHODOLOGY FOR {item.get('name', topic).upper()}\n"
                    f"- Category: {item.get('category')}\n"
                    f"- CWE: {item.get('cwe')} | OWASP: {item.get('owasp_category')}\n"
                    f"- Signals: {', '.join(item.get('signals', []))}\n"
                    f"- Verification Strategy: {item.get('verification_strategy')}\n"
                    f"- Evidence Required: {', '.join(item.get('evidence_requirements', []))}\n"
                    f"- Recommended Tools: {json.dumps(item.get('tools', []))}\n"
                    f"- Remediation: {item.get('remediation')}\n"
                )

        lines = [
            "### COMPREHENSIVE RECON & PORTSWIGGER METHODOLOGY KNOWLEDGE BASE",
            "When analyzing targets, follow these verified methodologies and standard tool chains:",
            ""
        ]
        for step_name, tools in self.steps_db.items():
            lines.append(f"#### {step_name}")
            for t in tools:
                cmd_str = t.get('cmd') or t.get('command') or ''
                desc_str = t.get('desc') or ''
                tool_name = t.get('tool') or 'Tool'
                lines.append(f"- **{tool_name}**: `{cmd_str}` — {desc_str}")
            lines.append("")
        return "\n".join(lines)
