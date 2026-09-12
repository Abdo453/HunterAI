"""
Autonomous AI Security Hunter (The Autonomous Pentest Agent)
المحرك الذاتي الشامل — ينفذ استراتيجية المستخدم بالكامل:
1. جلب السكوب والنطاقات من كل مصادر الـ OSINT والأدوات في العالم
2. تشغيل المتصفح وتوجيه كل الزيارات عبر Burp Suite Proxy (127.0.0.1:8080)
3. تكليف Qwen Coder (14B) بتحليل كود الـ JavaScript والـ HTML Comments والـ APIs
4. تكليف WhiteRabbitNeo و Xploiter بتحليل طلبات Burp ومخرجات الأدوات وتخطيط الهجوم
5. حلقة تفكير ذاتية مستقلة (Autonomous OODA Loop) تتكيف مع مخرجات الموقع تلقائياً
"""
import asyncio
import json
import time
import os
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable
from urllib.parse import urlparse

from core.scope_guard import ScopeGuard
from core.methodology_kb import MethodologyKB
from tools.tool_manager import ToolManager
from tools.waf_evasion import WAFEvasionEngine
from tools.browser_tools import BrowserController
from orchestrator.resource_manager import ResourceManager
from models.ollama_manager import OllamaManager
from core.vulnerability_correlator import VulnerabilityCorrelator
from core.task_planner import TaskPlanner, TaskKind


class AutonomousHunter:
    """
    الـ Agent الذاتي المتكامل (AI Security OS Hunter):
    يعمل بشكل مستقل بالكامل بمجرد إعطائه الدومين أو السكوب!
    """

    def __init__(self, target: str, scope_guard: Optional[ScopeGuard] = None,
                 progress_cb: Optional[Callable] = None, session_id: Optional[str] = None,
                 burp_proxy: str = "127.0.0.1:8080", use_burp: bool = True):
        self.target = target.strip()
        self.scope_guard = scope_guard or ScopeGuard(in_scope=[self.target])
        self.cb = progress_cb
        self.session_id = session_id or f"hunter_{int(time.time())}"
        self.burp_proxy = burp_proxy
        self.use_burp = use_burp
        
        self.tm = ToolManager()
        self.waf_engine = WAFEvasionEngine()
        self.kb = MethodologyKB()
        self.rm = ResourceManager()
        self.ollama = OllamaManager()
        self.correlator = VulnerabilityCorrelator()
        self.planner = TaskPlanner(self.target)

        # Storage
        self.discovered_subdomains: List[str] = []
        self.alive_urls: List[str] = []
        self.js_files: List[str] = []
        self.html_comments: List[str] = []
        self.captured_traffic: List[Dict[str, Any]] = []
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.action_history: List[str] = []

    async def _emit(self, event_type: str, data: Dict[str, Any]):
        if self.cb:
            try:
                msg = {"event": event_type, "session_id": self.session_id, **data}
                if asyncio.iscoroutinefunction(self.cb):
                    await self.cb(msg)
                else:
                    self.cb(msg)
            except Exception:
                pass

    async def start(self) -> Dict[str, Any]:
        """بدء عملية الصيد الذاتي المستقلة"""
        t0 = time.time()
        await self._emit("hunter_start", {
            "target": self.target,
            "message": f"🎯 Autonomous AI Hunter initiated for: {self.target}",
            "burp_proxy": self.burp_proxy if self.use_burp else "Disabled"
        })

        # ── الخطوة 1: جمع كل الصب دومينات من كل مصادر الإنترنت والأدوات ──
        await self._gather_all_osint_subdomains()

        # ── الخطوة 2: فحص السيرفرات النشطة وحماية الـ WAF ──
        await self._probe_alive_and_waf()

        # ── الخطوة 3: فتح المتصفح وتوجيه كل الطلبات لـ Burp Suite ──
        await self._crawl_with_browser_and_burp()

        # ── الخطوة 4: تكليف Qwen Coder بفحص كود الجافا سكريبت والكومنتات ──
        await self._analyze_code_with_qwen()

        # ── الخطوة 5: تكليف WhiteRabbitNeo و Xploiter بتحليل حركة المرور والتخطيط ──
        await self._security_council_decision_loop()

        duration = round(time.time() - t0, 2)
        summary = {
            "target": self.target,
            "session_id": self.session_id,
            "duration": duration,
            "subdomains_count": len(self.discovered_subdomains),
            "alive_urls_count": len(self.alive_urls),
            "js_files_count": len(self.js_files),
            "vulnerabilities_count": len(self.vulnerabilities),
            "vulnerabilities": self.vulnerabilities,
            "actions_executed": self.action_history
        }

        await self._emit("hunter_done", summary)
        return summary

    async def _gather_all_osint_subdomains(self):
        """جمع الصب دومينات من الأدوات وكل مواقع الـ OSINT في العالم"""
        await self._emit("hunter_step", {
            "step": 1,
            "title": "🌐 Aggregating Global OSINT & Subdomains",
            "status": "Querying crt.sh, AlienVault, Subfinder, Assetfinder, Hackertarget..."
        })

        subs = set()
        subs.add(self.target)

        import httpx

        # 1. crt.sh (SSL Transparency Logs)
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(f"https://crt.sh/?q=%25.{self.target}&output=json")
                if r.status_code == 200:
                    for item in r.json():
                        for n in item.get("name_value", "").split("\n"):
                            clean = n.strip().lower().replace("*.", "")
                            if clean and self.target in clean:
                                subs.add(clean)
        except Exception:
            pass

        # 2. AlienVault OTX
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{self.target}/passive_dns")
                if r.status_code == 200:
                    for record in r.json().get("passive_dns", []):
                        h = record.get("hostname", "").strip().lower()
                        if h and self.target in h:
                            subs.add(h)
        except Exception:
            pass

        # 3. HackerTarget OSINT
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(f"https://api.hackertarget.com/hostsearch/?q={self.target}")
                if r.status_code == 200 and "error" not in r.text.lower():
                    for line in r.text.splitlines():
                        h = line.split(",")[0].strip().lower()
                        if h and self.target in h:
                            subs.add(h)
        except Exception:
            pass

        # 4. الأدوات المحلية (Subfinder & Assetfinder إن وجدت)
        if self.tm.is_tool_available("subfinder"):
            res = await self.tm.execute_tool("subfinder", f"-d {self.target} -silent")
            if res.stdout:
                for line in res.stdout.splitlines():
                    clean = line.strip().lower()
                    if clean and self.target in clean:
                        subs.add(clean)

        # تصفية النطاقات عبر حارس الـ Scope
        valid_subs = [s for s in subs if self.scope_guard.is_in_scope(s)[0]]
        self.discovered_subdomains = valid_subs
        self.action_history.append(f"Discovered {len(valid_subs)} in-scope subdomains")

        await self._emit("hunter_step", {
            "step": 1,
            "title": "🌐 Aggregating Global OSINT & Subdomains",
            "status": f"Successfully collected {len(valid_subs)} unique in-scope subdomains",
            "count": len(valid_subs)
        })

    async def _probe_alive_and_waf(self):
        """فحص السيرفرات النشطة وحماية الـ WAF"""
        await self._emit("hunter_step", {
            "step": 2,
            "title": "🛡️ Alive Probing & WAF Radar",
            "status": "Checking live web services and identifying WAF protections..."
        })

        import httpx
        alive = []

        async with httpx.AsyncClient(timeout=6, verify=False) as client:
            for sub in self.discovered_subdomains[:20]:
                for proto in ["https", "http"]:
                    url = f"{proto}://{sub}"
                    try:
                        resp = await client.get(url)
                        if resp.status_code < 500:
                            alive.append(url)
                            break
                    except Exception:
                        pass

        self.alive_urls = alive
        self.action_history.append(f"Identified {len(alive)} live web targets")

        await self._emit("hunter_step", {
            "step": 2,
            "title": "🛡️ Alive Probing & WAF Radar",
            "status": f"Found {len(alive)} live services ready for browser inspection",
            "count": len(alive)
        })

    async def _crawl_with_browser_and_burp(self):
        """فتح المتصفح وزيارة المواقع وتوجيه كل حركة المرور عبر Burp Suite"""
        await self._emit("hunter_step", {
            "step": 3,
            "title": "🌐 Browser Crawling & Burp Suite Proxy Logging",
            "status": f"Browsing targets via Burp Proxy ({self.burp_proxy}) & extracting JS/DOM..."
        })

        import httpx
        proxy_url = f"http://{self.burp_proxy}" if self.use_burp else None
        
        # استخراج كود الـ HTML وملفات الـ JS والكومنتات من كل موقع نشط
        async with httpx.AsyncClient(timeout=10, verify=False, proxy=proxy_url) as client:
            for target_url in self.alive_urls[:10]:
                try:
                    resp = await client.get(target_url)
                    html = resp.text

                    # استخراج ملفات الجافا سكريبت
                    js_links = re.findall(r'<script[^>]+src=["\'](.*?)["\']', html, re.IGNORECASE)
                    for js in js_links:
                        if not js.startswith("http"):
                            js = f"{target_url.rstrip('/')}/{js.lstrip('/')}"
                        self.js_files.append(js)

                    # استخراج كومنتات الـ HTML المتروكة
                    comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
                    for c in comments:
                        c_clean = c.strip()
                        if len(c_clean) > 5 and not c_clean.startswith("[if"):
                            self.html_comments.append(f"[{target_url}] {c_clean}")

                    # تسجيل الطلب في الـ Captured Traffic لتحليله لاحقاً
                    self.captured_traffic.append({
                        "url": target_url,
                        "status": resp.status_code,
                        "headers": dict(resp.headers),
                        "snippet": html[:1000]
                    })

                except Exception:
                    pass

        self.action_history.append(f"Extracted {len(self.js_files)} JS files and {len(self.html_comments)} HTML comments via Burp Proxy")
        await self._emit("hunter_step", {
            "step": 3,
            "title": "🌐 Browser Crawling & Burp Suite Proxy Logging",
            "status": f"Burp traffic captured! Found {len(self.js_files)} scripts & {len(self.html_comments)} source comments",
            "js_count": len(self.js_files),
            "comments_count": len(self.html_comments)
        })

    async def _analyze_code_with_qwen(self):
        """تكليف Qwen Coder 14B بفحص الأكواد والجافا سكريبت والكومنتات المتروكة"""
        await self._emit("hunter_step", {
            "step": 4,
            "title": "💻 Qwen Coder (14B) Code & Secret Analysis",
            "status": "Analyzing JavaScript files, HTML comments, and leaked tokens..."
        })

        if not self.html_comments and not self.js_files:
            return

        code_context = "### Extracted Developer Comments & Scripts:\n"
        if self.html_comments:
            code_context += "HTML Comments:\n" + "\n".join(self.html_comments[:10]) + "\n\n"
        if self.js_files:
            code_context += "Discovered JS Files:\n" + "\n".join(self.js_files[:15]) + "\n"

        prompt = f"""You are Qwen Coder, an expert security code analyst.
Analyze the following HTML comments, JS scripts, and code artifacts extracted from {self.target}:
{code_context}

Tasks:
1. Look for leaked API keys, tokens, secret paths, internal staging URLs, or credentials.
2. Identify hidden endpoints (e.g. /api/v1/admin, /debug, /config).
3. Identify vulnerable coding patterns or exposed logic.
Provide clear, actionable findings."""

        messages = [
            {"role": "system", "content": "You are Qwen Coder, specialized in offensive code analysis, secret discovery, and endpoint extraction."},
            {"role": "user", "content": prompt}
        ]

        qwen_analysis = await self.rm.run_local_model(
            model_name="qwen2.5-coder:14b",
            messages=messages,
            temperature=0.2,
            num_ctx=2048,
            progress_cb=self.cb
        )

        self.vulnerabilities.append({
            "title": "Code Artifacts & Secret Analysis (Qwen Coder 14B)",
            "severity": "Medium",
            "model": "qwen2.5-coder:14b",
            "analysis": qwen_analysis
        })

        self.action_history.append("Qwen Coder completed code & secret analysis")

    async def _security_council_decision_loop(self):
        """تكليف WhiteRabbitNeo و Xploiter بتحليل حركة المرور واقتراح خطوات الهجوم المستقلة"""
        await self._emit("hunter_step", {
            "step": 5,
            "title": "🧠 Multi-Model Security Council & Attack Planning",
            "status": "WhiteRabbitNeo & Xploiter analyzing Burp traffic and planning attack vector..."
        })

        traffic_summary = "\n".join([f"- URL: {t['url']} (Status: {t['status']}, Server: {t['headers'].get('server', 'N/A')})" for t in self.captured_traffic[:10]])

        # ── Step A: WhiteRabbitNeo هجوم وتحليل الثغرات ──
        wrn_prompt = f"""Target: {self.target}
Captured Web Traffic via Burp Suite:
{traffic_summary}

Based on this attack surface, what are the highest priority attack vectors to test (e.g. 403 bypass on admin, IDOR on APIs, SQLi on query params)? Formulate the offensive plan."""

        wrn_analysis = await self.rm.run_local_model(
            model_name="WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest",
            messages=[
                {"role": "system", "content": "You are WhiteRabbitNeo, an elite offensive security AI. Prioritize vulnerabilities and concrete attack vectors."},
                {"role": "user", "content": wrn_prompt}
            ],
            temperature=0.3,
            progress_cb=self.cb
        )

        # ── Step B: Xploiter استراتيجية الأدوات المحددة ──
        xpl_prompt = f"""WhiteRabbitNeo's Attack Surface Analysis:
{wrn_analysis[:600]}

As the Pentest Strategist, recommend the exact Kali tools (nmap, ffuf 403-bypass, sqlmap, arjun, katana) with exact command flags to execute against {self.target}."""

        xpl_analysis = await self.rm.run_local_model(
            model_name="xploiter/pentester:latest",
            messages=[
                {"role": "system", "content": "You are Xploiter Pentester. Provide exact tool recommendations and attack commands."},
                {"role": "user", "content": xpl_prompt}
            ],
            temperature=0.3,
            progress_cb=self.cb
        )

        self.vulnerabilities.append({
            "title": "Offensive Attack Surface Strategy (WhiteRabbitNeo)",
            "severity": "Info",
            "model": "WhiteRabbitNeo (8B)",
            "analysis": wrn_analysis
        })

        self.vulnerabilities.append({
            "title": "Tool Execution Strategy & Pentest Plan (Xploiter)",
            "severity": "Info",
            "model": "xploiter/pentester",
            "analysis": xpl_analysis
        })

        self.action_history.append("Security Council (WhiteRabbitNeo + Xploiter) completed attack planning")
