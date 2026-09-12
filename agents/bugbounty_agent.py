"""
Bug Bounty & Full-Spectrum Audit Agent
ينفذ فحصاً شاملاً متكاملاً للبق بونتي (Recon, Secrets, JS, Server, Headers, APIs, Differential PoC)
"""
import re
import asyncio
import httpx
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, urljoin

from agents.base_agent import BaseAgent, AgentTask, AgentResult
from tools.tool_manager import ToolManager
from core.smart_probe_engine import SmartPoCExecutor
from core.skill_memory_engine import SkillLearnerEngine


class BugBountyAgent(BaseAgent):
    def __init__(self, mgr: ToolManager, cb=None, proxy: Optional[str] = None, auth: Optional[Dict[str, Any]] = None):
        super().__init__("bugbounty_agent", "Full-Spectrum Bug Bounty & Server Audit Agent", mgr, cb)
        self.proxy = proxy
        self.auth = auth or {}
        self.prober = SmartPoCExecutor(proxy=proxy)
        self.skills = SkillLearnerEngine()

    def _get_auth_headers(self) -> Dict[str, str]:
        hdrs = {}
        if self.auth.get("cookie"):
            hdrs["Cookie"] = self.auth["cookie"]
        if self.auth.get("token"):
            hdrs["Authorization"] = f"Bearer {self.auth['token']}"
        return hdrs

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target
        url = target if target.startswith("http") else f"https://{target}"
        r = AgentResult(agent_name=self.name, target=target)
        if not self.auth and task.extra.get("auth"):
            self.auth = task.extra["auth"]
        auth_note = " | 🔐 مصادقة مفعلة" if self.auth.get("username") or self.auth.get("cookie") else ""
        await self.emit("start", {"message": f"🚀 بدء الفحص الشامل للبق بونتي على الهدف: {url} | البروكسي: {self.proxy or 'Direct'}{auth_note}"})

        # ── 1. فحص إعدادات وحماية السيرفر والهيدرز (Server Headers & Security Audit) ──
        await self.emit("tool_start", {"tool": "Server Header & CORS Audit"})
        headers_findings = await self._audit_server_headers(url)
        for hf in headers_findings:
            r.findings.append(hf)
        await self.emit("tool_done", {"tool": "Server Header & CORS Audit", "findings": len(headers_findings)})

        # ── 2. زحف وتحليل ملفات الجافاسكريبت والروابط والباراميترات الحساسة ──
        await self.emit("tool_start", {"tool": "Crawler & Parameter Discovery"})
        js_findings, endpoints = await self._scrape_js_and_secrets(url)
        for jf in js_findings:
            r.findings.append(jf)
        await self.emit("tool_done", {"tool": "Crawler & Parameter Discovery", "endpoints": len(endpoints), "secrets": len(js_findings)})

        # ── 3. فحص الباراميترات والتفاضل الذكي وحقن الثغرات (Differential PoC Verification) ──
        if endpoints:
            await self.emit("tool_start", {"tool": "Differential PoC & Exploit Prober"})
            v_types = ["sqli", "xss"] if task.mode in ("bugbounty_full", "web", "all") else ([task.mode] if task.mode in ("sqli", "xss", "idor") else ["sqli", "xss"])
            for ep in endpoints[:15]:
                parsed = urlparse(ep)
                if "?" in ep or any(p in ep.lower() for p in ["category=", "id=", "user=", "page=", "file=", "url=", "query=", "search=", "q=", "name="]):
                    qs = parsed.query
                    param_name = qs.split("=")[0] if "=" in qs else "search"
                    base_ep = ep.split("?")[0] if "?" in ep else ep
                    await self.emit("log", {"message": f"🔍 [PROBING PARAMETER] '{param_name}' on {base_ep}"})
                    for vt in v_types:
                        try:
                            await self.emit("log", {"message": f"   -> Testing {vt.upper()} injection & reflection logic on: '{param_name}'..."})
                            poc_res = await self.prober.execute_and_verify(
                                target_url=base_ep,
                                param_name=param_name,
                                vuln_type=vt
                            )
                            if poc_res.get("verified"):
                                real_vt = poc_res.get("vuln_type", vt)
                                cvss_info = poc_res.get("cvss", {})
                                sev = cvss_info.get("severity") or ("High" if "xss" in real_vt else ("Critical" if "sql" in real_vt else "Medium"))
                                reason = poc_res.get('proof_reason', '')
                                rem = poc_res.get("remediation") or "قم بتعقيم وتطهير المدخلات وترميز المخرجات بحسب السياق."
                                await self.emit("log", {"message": f"   🔥 [CONFIRMED {real_vt.upper()}] Verified by AI! {reason}"})
                                r.findings.append({
                                    "type": f"verified_{real_vt}",
                                    "severity": sev,
                                    "title": f"🔥 ثغرة {real_vt.upper()} مؤكدة بالذكاء الاصطناعي على: {param_name}",
                                    "evidence": f"URL: {ep}\nReason: {reason}\nCVSS: {cvss_info.get('score', 7.5)}",
                                    "tool": "AI-SmartProbeEngine",
                                    "recommendation": rem
                                })
                            else:
                                await self.emit("log", {"message": f"   -> [CHECKED] No {vt.upper()} anomaly found on '{param_name}'"})
                        except Exception:
                            pass
            await self.emit("tool_done", {"tool": "Differential PoC & Exploit Prober"})

        # ── 4. فحص الأدوات الخارجية المتوفرة (Nuclei / Nmap / SQLMap / WAF) ──
        if self.mgr.is_available("wafw00f"):
            await self.emit("tool_start", {"tool": "wafw00f"})
            w_res = await self.mgr.execute("wafw00f", [url])
            if "is behind" in w_res.stdout:
                r.findings.append({
                    "type": "waf_detected",
                    "severity": "Info",
                    "title": "WAF Protection Detected",
                    "evidence": w_res.stdout[:300],
                    "tool": "wafw00f",
                    "recommendation": "Adjust stealth timing and evade WAF rate-limiting."
                })
            await self.emit("tool_done", {"tool": "wafw00f"})

        # ── 5. فحص ثغرات ونقاط كشف WordPress الحساسة (WP Exposures) ──
        try:
            from core.playbooks.bug_bounty_methodology import BugBountyMethodology
            bb_method = BugBountyMethodology(self.mgr)
            wp_exposures = await bb_method.check_wordpress_exposures(url)
            for wpe in wp_exposures:
                r.findings.append(wpe)
                await self.emit("log", {"message": f"   🚨 [WP EXPOSURE] {wpe['title']} on {wpe['url']}"})
        except Exception:
            pass

        # ── 6. محاولات تجاوز 403 Forbidden تلقائياً (403 Bypass Engine) ──
        try:
            bypasses = await bb_method.test_403_bypass(url)
            for bp in bypasses:
                r.findings.append(bp)
                await self.emit("log", {"message": f"   🔥 [403 BYPASS] {bp['title']}"})
        except Exception:
            pass

        # ── 7. فحص واكتشاف الباراميترات المخفية عبر Arjun (GET / POST) ──
        if self.mgr.is_available("arjun"):
            await self.emit("tool_start", {"tool": "arjun"})
            try:
                arjun_res = await self.mgr.execute("arjun", ["-u", url, "--passive", "-m", "get"])
                if "parameters found" in arjun_res.stdout.lower() or "[" in arjun_res.stdout:
                    r.findings.append({
                        "type": "hidden_parameters",
                        "severity": "Info",
                        "title": "Hidden Parameters Discovered (Arjun)",
                        "evidence": arjun_res.stdout[:500],
                        "tool": "arjun",
                        "recommendation": "Fuzz discovered hidden parameters for injection vulnerabilities."
                    })
            except Exception:
                pass
            await self.emit("tool_done", {"tool": "arjun"})

        if self.mgr.is_available("nuclei"):
            await self.emit("tool_start", {"tool": "nuclei"})
            n_res = await self.mgr.execute("nuclei", ["-u", url, "-severity", "critical,high,medium", "-silent"])
            for line in n_res.stdout.splitlines():
                if line.strip() and "[" in line:
                    sev = "Critical" if "critical" in line.lower() else "High" if "high" in line.lower() else "Medium"
                    r.findings.append({
                        "type": "cve_nuclei",
                        "severity": sev,
                        "title": line[:100],
                        "evidence": line,
                        "tool": "nuclei",
                        "recommendation": "Update affected components and patch vulnerabilities."
                    })
            await self.emit("tool_done", {"tool": "nuclei"})

        await self.emit("complete", {"findings": len(r.findings)})
        return r

    async def _audit_server_headers(self, url: str) -> List[Dict[str, Any]]:
        findings = []
        try:
            req_headers = {"Origin": "https://evil.com", **self._get_auth_headers()}
            async with httpx.AsyncClient(timeout=10, proxy=self.proxy, verify=False) as c:
                resp = await c.get(url, headers=req_headers)
                h = resp.headers

                # 1. CORS Misconfiguration
                acao = h.get("access-control-allow-origin", "")
                acac = h.get("access-control-allow-credentials", "")
                if acao == "*" or acao == "https://evil.com":
                    findings.append({
                        "type": "cors_misconfiguration",
                        "severity": "High" if acac.lower() == "true" else "Medium",
                        "title": "CORS Misconfiguration (Arbitrary Origin Allowed)",
                        "evidence": f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                        "tool": "HeaderAudit",
                        "recommendation": "Restrict Access-Control-Allow-Origin to trusted domains and disable wildcard with credentials."
                    })

                # 2. Missing Security Headers (Consolidated to avoid noise)
                sec_headers = ["content-security-policy", "x-frame-options", "x-content-type-options", "strict-transport-security"]
                missing = [sh for sh in sec_headers if sh not in h]
                if missing:
                    findings.append({
                        "type": "missing_headers",
                        "severity": "Low",
                        "title": f"Missing Security Headers ({len(missing)}): {', '.join(missing)}",
                        "evidence": f"Web server omitted headers: {', '.join(missing)}",
                        "tool": "HeaderAudit",
                        "recommendation": "Configure web server to return standard security headers (CSP, HSTS, X-Frame-Options)."
                    })

                # 3. Server Version Leaks
                server_hdr = h.get("server") or h.get("x-powered-by")
                if server_hdr and any(c.isdigit() for c in server_hdr):
                    findings.append({
                        "type": "version_disclosure",
                        "severity": "Low",
                        "title": f"Server Banner & Version Disclosure: {server_hdr}",
                        "evidence": f"Server header returned: {server_hdr}",
                        "tool": "HeaderAudit",
                        "recommendation": "Mask or disable Server and X-Powered-By response headers."
                    })
        except Exception:
            pass
        return findings

    async def _scrape_js_and_secrets(self, url: str) -> (List[Dict[str, Any]], List[str]):
        findings = []
        endpoints = set()

        secret_patterns = {
            "AWS Access Key": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
            "Generic API Key": r"(?i)(?:api_key|apikey|secret_key|app_secret|auth_token)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,64})['\"]",
            "JWT Token": r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            "Firebase URL": r"https://[a-zA-Z0-9_-]+\.firebaseio\.com",
            "GitHub Token": r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}",
            "Slack Webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
            "Internal Path Leak": r"['\"](/api/v[0-9]/[a-zA-Z0-9_\-/]+)['\"]"
        }

        try:
            auth_hdrs = self._get_auth_headers()
            async with httpx.AsyncClient(timeout=10, proxy=self.proxy, verify=False) as c:
                resp = await c.get(url, headers=auth_hdrs)
                html = resp.text
                
                # Extract HTML links and parameters (e.g. PortSwigger category filters, search forms)
                links = re.findall(r'href=["\']([^"\']+)["\']', html, re.I)
                for lk in links:
                    if "?" in lk or any(k in lk.lower() for k in ["category=", "id=", "search=", "query=", "file=", "user="]):
                        endpoints.add(urljoin(url, lk))

                # Extract HTML Forms and their input parameter names (e.g. search, q, comment, name)
                try:
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(html, 'html.parser')
                    for form in soup.find_all('form'):
                        action = form.get('action') or ''
                        form_url = urljoin(url, action)
                        for inp in form.find_all(['input', 'textarea']):
                            inp_name = inp.get('name')
                            if inp_name and inp_name.lower() not in ['csrf', '_csrf', 'token']:
                                endpoints.add(f"{form_url}?{inp_name}=test")
                except Exception:
                    pass

                # Find all JS links
                js_links = re.findall(r'<script[^>]+src=["\'](.*?)["\']', html, re.I)
                for link in js_links[:10]:
                    full_js_url = urljoin(url, link)
                    try:
                        js_resp = await c.get(full_js_url, timeout=6)
                        js_text = js_resp.text
                        
                        # Search patterns
                        for sec_name, pattern in secret_patterns.items():
                            matches = re.findall(pattern, js_text)
                            if matches:
                                sample = str(matches[0])[:80]
                                findings.append({
                                    "type": "secret_leak",
                                    "severity": "High" if "API" in sec_name or "AWS" in sec_name else "Medium",
                                    "title": f"🚨 Potential {sec_name} Leaked in JS File",
                                    "evidence": f"File: {full_js_url}\nMatch Sample: {sample}",
                                    "tool": "JSSecretHarvester",
                                    "recommendation": "Remove sensitive hardcoded keys and invalidate leaked tokens."
                                })

                        # Extract endpoints
                        api_matches = re.findall(r"['\"](/api/[a-zA-Z0-9_\-\./\?=&]+)['\"]", js_text)
                        for m in api_matches:
                            endpoints.add(urljoin(url, m))
                    except Exception:
                        pass
        except Exception:
            pass

        return findings, list(endpoints)
