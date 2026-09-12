"""
Autonomous Reasoning Agent — الوكيل الذكي القائم على التفكير والاستنتاج أولاً
يقوم بفحص الهدف وقراءة كود الصفحة ثم يسأل الذكاء الاصطناعي:
ما هي طبيعة هذا الهدف؟ وما هي الأدوات التي يحتاجها فعلاً وما هي الأدوات غير الضرورية التي يجب تخطيها؟
"""
import os
import re
import json
import time
import logging
from typing import Dict, List, Any, Optional, Callable
from urllib.parse import urlparse

import httpx

from core.ai_reasoning_core import AIReasoningCore

log = logging.getLogger("autonomous_reasoning_agent")


class AutonomousReasoningAgent:
    """
    وكيل ذكي مستقل: يفهم الهدف أولاً، يحدد الأدوات الضرورية فقط، ويتخطى الأدوات غير اللازمة
    """

    def __init__(self, tool_manager, progress_callback: Optional[Callable] = None):
        self.mgr = tool_manager
        self.cb = progress_callback

    async def emit(self, event: str, data: dict):
        if self.cb:
            try:
                await self.cb({"event": event, **data})
            except Exception:
                pass

    async def log_msg(self, msg: str):
        await self.emit("log", {"message": msg})

    async def run(self, target: str, mode: str = "auto", auth: Optional[dict] = None, proxy: Optional[str] = None) -> Dict[str, Any]:
        url = target if target.startswith("http") else f"http://{target}"
        findings = []
        t0 = time.time()

        await self.log_msg(f"🧠 [AI AGENT START] بدء الفحص الذكي للهدف: {url}")
        await self.log_msg("🔍 [STEP 1: PERCEPTION] جاري سحب كود الصفحة وتفاصيل الاستجابة لفهم بيئة الهدف...")

        # ── الخطوة 1: سحب الصفحة الأولى واستكشاف المعطيات ──
        html_snippet = ""
        status_code = 0
        headers = {}
        cookies = auth.get("cookie", "") if auth else ""

        req_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }
        if cookies:
            req_headers["Cookie"] = cookies

        try:
            async with httpx.AsyncClient(timeout=10.0, proxy=proxy, verify=False, follow_redirects=True) as client:
                resp = await client.get(url, headers=req_headers)
                html_snippet = resp.text
                status_code = resp.status_code
                headers = dict(resp.headers)
        except Exception as e:
            await self.log_msg(f"⚠️ [WARNING] تعذر جلب الصفحة عبر HTTP المباشر: {e}")

        # ── الخطوة 2: استشارة الذكاء الاصطناعي لتحديد الاستراتيجية والأدوات المطلوبة ──
        await self.log_msg("💡 [STEP 2: AI REASONING] الذكاء الاصطناعي يحلل كود الصفحة ويقرر الأدوات الضرورية فقط...")

        available_tools = self.mgr.get_available() if hasattr(self.mgr, "get_available") else ["nmap", "subfinder", "gobuster", "sqlmap", "nuclei", "dalfox", "crawler"]

        prompt = (
            f"Target URL: {url}\n"
            f"HTTP Status: {status_code}\n"
            f"Available System Tools: {available_tools}\n"
            f"HTML Snippet (first 3000 chars):\n{html_snippet[:3000]}\n\n"
            f"TASK:\n"
            f"1. Understand what this target is (e.g. A specific lab endpoint, a search form, a login portal, or a full root domain).\n"
            f"2. DECIDE which tools are ACTUALLY NEEDED and which tools should be SKIPPED.\n"
            f"   (e.g., If this is a specific URL parameter or lab, SKIP heavy port scans and subfinder, and focus ONLY on parameter inspection).\n"
            f"3. Return a JSON object with this exact structure:\n"
            f'{{\n'
            f'  "target_analysis": "Brief explanation of what the target is",\n'
            f'  "needed_tools": ["tool1", "tool2"],\n'
            f'  "skipped_tools": ["tool3", "tool4"],\n'
            f'  "skip_reasons": "Why these tools were skipped",\n'
            f'  "primary_focus": "xss / sqli / auth / ports / recon / api",\n'
            f'  "parameters_to_audit": ["search", "id"]\n'
            f'}}'
        )

        ai_plan_raw = await AIReasoningCore.ask_ai(prompt, system_prompt="You are an autonomous AI security strategist. Output valid JSON only.")
        plan = {}
        if ai_plan_raw:
            try:
                m = re.search(r'\{.*\}', ai_plan_raw, re.DOTALL)
                if m:
                    plan = json.loads(m.group(0))
            except Exception:
                pass

        if not plan:
            # Fallback reasoning
            is_lab = "web-security-academy.net" in url or "lab" in html_snippet.lower()
            plan = {
                "target_analysis": "Specific web application / Lab endpoint" if is_lab else "Standard Web Target",
                "needed_tools": ["DOM Reflection & Parameter Auditor", "SmartProbeEngine"],
                "skipped_tools": ["nmap", "subfinder", "gobuster"],
                "skip_reasons": "Target is a specific endpoint; network-level recon and heavy fuzzing are redundant.",
                "primary_focus": "xss" if "xss" in html_snippet.lower() else "sqli",
                "parameters_to_audit": ["search", "q", "category", "id"]
            }

        # بث قرار الذكاء الاصطناعي للمستخدم
        await self.log_msg(f"🧠 [AI ANALYSIS] {plan.get('target_analysis', 'Web Target Analyzed')}")
        await self.log_msg(f"🎯 [AI FOCUS] التركيز الأساسي: {plan.get('primary_focus', 'General Web Audit').upper()}")
        
        skipped = plan.get("skipped_tools", [])
        if skipped:
            await self.log_msg(f"⏭️ [AI DECISION] تخطي الأدوات غير الضرورية ({', '.join(skipped)}) -> {plan.get('skip_reasons', 'غير مطلوبة لهذا الهدف')}")
        
        needed = plan.get("needed_tools", [])
        await self.log_msg(f"⚙️ [AI PLAN] الأدوات والمحركات المعتمدة للفحص: {', '.join(needed)}")

        # ── الخطوة 3: استخراج حقول الإدخال والباراميترات المستهدفة ──
        discovered_params = set(plan.get("parameters_to_audit", []))
        
        # تحليل استمارة البحث في HTML
        from bs4 import BeautifulSoup
        if html_snippet:
            soup = BeautifulSoup(html_snippet, "html.parser")
            for inp in soup.find_all(["input", "textarea"]):
                name = inp.get("name")
                if name and name.lower() not in ("submit", "button", "csrf", "_csrf", "csrf_token"):
                    discovered_params.add(name)

        parsed = urlparse(url)
        if parsed.query:
            for k in parsed.query.split("&"):
                if "=" in k:
                    discovered_params.add(k.split("=")[0])

        if not discovered_params:
            discovered_params.add("search")

        # ── الخطوة 4: تنفيذ الفحص والتحليل الذكي خطوة بخطوة ──
        base_endpoint = url.split("?")[0]
        focus = plan.get("primary_focus", "all").lower()

        from core.smart_probe_engine import SmartPoCExecutor
        prober = SmartPoCExecutor(proxy=proxy)

        for param in list(discovered_params)[:5]:
            await self.log_msg(f"🔍 [AI AUDITING PARAMETER] فحص المعامل '{param}' على {base_endpoint}...")
            
            # تحديد أنواع الفحص بناءً على قرار الذكاء الاصطناعي
            v_types = [focus] if focus in ("xss", "sqli", "idor") else ["xss", "sqli"]
            
            for vt in v_types:
                await self.log_msg(f"   -> اختبار معالجة السيرفر وترميز المخرجات لـ: '{param}' ({vt.upper()})...")
                res = await prober.execute_and_verify(target_url=base_endpoint, param_name=param, vuln_type=vt)
                
                if res.get("verified"):
                    real_vt = res.get("vuln_type", vt)
                    cvss = res.get("cvss", {})
                    reason = res.get("proof_reason", "Verified vulnerability")
                    rem = res.get("remediation", "Apply context-aware encoding.")
                    
                    await self.log_msg(f"   🔥 [AI VERIFIED {real_vt.upper()}] تم تأكيد الخلل وفهم السياق! {reason}")
                    
                    findings.append({
                        "type": f"ai_verified_{real_vt}",
                        "severity": cvss.get("severity", "High"),
                        "cvss": cvss.get("score", 7.5),
                        "title": f"🔥 ثغرة {real_vt.upper()} مؤكدة بالذكاء الاصطناعي على المعامل: {param}",
                        "evidence": f"Target: {url}\nParameter: {param}\nReasoning: {reason}",
                        "tool": "AutonomousReasoningAgent",
                        "recommendation": rem
                    })
                else:
                    await self.log_msg(f"   -> [SAFE] المعامل '{param}' آمن ضد {vt.upper()}.")

        # ── الخطوة 5: فحص هيدرز الأمان (خفيف وسريع بدون إزعاج) ──
        missing_sec_headers = []
        for sh in ["content-security-policy", "x-content-type-options", "strict-transport-security"]:
            if sh not in [k.lower() for k in headers.keys()]:
                missing_sec_headers.append(sh)
        if missing_sec_headers:
            findings.append({
                "type": "headers",
                "severity": "Low",
                "cvss": 2.5,
                "title": f"Missing Security Headers ({len(missing_sec_headers)}): {', '.join(missing_sec_headers)}",
                "evidence": f"Omitted headers: {', '.join(missing_sec_headers)}",
                "tool": "HeaderAudit",
                "recommendation": "Configure security headers to enforce CSP and MIME protections."
            })

        duration = round(time.time() - t0, 2)
        await self.log_msg(f"✅ [AI AGENT COMPLETE] اكتمل الفحص الذكي في {duration} ثانية | إجمالي الثغرات المؤكدة: {len(findings)}")

        return {
            "target": target,
            "duration": duration,
            "findings": findings,
            "plan": plan
        }
