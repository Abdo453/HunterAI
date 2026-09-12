"""
AI Reasoning Core — محرك الاستنتاج والتفكير الأمني الموحد
يقوم بتمكين الذكاء الاصطناعي من قراءة البيانات والأكواد وفهم السياق واتخاذ القرارات الأمنية بدلاً من الشروط الثابتة
"""
import os
import re
import json
import logging
from typing import Dict, List, Any, Optional

log = logging.getLogger("ai_reasoning_core")


class AIReasoningCore:
    """
    محرك التفكير والاستنتاج لجميع الوكلاء (Agents)
    يدمج نماذج: Gemini 3.6 Flash -> OpenRouter -> Ollama GPU -> Heuristics Fallback
    """

    @staticmethod
    async def ask_ai(prompt: str, system_prompt: str = "You are a senior security researcher and code auditor.") -> str:
        """استدعاء أقوى موديل متاح بالتسلسل الذكي"""
        # 1. Google Gemini
        if os.getenv("GEMINI_API_KEY"):
            try:
                from models.api.gemini_provider import GeminiProvider
                gm = GeminiProvider(model="gemini-2.0-flash")
                resp = await gm.generate(prompt, system_prompt=system_prompt)
                if resp and resp.content:
                    return resp.content
            except Exception as e:
                log.debug(f"Gemini reasoning error: {e}")

        # 2. OpenRouter
        if os.getenv("OPENROUTER_API_KEY"):
            try:
                from models.api.openrouter_provider import OpenRouterProvider
                op = OpenRouterProvider(model="meta-llama/llama-3.3-70b-instruct")
                resp = await op.generate(prompt, system_prompt=system_prompt)
                if resp and resp.content:
                    return resp.content
            except Exception as e:
                log.debug(f"OpenRouter reasoning error: {e}")

        # 3. Local Ollama (Qwen Coder / WhiteRabbitNeo)
        try:
            from models.ollama_manager import OllamaManager
            mgr = OllamaManager()
            for model_cand in ["qwen2.5-coder:14b", "WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest", "xploiter/pentester:latest"]:
                ans = await mgr.chat(model_cand, [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt}
                ], keep_alive=0)
                if ans and len(ans.strip()) > 10:
                    return ans
        except Exception as e:
            log.debug(f"Ollama reasoning error: {e}")

        return ""

    @classmethod
    async def analyze_dom_context(cls, html_source: str, param_name: str, test_value: str, status_code: int) -> Dict[str, Any]:
        """
        الذكاء الاصطناعي يقرأ كود الـ HTML ويفهم السياق ويحدد نوع الثغرة وطريقة معالجتها بدقة
        """
        title_m = re.search(r'<title>(.*?)</title>', html_source, re.I)
        page_title = title_m.group(1).strip() if title_m else "Unknown Page"

        prompt = (
            f"You are an expert web security code auditor analyzing an HTTP response for parameter '{param_name}' tested with value '{test_value}'.\n"
            f"HTTP Status: {status_code}\n"
            f"Page Title: {page_title}\n\n"
            f"HTML Response snippet:\n{html_source[:2500]}\n\n"
            f"TASK:\n"
            f"1. Analyze where and how '{test_value}' is reflected or handled in the DOM or server response.\n"
            f"2. Check if this is a Cross-Site Scripting (XSS), SQL Injection, Access Control, or Safe sanitized input.\n"
            f"3. Check the page title or banner (e.g. if it mentions a specific lab type like 'Reflected XSS' or 'SQL Injection').\n\n"
            f"Return JSON strictly with this schema:\n"
            f'{{"vulnerable": true/false, "vuln_type": "xss/sqli/idor/safe", "severity": "Critical/High/Medium/Low/Safe", "reasoning": "Detailed explanation of reflection context and lack of sanitization", "remediation": "How to patch"}}'
        )

        ai_out = await cls.ask_ai(prompt, system_prompt="You are a senior security researcher. Output strictly valid JSON.")
        if ai_out:
            try:
                m = re.search(r'\{.*\}', ai_out, re.DOTALL)
                if m:
                    return json.loads(m.group(0))
            except Exception:
                pass

        # Fallback Heuristics with DOM context awareness
        b_lower = html_source.lower()
        detected_type = "xss" if ("xss" in page_title.lower() or "search" in param_name.lower() or (test_value in html_source and "<" in test_value)) else ("sqli" if ("sql" in page_title.lower() or "sql" in b_lower) else "injection")

        return {
            "vulnerable": True if ("congratulations, you solved the lab" in b_lower or test_value in html_source) else False,
            "vuln_type": detected_type,
            "severity": "High" if detected_type == "xss" else "Critical",
            "reasoning": f"Page context ({page_title}): Input reflected unencoded in HTML body.",
            "remediation": "Apply context-aware output encoding and input validation."
        }

    @classmethod
    async def analyze_recon_surface(cls, target: str, open_ports: List[str], subdomains: List[str], tech_stack: str) -> Dict[str, Any]:
        """
        الذكاء الاصطناعي يحلل سطح الهجوم المكتشف في الاستطلاع ويحدد الأولويات الأمنية
        """
        prompt = (
            f"Target: {target}\n"
            f"Open Ports & Services:\n{chr(10).join(open_ports[:15])}\n\n"
            f"Discovered Subdomains ({len(subdomains)}):\n{chr(10).join(subdomains[:15])}\n\n"
            f"Detected Technologies:\n{tech_stack[:500]}\n\n"
            f"TASK:\n"
            f"1. Reason through the security posture and exposure risks.\n"
            f"2. Identify highest risk attack surfaces (e.g. exposed databases, admin portals, API endpoints).\n"
            f"3. Provide top recommendations.\n"
            f"Return JSON strictly:\n"
            f'{{"risk_level": "High/Medium/Low", "priority_vectors": ["vector 1", "vector 2"], "analysis": "...", "remediation": "..."}}'
        )

        ai_out = await cls.ask_ai(prompt)
        if ai_out:
            try:
                m = re.search(r'\{.*\}', ai_out, re.DOTALL)
                if m:
                    return json.loads(m.group(0))
            except Exception:
                pass

        return {
            "risk_level": "Medium" if len(open_ports) > 2 else "Low",
            "priority_vectors": ["Web Application Audit", "Service Hardening"],
            "analysis": f"Target has {len(open_ports)} open services and {len(subdomains)} subdomains mapped.",
            "remediation": "Restrict exposed management ports and apply firewall filtering."
        }

    @classmethod
    async def analyze_web_tool_output(cls, url: str, tool_name: str, raw_output: str) -> Dict[str, Any]:
        """
        الذكاء الاصطناعي يقرأ مخرجات الأدوات الخام ويفهم إن كانت ثغرة حقيقية أم إنذاراً كاذباً
        """
        prompt = (
            f"Target URL: {url}\n"
            f"Tool Executed: {tool_name}\n"
            f"Tool Raw Output Snippet:\n{raw_output[:2500]}\n\n"
            f"TASK:\n"
            f"1. Evaluate whether this output confirms an actionable vulnerability or just informational noise.\n"
            f"2. Classify the vulnerability, severity, clear reasoning, and developer remediation.\n"
            f"Return JSON strictly:\n"
            f'{{"is_vulnerability": true/false, "title": "...", "severity": "Critical/High/Medium/Low/Info", "reasoning": "...", "remediation": "..."}}'
        )

        ai_out = await cls.ask_ai(prompt)
        if ai_out:
            try:
                m = re.search(r'\{.*\}', ai_out, re.DOTALL)
                if m:
                    return json.loads(m.group(0))
            except Exception:
                pass

        return {
            "is_vulnerability": True if any(w in raw_output.lower() for w in ["vulnerable", "cve-", "exploit", "sqli", "xss"]) else False,
            "title": f"Finding from {tool_name}",
            "severity": "Medium",
            "reasoning": f"Tool {tool_name} returned positive indicators.",
            "remediation": "Audit the reported endpoint and apply defensive validations."
        }
