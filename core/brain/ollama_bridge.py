"""
╔══════════════════════════════════════════════════════════════════════════╗
║          OLLAMA BRIDGE — ربط الـ Brain بالـ OllamaManager الموجود       ║
║                                                                          ║
║  يستخدم OllamaManager الحالي في المشروع مباشرة                          ║
║  مع Dual-Model Strategy:                                                 ║
║    • qwen2.5-coder:14b-tools → التخطيط + tool calling                  ║
║    • xploiter/pentester      → تحليل الثغرات الأمني                     ║
║    • qwen3:8b                → التفكير المنطقي                           ║
║    • qwen2.5-coder:14b       → كتابة الـ PoC code                       ║
╚══════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Dual-model strategy — كل دور له النموذج الأنسب
DUAL_MODEL_MAP: Dict[str, str] = {
    "planner":  "qwen2.5-coder:14b",         # يخطط + tool calling
    "analyst":  "xploiter/pentester:latest",   # تحليل أمني متخصص
    "reasoner": "qwen3:8b",                    # تفكير منطقي عميق
    "coder":    "qwen2.5-coder:14b",           # كتابة كود + PoC
}


class OllamaBridge:
    """
    جسر موحد بين world_elite_react_loop و OllamaManager الموجود.
    يوفر نفس واجهة OllamaProvider لكن يستخدم البنية الحالية للمشروع.
    """

    def __init__(self, host: str = "http://localhost:11434"):
        self.host = host
        self._manager = None

    def _get_manager(self):
        """Lazy init للـ OllamaManager"""
        if self._manager is None:
            try:
                import sys, os
                # تأكد من وجود مسار المشروع
                project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
                if project_root not in sys.path:
                    sys.path.insert(0, project_root)

                from models.ollama_manager import OllamaManager
                self._manager = OllamaManager(host=self.host)
                logger.info("✅ OllamaBridge → OllamaManager connected at %s", self.host)
            except Exception as exc:
                logger.warning("OllamaManager unavailable: %s — using HTTP fallback", exc)
                self._manager = _HttpFallbackManager(host=self.host)
        return self._manager

    async def chat(
        self,
        messages: List[Dict[str, str]],
        role: str = "planner",
        temperature: float = 0.3,
        num_ctx: int = 4096,
    ) -> str:
        """
        يرسل رسالة للـ LLM ويرجع الرد كـ string.
        يختار النموذج تلقائياً حسب الـ role.
        """
        model = DUAL_MODEL_MAP.get(role, DUAL_MODEL_MAP["planner"])
        manager = self._get_manager()

        try:
            response = await manager.chat(
                model_name=model,
                messages=messages,
                temperature=temperature,
                num_ctx=num_ctx,
            )
            logger.debug("🤖 [%s/%s] → %s chars", role, model, len(str(response)))
            return str(response)
        except Exception as exc:
            logger.error("OllamaBridge.chat error [%s]: %s", model, exc)
            return f"[LLM_ERROR] {exc}"

    async def think_and_plan(
        self,
        context: str,
        available_tools: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        يفكر في الوضع الحالي ويخطط الخطوة التالية.
        يستخدم qwen2.5-coder:14b-tools للـ tool-calling.
        """
        tools_str = ", ".join(available_tools or []) or "port_scanner, nuclei_scan, web_crawler"
        prompt = f"""
You are a world-class penetration testing agent. Analyze the current state and decide the next optimal action.

{context}

Available tools: {tools_str}

Respond ONLY with valid JSON:
{{
  "type": "RECON|HYPOTHESIS|EXPLOITATION|VERIFICATION|REPORTING",
  "content": "what you think and why",
  "confidence": 0.0-1.0,
  "reasoning": "step by step reasoning",
  "suggested_tools": ["tool1", "tool2"]
}}
"""
        raw = await self.chat(
            messages=[{"role": "user", "content": prompt}],
            role="planner",
            temperature=0.2,
        )

        # استخراج JSON
        try:
            start = raw.find("{")
            end = raw.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(raw[start:end])
        except json.JSONDecodeError:
            pass

        return {
            "type": "RECON",
            "content": raw[:300],
            "confidence": 0.4,
            "reasoning": "Could not parse structured response",
            "suggested_tools": ["port_scanner"],
        }

    async def analyze_finding(
        self,
        finding: str,
        context: str = "",
    ) -> Dict[str, Any]:
        """
        يحلل finding ويقرر إذا كان حقيقي.
        يستخدم xploiter/pentester للتحليل الأمني المتخصص.
        """
        prompt = f"""
You are an expert security analyst specializing in vulnerability validation.
Analyze this finding and determine if it is a real vulnerability or a false positive.

FINDING:
{finding}

CONTEXT:
{context}

Respond ONLY with valid JSON:
{{
  "is_real": true/false,
  "confidence": 0.0-1.0,
  "severity": "critical/high/medium/low/info",
  "cvss_estimate": 0.0-10.0,
  "false_positive_reason": "reason if FP, else empty",
  "poc_recommended": true/false,
  "recommended_next_steps": ["step1", "step2"]
}}
"""
        raw = await self.chat(
            messages=[{"role": "user", "content": prompt}],
            role="analyst",
            temperature=0.1,
        )

        try:
            start = raw.find("{")
            end = raw.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(raw[start:end])
        except json.JSONDecodeError:
            pass

        return {
            "is_real": False,
            "confidence": 0.0,
            "severity": "info",
            "cvss_estimate": 0.0,
            "false_positive_reason": "LLM parse error",
            "poc_recommended": False,
            "recommended_next_steps": [],
        }

    async def generate_poc(self, vulnerability: Dict[str, Any]) -> str:
        """
        يولد PoC Python code للثغرة.
        يستخدم qwen2.5-coder:14b للكود الدقيق.
        للأغراض التعليمية فقط — على أهداف مصرح بها.
        """
        prompt = f"""
You are a security researcher writing educational proof-of-concept code.
Write a Python PoC to verify (NOT exploit destructively) this vulnerability on authorized targets only:

{json.dumps(vulnerability, indent=2, ensure_ascii=False)}

Requirements:
- Pure Python, no external exploits
- Only verify vulnerability existence
- Include safety check at the start
- Add clear comments explaining each step
- Output: working Python code only
"""
        return await self.chat(
            messages=[{"role": "user", "content": prompt}],
            role="coder",
            temperature=0.2,
            num_ctx=8192,
        )

    async def list_available_models(self) -> List[str]:
        """يرجع قائمة النماذج المتاحة"""
        manager = self._get_manager()
        try:
            return list(await manager.list_available() or [])
        except Exception:
            return list(DUAL_MODEL_MAP.values())


# ─────────────────────────────────────────────────────────────────────────────
# HTTP FALLBACK — مباشر بدون مكتبة ollama
# ─────────────────────────────────────────────────────────────────────────────

class _HttpFallbackManager:
    """HTTP fallback مباشر لـ Ollama API بدون أي مكتبة"""

    def __init__(self, host: str = "http://localhost:11434"):
        self.host = host.rstrip("/")

    async def chat(
        self,
        model_name: str,
        messages: List[Dict],
        temperature: float = 0.3,
        num_ctx: int = 4096,
        **_,
    ) -> str:
        import urllib.request
        payload = json.dumps({
            "model": model_name,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_ctx": num_ctx,
            },
        }).encode("utf-8")

        req = urllib.request.Request(
            f"{self.host}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        loop = asyncio.get_running_loop()
        response = await loop.run_in_executor(
            None,
            lambda: urllib.request.urlopen(req, timeout=120).read().decode("utf-8"),
        )
        data = json.loads(response)
        return data.get("message", {}).get("content", "")

    async def list_available(self) -> List[str]:
        import urllib.request
        loop = asyncio.get_running_loop()
        raw = await loop.run_in_executor(
            None,
            lambda: urllib.request.urlopen(
                f"{self.host}/api/tags", timeout=5
            ).read().decode("utf-8"),
        )
        data = json.loads(raw)
        return [m["name"] for m in data.get("models", [])]
