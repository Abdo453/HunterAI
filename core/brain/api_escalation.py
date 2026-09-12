import os, asyncio, re, json, logging
from typing import Dict, Any, List, Optional, Callable
log = logging.getLogger("api_escalation")

class APIEscalationManager:
    def __init__(self, emit_fn=None):
        self.emit_fn = emit_fn

    async def _log(self, msg):
        if self.emit_fn:
            try: await self.emit_fn({"event": "log", "message": msg})
            except: pass

    async def _call_one(self, name, coro):
        try:
            r = await coro
            if r and getattr(r, "content", None):
                return {"api": name, "content": r.content}
        except Exception as e:
            log.debug(f"{name}: {e}")
        return {"api": name, "content": ""}

    async def call_all_parallel(self, prompt: str) -> List[Dict[str, str]]:
        import importlib
        tasks = []
        if os.getenv("GEMINI_API_KEY"):
            gem_model = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
            tasks.append(self._call_one("gemini", m.GeminiProvider(model=gem_model).generate(prompt)))
        if os.getenv("OPENROUTER_API_KEY"):
            m = importlib.import_module("models.api.openrouter_provider")
            tasks.append(self._call_one("openrouter", m.OpenRouterProvider().generate(prompt)))
        if os.getenv("GROQ_API_KEY"):
            m = importlib.import_module("models.api.groq_provider")
            tasks.append(self._call_one("groq", m.GroqProvider().generate(prompt)))
        if os.getenv("ANTHROPIC_API_KEY"):
            m = importlib.import_module("models.api.anthropic_provider")
            ant_model = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")
            tasks.append(self._call_one("anthropic", m.AnthropicProvider(model=ant_model).generate(prompt)))
        if not tasks:
            return []
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, dict) and r.get("content")]

    async def confidence_check(self, finding: dict, html_context: str = "") -> dict:
        prompt = (
            f"Security Finding:\n{json.dumps(finding, indent=2)}\n"
            f"HTML Context:\n{html_context[:800]}\n\n"
            'Is this a real vulnerability? Reply with ONLY JSON: '
            '{"confidence": 0.85, "is_real": true, "reasoning": "...", "action": "confirm|reject|verify"}'
        )
        results = await self.call_all_parallel(prompt)
        if not results:
            return {"consensus": 0.5, "opinions": [], "recommended_action": "verify"}
        confs = []
        for r in results:
            try:
                m = re.search(r'\{.*\}', r["content"], re.DOTALL)
                if m:
                    confs.append(float(json.loads(m.group(0)).get("confidence", 0.5)))
            except Exception:
                confs.append(0.5)
        avg = sum(confs) / len(confs) if confs else 0.5
        action = "confirm" if avg >= 0.75 else ("reject" if avg < 0.35 else "verify")
        return {"consensus": round(avg, 2), "opinions": results, "recommended_action": action}

    async def escalate_if_uncertain(self, local_result: dict, threshold: float = 0.6) -> dict:
        if local_result.get("confidence_score", 1.0) >= threshold:
            return local_result
        await self._log(f"[API ESCALATION] local confidence below {threshold:.0%} - asking cloud...")
        check = await self.confidence_check(local_result)
        local_result["api_consensus"] = check["consensus"]
        local_result["api_recommended_action"] = check["recommended_action"]
        await self._log(f"   -> Cloud consensus: {check['consensus']:.0%} - {check['recommended_action']}")
        return local_result
