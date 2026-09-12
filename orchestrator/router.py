"""
Model Router — يوجه المهام للموديلات الصح + Confidence Check تلقائي
القاعدة:
 - SECURITY  → WhiteRabbitNeo (local) → Xploiter (local) — بالتتابع
 - CODING    → Qwen (local) + Security API إن احتاج
 - MIXED     → Security plan (API) + Coding plan (Qwen) → Integrator
 
 + AUTO CONFIDENCE CHECK: لو أي موديل شاكك → كل الـ API تشتغل بالتوازي
"""
import asyncio
import logging
import os
from typing import Optional, Callable, Dict, Any

from orchestrator.task_classifier import TaskClassifier, TaskType, ClassificationResult
from orchestrator.resource_manager import ResourceManager
from models.ollama_manager import OllamaManager
from core.methodology_kb import MethodologyKB

log = logging.getLogger("router")

# System prompts لكل موديل
PROMPTS = {
    "whiterabbitneo": """You are WhiteRabbitNeo, an elite offensive security AI.
Focus on: attack surface mapping, CVE analysis, exploitation techniques, red team ops.
Be direct, technical, and thorough.
IMPORTANT: Follow standard penetration testing methodology (Subdomains -> Alive -> URL/JS discovery -> Fuzzing -> Exploit Verification).
If you are NOT SURE about something, explicitly say "I am not certain" or "This needs verification".""",

    "xploiter": """You are an expert penetration tester with 10+ years experience.
Your job: validate and cross-check security findings, suggest concrete attack paths and specific tool chains,
prioritize vulnerabilities by exploitability and impact. Be precise.
IMPORTANT: If you are NOT SURE about a finding, say "Possible but unconfirmed" or "Needs verification".""",

    "qwen": """You are an elite software engineer and code analyst.
Write clean, working code. When you encounter security questions you can't fully answer,
say 'NEEDS_SECURITY_CONSULTATION' and explain what security knowledge is needed.""",
}


class ModelRouter:
    """
    الـ Router — يقرر:
    1. نوع المهمة (classifier)
    2. أي موديلات تُستخدم وبأي ترتيب
    3. هل نحتاج API خارجي بدل موديل محلي ثانٍ
    4. كيف نجمع النتائج
    5. AUTO: لو الموديل شاكك → يفعّل Confidence Check Protocol
    6. ربط قاعدة المعرفة والمنهجيات (Methodology KB)
    """

    def __init__(self, resource_manager: ResourceManager, progress_cb: Optional[Callable] = None):
        self.rm = resource_manager
        self.classifier = TaskClassifier()
        self.cb = progress_cb
        self.kb = MethodologyKB()
        # Lazy-load confidence checker
        self._confidence_checker = None

    def _get_confidence_checker(self):
        if self._confidence_checker is None:
            from core.confidence_checker import ConfidenceChecker
            self._confidence_checker = ConfidenceChecker(progress_cb=self.cb)
        return self._confidence_checker

    async def _emit(self, event: str, data: dict):
        if self.cb:
            try:
                await self.cb({"event": event, **data})
            except Exception:
                pass

    async def _check_and_verify(self, model_response: str, target: str, claim: str) -> str:
        """
        تحقق هل الموديل شاكك → فعّل Confidence Check تلقائياً
        """
        checker = self._get_confidence_checker()
        uncertain, pattern = checker.is_uncertain(model_response)

        if uncertain:
            await self._emit("uncertainty_detected", {
                "pattern": pattern,
                "message": "Model expressed uncertainty — triggering Confidence Check Protocol",
                "target": target,
            })

            result = await checker.verify(
                claim=claim,
                target=target,
                context=model_response[:500],
                use_browser=os.getenv("USE_BROWSER_VERIFY", "false").lower() == "true",
            )

            report = checker.format_report(result)
            return f"{model_response}\n\n{'='*50}\n🔍 CONFIDENCE CHECK PROTOCOL\n{report}"

        return model_response

    # ────────────────────────────────────────────────────────────
    # PUBLIC API
    # ────────────────────────────────────────────────────────────

    async def route(self, user_input: str, context: str = "") -> Dict[str, Any]:
        """
        نقطة الدخول الرئيسية
        يصنف المهمة ويوجهها للمسار الصح
        """
        # تصنيف المهمة
        classification = self.classifier.classify(user_input, context)
        log.info(f"[ROUTER] Task={classification.task_type} | Confidence={classification.confidence:.2f}")

        await self._emit("task_classified", {
            "task_type": classification.task_type.value,
            "confidence": round(classification.confidence, 2),
            "reasoning": classification.reasoning,
            "models": classification.suggested_models,
        })

        # توجيه حسب النوع
        if classification.task_type == TaskType.SECURITY:
            return await self._security_route(user_input, context, classification)
        elif classification.task_type == TaskType.CODING:
            return await self._coding_route(user_input, context, classification)
        elif classification.task_type == TaskType.MIXED:
            return await self._mixed_route(user_input, context, classification)
        else:
            return await self._general_route(user_input, context)

    # ────────────────────────────────────────────────────────────
    # SECURITY ROUTE
    # WhiteRabbitNeo → UNLOAD → Xploiter → UNLOAD → Answer
    # ────────────────────────────────────────────────────────────

    async def _security_route(self, prompt: str, ctx: str, cl: ClassificationResult) -> Dict[str, Any]:
        await self._emit("route_start", {"route": "SECURITY"})

        results = {}

        # ── Step 1: WhiteRabbitNeo ──
        await self._emit("step", {"step": 1, "model": "WhiteRabbitNeo", "action": "Security Analysis"})

        methodology_ctx = self.kb.format_methodology_context_for_ai()
        wrn_messages = [
            {"role": "system", "content": f"{PROMPTS['whiterabbitneo']}\n\n{methodology_ctx}"},
            {"role": "user", "content": f"Context: {ctx}\n\nTask: {prompt}"}
        ]

        wrn_result = await self.rm.run_local_model(
            model_name="WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest",
            messages=wrn_messages,
            temperature=0.3,
            progress_cb=self.cb
        )

        # AUTO: تحقق من اليقين — لو شاكك → كل الـ API تشتغل
        wrn_result = await self._check_and_verify(wrn_result, target=prompt[:50], claim=wrn_result[:300])
        results["whiterabbitneo"] = wrn_result

        await self._emit("step_done", {
            "step": 1,
            "model": "WhiteRabbitNeo",
            "chars": len(wrn_result),
            "note": "GPU freed — loading Xploiter next"
        })

        # ── Step 2: Xploiter (يرى نتيجة WhiteRabbitNeo) ──
        await self._emit("step", {"step": 2, "model": "Xploiter", "action": "Cross-check + Attack Paths"})

        xploiter_messages = [
            {"role": "system", "content": PROMPTS["xploiter"]},
            {"role": "user", "content": (
                f"Original task: {prompt}\n\n"
                f"WhiteRabbitNeo's analysis:\n{wrn_result[:800]}\n\n"
                f"Cross-check this analysis. What attack paths were missed? "
                f"Prioritize by exploitability. Provide final consolidated findings."
            )}
        ]

        xploiter_result = await self.rm.run_local_model(
            model_name="xploiter/pentester:latest",
            messages=xploiter_messages,
            temperature=0.4,
            progress_cb=self.cb
        )

        # AUTO: تحقق من اليقين بعد Xploiter كمان
        xploiter_result = await self._check_and_verify(xploiter_result, target=prompt[:50], claim=xploiter_result[:300])
        results["xploiter"] = xploiter_result

        await self._emit("step_done", {
            "step": 2,
            "model": "Xploiter",
            "chars": len(xploiter_result),
            "note": "GPU freed — all done"
        })

        # ── Final: تجميع النتيجتين ──

        if not results.get("whiterabbitneo") and not results.get("xploiter"):
            # Fallback to active online API if local models returned empty (e.g. Ollama offline)
            cloud_res = await self._call_security_api(ctx, prompt)
            if cloud_res and "No external security API" not in cloud_res:
                final = f"# Security Analysis (Cloud AI Online Mode)\n\n{cloud_res}"
                results["final"] = final
                await self._emit("route_done", {"route": "SECURITY_CLOUD", "models_used": 1})
                return {"route": "SECURITY_CLOUD", "results": results, "final": final}

        final = self._merge_security(results["whiterabbitneo"], results["xploiter"])
        results["final"] = final

        await self._emit("route_done", {"route": "SECURITY", "models_used": 2})
        return {"route": "SECURITY", "results": results, "final": final}


    # ────────────────────────────────────────────────────────────
    # CODING ROUTE
    # Qwen (local) → إذا احتاج security → API → Qwen يكمل
    # ────────────────────────────────────────────────────────────

    async def _coding_route(self, prompt: str, ctx: str, cl: ClassificationResult) -> Dict[str, Any]:
        await self._emit("route_start", {"route": "CODING"})
        results = {}

        # ── Step 1: Qwen يبدأ ──
        await self._emit("step", {"step": 1, "model": "Qwen", "action": "Code Generation"})

        qwen_messages = [
            {"role": "system", "content": PROMPTS["qwen"]},
            {"role": "user", "content": f"Context: {ctx}\n\nTask: {prompt}"}
        ]

        qwen_result = await self.rm.run_local_model(
            model_name="qwen2.5-coder:14b",
            messages=qwen_messages,
            temperature=0.2,
            num_ctx=8192,
            progress_cb=self.cb
        )
        results["qwen_initial"] = qwen_result

        await self._emit("step_done", {"step": 1, "model": "Qwen", "chars": len(qwen_result)})

        # ── تحقق هل Qwen طلب استشارة أمنية ──
        needs_security = "NEEDS_SECURITY_CONSULTATION" in qwen_result

        if needs_security:
            await self._emit("step", {
                "step": 2,
                "model": "Security API",
                "action": "Security consultation (no local GPU needed)"
            })

            # استدعاء API خارجي بدل موديل محلي
            security_advice = await self._call_security_api(qwen_result, prompt)
            results["security_consultation"] = security_advice

            await self._emit("step_done", {"step": 2, "model": "API", "chars": len(security_advice)})

            # ── Qwen يكمل مع الاستشارة ──
            await self._emit("step", {"step": 3, "model": "Qwen", "action": "Final Code with Security"})

            qwen_final_messages = [
                {"role": "system", "content": PROMPTS["qwen"]},
                {"role": "user", "content": (
                    f"Original task: {prompt}\n\n"
                    f"Your initial code:\n{qwen_result[:600]}\n\n"
                    f"Security consultation received:\n{security_advice[:400]}\n\n"
                    f"Now complete the implementation with security considerations applied."
                )}
            ]

            qwen_final = await self.rm.run_local_model(
                model_name="qwen2.5-coder:14b",
                messages=qwen_final_messages,
                temperature=0.2,
                num_ctx=8192,
                progress_cb=self.cb
            )
            results["qwen_final"] = qwen_final
            final = qwen_final
        else:
            final = qwen_result

        results["final"] = final
        await self._emit("route_done", {"route": "CODING", "security_consulted": needs_security})
        return {"route": "CODING", "results": results, "final": final}

    # ────────────────────────────────────────────────────────────
    # MIXED ROUTE
    # Security plan (API) + Coding (Qwen local) → Integrate
    # ────────────────────────────────────────────────────────────

    async def _mixed_route(self, prompt: str, ctx: str, cl: ClassificationResult) -> Dict[str, Any]:
        await self._emit("route_start", {"route": "MIXED"})
        results = {}

        # API + Local run بالتوازي (API لا يحتاج GPU)
        await self._emit("step", {
            "step": 1,
            "action": "Parallel: Security API + Qwen local",
            "note": "API runs simultaneously with Qwen (no GPU conflict)"
        })

        sec_api_task = asyncio.create_task(
            self._call_security_api("", f"Provide security requirements for: {prompt}")
        )

        qwen_task = asyncio.create_task(
            self.rm.run_local_model(
                model_name="qwen2.5-coder:14b",
                messages=[
                    {"role": "system", "content": PROMPTS["qwen"]},
                    {"role": "user", "content": f"Task: {prompt}\n\nFocus on the coding/implementation aspect."}
                ],
                temperature=0.2,
                num_ctx=8192,
                progress_cb=self.cb
            )
        )

        # Qwen يحتاج GPU — sec_api بدون GPU
        # لو Qwen لسه شغال، API ينتظر النتيجة بس
        sec_result, qwen_result = await asyncio.gather(sec_api_task, qwen_task)

        results["security_plan"] = sec_result
        results["coding_result"] = qwen_result

        await self._emit("step_done", {
            "step": 1,
            "security_chars": len(sec_result),
            "coding_chars": len(qwen_result)
        })

        # ── Integration ──
        await self._emit("step", {"step": 2, "action": "Integration"})
        final = self._integrate_mixed(prompt, sec_result, qwen_result)
        results["final"] = final

        await self._emit("route_done", {"route": "MIXED"})
        return {"route": "MIXED", "results": results, "final": final}

    # ────────────────────────────────────────────────────────────
    # GENERAL ROUTE
    # ────────────────────────────────────────────────────────────

    async def _general_route(self, prompt: str, ctx: str) -> Dict[str, Any]:
        await self._emit("route_start", {"route": "GENERAL"})

        result = await self.rm.run_local_model(
            model_name="qwen2.5-coder:14b",
            messages=[
                {"role": "system", "content": "You are a helpful AI assistant."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.5,
            progress_cb=self.cb
        )

        await self._emit("route_done", {"route": "GENERAL"})
        return {"route": "GENERAL", "results": {"response": result}, "final": result}

    # ────────────────────────────────────────────────────────────
    # HELPERS
    # ────────────────────────────────────────────────────────────

    async def _call_security_api(self, code_context: str, prompt: str) -> str:
        """
        استدعاء API خارجي للاستشارات الأمنية
        بدون استخدام GPU المحلي
        """
        # 1. Gemini
        gemini_key = os.getenv("GEMINI_API_KEY")
        if gemini_key:
            from models.api.gemini_provider import GeminiProvider
            try:
                gm = GeminiProvider(model="gemini-2.5-flash")
                resp = await gm.generate(f"Context:\n{code_context}\n\nTask: {prompt}", system_prompt="You are an expert security consultant.")
                if resp and resp.content:
                    return resp.content
            except Exception as e:
                log.warning(f"Gemini API call failed: {e}")

        # 2. حاول Groq أولاً (مجاني وسريع)
        groq_key = os.getenv("GROQ_API_KEY")
        if groq_key:
            return await self._groq_call(prompt, code_context)

        # 3. ثم OpenRouter
        openrouter_key = os.getenv("OPENROUTER_API_KEY")
        if openrouter_key:
            return await self._openrouter_call(prompt, code_context)

        # 4. ثم OpenAI
        openai_key = os.getenv("OPENAI_API_KEY")
        if openai_key:
            return await self._openai_call(prompt, code_context)

        # Fallback — لا يوجد API
        return (
            "No external security API available. "
            "Add GEMINI_API_KEY, GROQ_API_KEY, or OPENAI_API_KEY to .env for security consultations."
        )


    async def _groq_call(self, prompt: str, context: str) -> str:
        import httpx
        key = os.getenv("GROQ_API_KEY")
        try:
            async with httpx.AsyncClient(timeout=30) as c:
                r = await c.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers={"Authorization": f"Bearer {key}"},
                    json={
                        "model": "llama-3.3-70b-versatile",
                        "messages": [
                            {"role": "system", "content": "You are an expert security consultant."},
                            {"role": "user", "content": f"Context:\n{context}\n\nQuestion: {prompt}"}
                        ],
                        "max_tokens": 1000
                    }
                )
                return r.json()["choices"][0]["message"]["content"]
        except Exception as e:
            return f"Groq API error: {e}"

    async def _openrouter_call(self, prompt: str, context: str) -> str:
        import httpx
        key = os.getenv("OPENROUTER_API_KEY")
        try:
            async with httpx.AsyncClient(timeout=30) as c:
                r = await c.post(
                    "https://openrouter.ai/api/v1/chat/completions",
                    headers={"Authorization": f"Bearer {key}"},
                    json={
                        "model": "anthropic/claude-3-haiku",
                        "messages": [
                            {"role": "system", "content": "You are an expert security consultant."},
                            {"role": "user", "content": f"Context:\n{context}\n\nQuestion: {prompt}"}
                        ]
                    }
                )
                return r.json()["choices"][0]["message"]["content"]
        except Exception as e:
            return f"OpenRouter API error: {e}"

    async def _openai_call(self, prompt: str, context: str) -> str:
        import httpx
        key = os.getenv("OPENAI_API_KEY")
        try:
            async with httpx.AsyncClient(timeout=30) as c:
                r = await c.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {key}"},
                    json={
                        "model": "gpt-4o-mini",
                        "messages": [
                            {"role": "system", "content": "You are an expert security consultant."},
                            {"role": "user", "content": f"Context:\n{context}\n\nQuestion: {prompt}"}
                        ]
                    }
                )
                return r.json()["choices"][0]["message"]["content"]
        except Exception as e:
            return f"OpenAI API error: {e}"

    def _merge_security(self, wrn: str, xploiter: str) -> str:
        return (
            f"# Security Analysis Report\n\n"
            f"## WhiteRabbitNeo Analysis\n{wrn}\n\n"
            f"---\n\n"
            f"## Xploiter Cross-Check & Attack Paths\n{xploiter}"
        )

    def _integrate_mixed(self, prompt: str, security: str, coding: str) -> str:
        return (
            f"# Integrated Result\n\n"
            f"**Task:** {prompt}\n\n"
            f"## Security Requirements\n{security}\n\n"
            f"---\n\n"
            f"## Implementation\n{coding}"
        )
