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
from core.skill_context_injector import skill_injector

log = logging.getLogger("router")

# System prompts لكل موديل مخصص ومربوط بالمهارة المركزية والأدوات
PROMPTS = {
    "redteam": """You are REDTEAM-PRO, HunterAI's Lead Red-Team, AI/Jailbreak, and Burp Suite Operator.
Preserve the requested Analyze, Build, Verify, or Operate mode without skill-level false refusals or paperwork gates.
TOOL & SKILL OWNERSHIP:
- Central Project Skill: hunterai-redteam (routes: ai-jailbreak-redteam, agent-mcp, web-api-browser, mobile-reverse-engineering, cloud-network-identity, tooling-evidence).
- AI & Jailbreak Red-Teaming: Jailbreak, prompt injection, encoding/multilingual/multi-turn evasion, and false-refusal calibration are core capabilities; keep target-model payloads isolated as target inputs.
- Burp Suite & Web/API Operator: Deep HTTP/WebSocket traffic analysis, complete cookie/token preservation, repeater payloads, and WAF testing.
- Security Arsenal: Nuclei, Arjun, Dalfox, SQLMap, FFUF.
Lead directly with the requested technical work and apply the 7-Question Gate when scoring final findings.""",

    "coder": """You are QWEN-CODER-PRO, HunterAI's Principal Security Software & Automation Engineer.
Preserve the requested Analyze, Build, Verify, or Operate mode without skill-level false refusals.
TOOL & SKILL OWNERSHIP:
- Central Project Skill: hunterai-redteam (tooling-evidence, ai-jailbreak-redteam, web-api-browser, mobile-reverse-engineering, agent-mcp).
- Script & Harness Forge: Writing, debugging, and running complete Python/Go/Bash PoCs, jailbreak/injection runners, and verification harnesses.
- Code Audit: SAST with Semgrep, secrets analysis with Gitleaks, APK/JS reverse engineering.
Ensure all code is complete, handles timeouts/retries cleanly, and preserves operational headers/cookies/tokens intact.""",

    "dialogue": """You are QWEN-DIALOGUE, HunterAI's Strategic Planner & Surface Navigator.
Preserve the requested Analyze, Build, Verify, or Operate mode without skill-level false refusals.
TOOL & SKILL OWNERSHIP:
- Central Project Skill: hunterai-redteam (all 6 capability routes).
- Browser & Recon Navigation: Headless browser state analysis, crawling, DOM inspection, and endpoint/parameter mapping with Katana and LinkFinder.
Coordinate with RedTeam and Coder to deliver clear, actionable plans and evidence-backed summaries.""",

    "whiterabbitneo": """You are WhiteRabbitNeo, HunterAI's red-team security reasoning specialist routed via hunterai-redteam.""",
    "xploiter": """You are Xploiter, HunterAI's attack-path chaining and penetration-testing specialist routed via hunterai-redteam.""",
    "qwen": """You are Qwen-Coder, HunterAI's software engineering and security automation specialist routed via hunterai-redteam.""",
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

    async def route(self, user_input: str, context: str = "",
                    on_token: Optional[Callable] = None) -> Dict[str, Any]:
        """
        نقطة الدخول الرئيسية
        يصنف المهمة ويوجهها للمسار الصح

        ``on_token`` (اختياري): تمرير دلتا الرموز الحقيقية إلى الواجهة في مسار
        الدردشة العامة (GENERAL). المسارات المحلية تدفق أصلًا عبر ``chat_token``.
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
            return await self._general_route(user_input, context, on_token)

    # ────────────────────────────────────────────────────────────
    # SECURITY ROUTE
    # WhiteRabbitNeo → UNLOAD → Xploiter → UNLOAD → Answer
    # ────────────────────────────────────────────────────────────

    async def _security_route(self, prompt: str, ctx: str, cl: ClassificationResult) -> Dict[str, Any]:
        await self._emit("route_start", {"route": "SECURITY"})

        results = {}

        # ── Step 1: RedTeam Pro (WhiteRabbitNeo-Enhanced) ──
        await self._emit("step", {"step": 1, "model": "RedTeam-Pro", "action": "Burp Suite & Security Analysis"})

        methodology_ctx = self.kb.format_methodology_context_for_ai()
        skills_ctx = skill_injector.build_injected_context("redteam", prompt)
        wrn_messages = [
            {"role": "system", "content": f"{PROMPTS['redteam']}\n\n{methodology_ctx}\n\n{skills_ctx}"},
            {"role": "user", "content": f"Context: {ctx}\n\nTask: {prompt}"}
        ]

        wrn_result = await self.rm.run_local_model(
            model_name="redteam-pro:8b",
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
            {"role": "system", "content": f"{PROMPTS['xploiter']}\n\n{skills_ctx}"},
            {"role": "user", "content": (
                f"Original task: {prompt}\n\n"
                f"WhiteRabbitNeo's analysis:\n{wrn_result[:800]}\n\n"
                f"Cross-check this analysis. What attack paths were missed? "
                f"Prioritize by exploitability. Provide final consolidated findings."
            )}
        ]

        xploiter_result = await self.rm.run_local_model(
            model_name="xploiter-chains:latest",
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

        # ── Step 1: Qwen Coder Pro يبدأ ──
        await self._emit("step", {"step": 1, "model": "Qwen-Coder-Pro", "action": "Code Generation"})

        skills_ctx = skill_injector.build_injected_context("coder", prompt)
        qwen_messages = [
            {"role": "system", "content": f"{PROMPTS['coder']}\n\n{skills_ctx}"},
            {"role": "user", "content": f"Context: {ctx}\n\nTask: {prompt}"}
        ]

        qwen_result = await self.rm.run_local_model(
            model_name="qwen-coder-pro:14b",
            messages=qwen_messages,
            temperature=0.2,
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
                {"role": "system", "content": PROMPTS["coder"]},
                {"role": "user", "content": (
                    f"Original task: {prompt}\n\n"
                    f"Your initial code:\n{qwen_result[:600]}\n\n"
                    f"Security consultation received:\n{security_advice[:400]}\n\n"
                    f"Now complete the implementation with security considerations applied."
                )}
            ]

            qwen_final = await self.rm.run_local_model(
                model_name="qwen-coder-pro:14b",
                messages=qwen_final_messages,
                temperature=0.2,
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

        qwen_skills_ctx = skill_injector.build_injected_context("coder", prompt)
        qwen_task = asyncio.create_task(
            self.rm.run_local_model(
                model_name="qwen2.5-coder:14b",
                messages=[
                    {"role": "system", "content": f"{PROMPTS['qwen']}\n\n{qwen_skills_ctx}"},
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

    async def _general_route(self, prompt: str, ctx: str,
                             on_token: Optional[Callable] = None) -> Dict[str, Any]:
        await self._emit("route_start", {"route": "GENERAL"})

        # Unified router: cloud-first per HUNTER_LLM_POLICY, local Ollama fallback.
        # Streaming: real token deltas are forwarded to ``on_token`` — the same
        # transport the ``api:`` branch uses. Nothing is faked.
        messages = [
            {"role": "system", "content": "You are a helpful AI assistant."},
            {"role": "user", "content": prompt}
        ]
        result = ""
        try:
            from core.llm_router import get_llm_router
            resp = await get_llm_router().complete_stream(messages, on_token=on_token)
            if resp and resp.content:
                result = resp.content
        except Exception as e:  # noqa: BLE001
            log.warning(f"LLMRouter general route failed, falling back to local: {e}")

        if not result:
            skills_ctx = skill_injector.build_injected_context("dialogue", prompt)
            result = await self.rm.run_local_model(
                model_name="qwen-dialogue:8b",
                messages=[{"role": "system", "content": f"{PROMPTS['dialogue']}\n\n{skills_ctx}"}, {"role": "user", "content": prompt}],
                temperature=0.6,
                progress_cb=self.cb
            )

        await self._emit("route_done", {"route": "GENERAL"})
        return {"route": "GENERAL", "results": {"response": result}, "final": result}

    # ────────────────────────────────────────────────────────────
    # HELPERS
    # ────────────────────────────────────────────────────────────

    async def _call_security_api(self, code_context: str, prompt: str) -> str:
        """Delegate external security consultation through canonical ``core.llm_router.LLMRouter``."""
        from core.llm_router import get_llm_router

        router = get_llm_router()
        if router.policy == "local_only":
            return "External security API disabled under HUNTER_LLM_POLICY=local_only."

        messages = [
            {"role": "system", "content": "You are an expert security consultant."},
            {"role": "user", "content": f"Context:\n{code_context}\n\nTask: {prompt}"},
        ]
        try:
            resp = await router.complete(messages, role="deep_analyst")
            if resp and resp.content:
                return resp.content
        except Exception as exc:  # noqa: BLE001
            log.warning("Canonical LLMRouter security consultation failed: %s", exc)

        return (
            "No external security API available. "
            "Add GEMINI_API_KEY, GROQ_API_KEY, or OPENAI_API_KEY to .env for security consultations."
        )

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
