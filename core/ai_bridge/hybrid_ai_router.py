"""
Hybrid AI Router (Local Ollama <-> Online Cloud with Refusal-Triggered Reframe)
Mediates between the Security Agent and AI Models:
1. Preserves the requested cybersecurity mode and terminology on the initial call.
2. Invokes Online Cloud AI (Gemini / Claude / OpenRouter).
3. Inspects for refusal signatures via RefusalDetector.
4. On refusal, reframes the request phrasing and retries the SAME model before switching models.
5. Falls back to Local Ollama (Qwen2.5-Coder, DeepSeek, WhiteRabbitNeo) and then deterministic rules only if needed.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from core.ai_bridge.defensive_prompt_framer import DefensivePromptFramer
from core.ai_bridge.refusal_detector import RefusalDetector
from core.ai_bridge.structured_output_parser import StructuredOutputParser

logger = logging.getLogger(__name__)


@dataclass
class AIBridgeResponse:
    content: str
    parsed_json: Optional[Dict[str, Any]]
    model_used: str  # e.g. "gemini-2.0-flash", "ollama/qwen2.5-coder", "deterministic_heuristics"
    provider_tier: str  # "online_cloud", "local_ollama", "deterministic_rules"
    fallback_triggered: bool
    refusal_encountered: bool
    latency_ms: float
    raw_prompt_reframed: bool = False


class HybridAIRouter:
    """
    موجه الذكاء الاصطناعي الهجين (Hybrid AI Router):
    - يدير العلاقة بين الـ Agent ونماذج الذكاء الاصطناعي (أونلاين + محلي).
    - يمنع تعطل الـ Agent عند رفض النماذج السحابية عبر التحويل التلقائي للنماذج المحلية.
    """

    def __init__(
        self,
        prefer_online: bool = True,
        preferred_local_model: str = "qwen2.5-coder:14b",
        preferred_online_model: Optional[str] = None,
        retry_reframed_on_refusal: bool = True,
    ):
        from core.llm.manifest import canonical_gemini_model

        self.prefer_online = prefer_online
        self.preferred_local_model = preferred_local_model
        self.preferred_online_model = preferred_online_model or canonical_gemini_model()
        self.retry_reframed_on_refusal = retry_reframed_on_refusal
        self.call_history: List[AIBridgeResponse] = []

    @staticmethod
    async def _invoke_caller(caller_fn: Callable[[str, str], Any], query: str, system_prompt: str) -> str:
        if asyncio.iscoroutinefunction(caller_fn):
            return await caller_fn(query, system_prompt)
        return caller_fn(query, system_prompt)

    async def query_security_reasoning(
        self,
        raw_agent_query: str,
        target_context: Optional[str] = None,
        task_category: str = "vulnerability_analysis",
        online_caller_fn: Optional[Callable[[str, str], Any]] = None,
        local_caller_fn: Optional[Callable[[str, str], Any]] = None
    ) -> AIBridgeResponse:
        """
        Send the raw mode-preserving prompt first; if the model refuses, reframe the
        request wording on the same model before falling back to local/deterministic tiers.
        """
        t0 = time.time()
        sys_prompt, initial_query = DefensivePromptFramer.reframe_query(
            raw_query=raw_agent_query,
            target_context=target_context,
            task_category=task_category
        )

        refusal_encountered = False
        fallback_triggered = False
        raw_prompt_reframed = False
        content_result = ""
        model_name = "unknown"
        provider_tier = "online_cloud"

        # ── Step 1: Try Online Cloud AI (raw wording first, reframe same model on refusal) ─
        if self.prefer_online and (online_caller_fn or os.getenv("GEMINI_API_KEY") or os.getenv("OPENROUTER_API_KEY")):
            try:
                if online_caller_fn:
                    res_raw = await self._invoke_caller(online_caller_fn, initial_query, sys_prompt)
                else:
                    res_raw = await self._call_default_online(initial_query, sys_prompt)

                refusal_check = RefusalDetector.check_response(res_raw)
                if not refusal_check.is_refusal:
                    content_result = res_raw
                    model_name = self.preferred_online_model
                    provider_tier = "online_cloud"
                else:
                    refusal_encountered = True
                    if self.retry_reframed_on_refusal:
                        logger.warning(
                            f"[HybridAIRouter] Online AI refused raw prompt ('{refusal_check.matched_signature}'). "
                            "Retrying same online model with reframed phrasing..."
                        )
                        reframed_sys, reframed_query = DefensivePromptFramer.reframe_on_refusal(
                            raw_query=raw_agent_query,
                            target_context=target_context,
                            task_category=task_category,
                            refusal_signature=refusal_check.matched_signature,
                        )
                        if online_caller_fn:
                            res_retry = await self._invoke_caller(online_caller_fn, reframed_query, reframed_sys)
                        else:
                            res_retry = await self._call_default_online(reframed_query, reframed_sys)
                        retry_check = RefusalDetector.check_response(res_retry)
                        if not retry_check.is_refusal:
                            content_result = res_retry
                            model_name = self.preferred_online_model
                            provider_tier = "online_cloud"
                            raw_prompt_reframed = True
                        else:
                            logger.warning(
                                f"[HybridAIRouter] Reframed retry also refused ('{retry_check.matched_signature}'). "
                                "Falling back to local model..."
                            )
                            fallback_triggered = True
                    else:
                        logger.warning(
                            f"[HybridAIRouter] Online AI refused request: '{refusal_check.matched_signature}'. "
                            "Falling back to local model..."
                        )
                        fallback_triggered = True

            except Exception as e:
                logger.warning(f"[HybridAIRouter] Online AI communication failed ({e}). Falling back to local model...")
                fallback_triggered = True

        # ── Step 2: Fallback to Local Ollama ───────────────────────────
        if not content_result:
            fallback_triggered = True
            try:
                if local_caller_fn:
                    res_local = await self._invoke_caller(local_caller_fn, initial_query, sys_prompt)
                else:
                    res_local = await self._call_default_local(initial_query, sys_prompt)

                local_check = RefusalDetector.check_response(res_local)
                if local_check.is_refusal and self.retry_reframed_on_refusal and res_local and res_local.strip():
                    refusal_encountered = True
                    reframed_sys, reframed_query = DefensivePromptFramer.reframe_on_refusal(
                        raw_query=raw_agent_query,
                        target_context=target_context,
                        task_category=task_category,
                        refusal_signature=local_check.matched_signature,
                    )
                    if local_caller_fn:
                        res_local_retry = await self._invoke_caller(local_caller_fn, reframed_query, reframed_sys)
                    else:
                        res_local_retry = await self._call_default_local(reframed_query, reframed_sys)
                    if not RefusalDetector.check_response(res_local_retry).is_refusal:
                        content_result = res_local_retry
                        model_name = f"ollama/{self.preferred_local_model}"
                        provider_tier = "local_ollama"
                        raw_prompt_reframed = True
                elif not local_check.is_refusal and res_local and len(res_local.strip()) > 10:
                    content_result = res_local
                    model_name = f"ollama/{self.preferred_local_model}"
                    provider_tier = "local_ollama"
                    raw_prompt_reframed = False
                else:
                    logger.info("[HybridAIRouter] Local model returned empty or refused response. Activating deterministic rule engine...")

            except Exception as e:
                logger.info(f"[HybridAIRouter] Local Ollama unavailable ({e}). Activating deterministic rule engine...")

        # ── Step 3: Fallback to Deterministic Heuristic Engine ──────────
        if not content_result:
            fallback_triggered = True
            content_result = self._execute_deterministic_heuristics(raw_agent_query, task_category)
            model_name = "deterministic_rule_engine"
            provider_tier = "deterministic_rules"

        # ── Step 4: Parse Structured Output ─────────────────────────────
        parsed_json = StructuredOutputParser.extract_json(content_result)
        latency_ms = round((time.time() - t0) * 1000, 1)

        bridge_resp = AIBridgeResponse(
            content=content_result,
            parsed_json=parsed_json,
            model_used=model_name,
            provider_tier=provider_tier,
            fallback_triggered=fallback_triggered,
            refusal_encountered=refusal_encountered,
            latency_ms=latency_ms,
            raw_prompt_reframed=raw_prompt_reframed
        )

        self.call_history.append(bridge_resp)
        return bridge_resp

    async def _call_default_online(self, prompt: str, system_prompt: str) -> str:
        """Delegate cloud completion to canonical ``core.llm_router.LLMRouter``."""
        try:
            from core.llm_router import get_llm_router

            router = get_llm_router()
            prefer = (
                f"api:gemini:{self.preferred_online_model}"
                if os.getenv("GEMINI_API_KEY")
                else None
            )
            resp = await router.complete(
                [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt},
                ],
                prefer=prefer,
            )
            if resp and resp.content:
                return resp.content
        except Exception as exc:  # noqa: BLE001
            logger.debug("[HybridAIRouter] online LLMRouter delegation failed: %s", exc)
        return ""

    async def _call_default_local(self, prompt: str, system_prompt: str) -> str:
        """Delegate local Ollama completion to canonical ``core.llm_router.LLMRouter``."""
        try:
            from core.llm_router import get_llm_router

            router = get_llm_router()
            resp = await router.complete(
                [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt},
                ],
                prefer=f"local:{self.preferred_local_model}",
                keep_alive=0,
            )
            if resp and resp.content and len(resp.content.strip()) > 5:
                return resp.content
        except Exception as exc:  # noqa: BLE001
            logger.debug("[HybridAIRouter] local LLMRouter delegation failed: %s", exc)
        return ""

    @classmethod
    def _execute_deterministic_heuristics(cls, raw_query: str, task_category: str) -> str:
        """
        محرك القواعد الحتمية الأخير في حال انقطاع كافة نماذج الذكاء الاصطناعي:
        يضمن إرجاع نتيجة أمنية منطقية منظمة بصيغة JSON حتى بدون إنترنت أو موديل محلي.
        """
        q_lower = raw_query.lower()
        if "sql" in q_lower or "500" in q_lower:
            return json.dumps({
                "vulnerability_type": "sql_injection",
                "recommended_action": "perform_benign_boolean_differential",
                "safe_verification": "Compare parameter with (21+21) and 1=1 vs 1=2",
                "remediation": "Enforce parameterized queries and prepared statements.",
                "confidence": 0.85
            })
        elif "idor" in q_lower or "user_id" in q_lower or "order" in q_lower:
            return json.dumps({
                "vulnerability_type": "broken_object_level_authorization",
                "recommended_action": "dual_account_cross_session_check",
                "safe_verification": "Request object with Account A session and verify rejection.",
                "remediation": "Filter database queries strictly by current_user.id.",
                "confidence": 0.90
            })
        elif "ssrf" in q_lower or "url" in q_lower:
            return json.dumps({
                "vulnerability_type": "ssrf",
                "recommended_action": "canary_collaborator_callback",
                "safe_verification": "Send researcher-owned callback domain without targeting metadata.",
                "remediation": "Enforce strict protocol allowlist and resolve IP validation.",
                "confidence": 0.85
            })

        return json.dumps({
            "task": task_category,
            "analysis_status": "evaluated_via_deterministic_rules",
            "guidance": "Verify input boundaries using safe baseline differential.",
            "remediation": "Apply strict input allowlisting and server-side authorization filters."
        })
