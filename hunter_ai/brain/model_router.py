"""Hunter Agent Protocol v1: AI Model Router (Thin Forwarding Shim to ``core.llm_router``).

Delegates model selection, unified Gemini defaults, context windows, and execution
to ``core.llm.manifest.ModelManifest`` and ``core.llm_router.LLMRouter``.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import logging
import os
import re
from typing import Any, Dict, List, Optional, Sequence

from core.llm.manifest import canonical_gemini_model, get_model_manifest
from core.llm_router import LLMRouter, get_llm_router
from hunter_ai.protocol.contract import ModelTierPreference
from models.base_model import ModelResponse

logger = logging.getLogger("hunter_ai.model_router")


class TaskIntent(str, Enum):
    EXPLAIN_VULNERABILITY = "explain_vulnerability"
    CODE_ANALYSIS = "code_analysis"
    OFFENSIVE_EXPLOITATION = "offensive_exploitation"
    LARGE_REASONING = "large_reasoning"
    DEEP_THREAT_LOGIC = "deep_threat_logic"
    RAPID_TRIAGE = "rapid_triage"
    REPORT_SYNTHESIS = "report_synthesis"


@dataclass
class RoutedModelSelection:
    model_name: str
    tier: ModelTierPreference
    provider: str  # ollama, gemini, openrouter, local
    context_window: int
    temperature: float
    rationale: str


class AIModelRouter:
    """Thin shim over ``ModelManifest`` + ``LLMRouter`` preserving ``route_task()``."""

    ROUTING_RULES = [
        (re.compile(r"(?i)(javascript|source code|decompil|ast|function|parse code|regex)"), TaskIntent.CODE_ANALYSIS),
        (re.compile(r"(?i)(bypass|waf|filter|payload|breakout|sql injection|xss|ssrf)"), TaskIntent.OFFENSIVE_EXPLOITATION),
        (re.compile(r"(?i)(sitemap|crawl|recon|domains|openapi|1m tokens|massive)"), TaskIntent.LARGE_REASONING),
        (re.compile(r"(?i)(business logic|multi-tenant|privilege escalation|rbac|idor matrix)"), TaskIntent.DEEP_THREAT_LOGIC),
        (re.compile(r"(?i)(triage|quick rank|parameter list|fast check)"), TaskIntent.RAPID_TRIAGE),
        (re.compile(r"(?i)(explain|summary|remediation|report|cwe|cvss)"), TaskIntent.EXPLAIN_VULNERABILITY),
    ]

    def __init__(self, ollama_host: Optional[str] = None, router: Optional[LLMRouter] = None):
        self.manifest = get_model_manifest()
        self.ollama_host = ollama_host or os.getenv("OLLAMA_HOST") or self.manifest.default_host
        self._router = router

    @property
    def router(self) -> LLMRouter:
        return self._router or get_llm_router()

    def infer_intent(self, task_description: str) -> TaskIntent:
        for pattern, intent in self.ROUTING_RULES:
            if pattern.search(task_description or ""):
                return intent
        return TaskIntent.RAPID_TRIAGE

    def route_task(
        self,
        task_description: str,
        preferred_tier: Optional[ModelTierPreference] = None,
    ) -> RoutedModelSelection:
        intent = self.infer_intent(task_description)
        profile = self.manifest.resolve_hardware_profile()

        if preferred_tier == ModelTierPreference.LOCAL_CODE or intent == TaskIntent.CODE_ANALYSIS:
            cfg = self.manifest.get_role_config("fixer", profile=profile)
            return RoutedModelSelection(
                model_name=cfg.local_model,
                tier=ModelTierPreference.LOCAL_CODE,
                provider="ollama",
                context_window=self.manifest.context_window_for(cfg.local_model, default=16384),
                temperature=cfg.temperature,
                rationale="Specialized AST parsing and secure PoC synthesis via ModelManifest fixer role.",
            )

        if preferred_tier == ModelTierPreference.LOCAL_OFFENSIVE or intent == TaskIntent.OFFENSIVE_EXPLOITATION:
            cfg = self.manifest.get_role_config("deep_analyst", profile=profile)
            return RoutedModelSelection(
                model_name=cfg.local_model,
                tier=ModelTierPreference.LOCAL_OFFENSIVE,
                provider="ollama",
                context_window=self.manifest.context_window_for(cfg.local_model, default=8192),
                temperature=cfg.temperature,
                rationale="High-precision offensive and red-team attack vector analysis via deep_analyst role.",
            )

        if preferred_tier == ModelTierPreference.CLOUD_FAST or intent == TaskIntent.LARGE_REASONING:
            gem_model = canonical_gemini_model()
            return RoutedModelSelection(
                model_name=gem_model,
                tier=ModelTierPreference.CLOUD_FAST,
                provider="gemini",
                context_window=self.manifest.context_window_for(gem_model, default=1048576),
                temperature=0.2,
                rationale=f"1M token context window for massive DOM/Recon asset analysis via {gem_model}.",
            )

        if preferred_tier == ModelTierPreference.CLOUD_DEEP or intent == TaskIntent.DEEP_THREAT_LOGIC:
            or_model = self.manifest.get_default_model("openrouter") or "anthropic/claude-3.5-sonnet"
            return RoutedModelSelection(
                model_name=or_model,
                tier=ModelTierPreference.CLOUD_DEEP,
                provider="openrouter",
                context_window=self.manifest.context_window_for(or_model, default=200000),
                temperature=0.1,
                rationale="Deep multi-tenant logic and BOLA verification via canonical cloud model.",
            )

        if intent in (TaskIntent.EXPLAIN_VULNERABILITY, TaskIntent.REPORT_SYNTHESIS):
            cfg = self.manifest.get_role_config("copilot", profile=profile)
            return RoutedModelSelection(
                model_name=cfg.local_model,
                tier=ModelTierPreference.LOCAL_CODE,
                provider="ollama",
                context_window=self.manifest.context_window_for(cfg.local_model, default=16384),
                temperature=cfg.temperature,
                rationale="Clear vulnerability remediation advice and reproduction steps via copilot role.",
            )

        triage = self.manifest.get_role_config("triage", profile=profile)
        return RoutedModelSelection(
            model_name=triage.local_model,
            tier=ModelTierPreference.LOCAL_FAST,
            provider="ollama",
            context_window=self.manifest.context_window_for(triage.local_model, default=8192),
            temperature=triage.temperature,
            rationale="Ultra-fast local parameter triager via ModelManifest triage role.",
        )

    async def complete(
        self,
        messages: Sequence[Any],
        *,
        task_description: str = "",
        preferred_tier: Optional[ModelTierPreference] = None,
        system_prompt: str = "",
    ) -> ModelResponse:
        """Forward execution directly to the canonical ``LLMRouter``."""
        sel = self.route_task(task_description, preferred_tier=preferred_tier)
        prefer = (
            f"local:{sel.model_name}"
            if sel.provider in ("ollama", "local")
            else f"api:{sel.provider}:{sel.model_name}"
        )
        return await self.router.complete(
            messages,
            prefer=prefer,
            system_prompt=system_prompt,
        )
