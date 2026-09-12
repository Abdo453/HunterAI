"""
HunterAI Model Registry
Maintains registry of all AI models (Local Ollama, Cloud APIs, Specialists)
with capabilities, context sizes, health status, and latency monitoring.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from hunter_ai.agents.capabilities import AgentCapability

logger = logging.getLogger(__name__)


@dataclass
class ModelProfile:
    model_id: str
    provider_type: str  # "local", "cloud", "deterministic"
    model_name: str
    capabilities: Set[AgentCapability]
    context_window: int
    is_online: bool = True
    average_latency_ms: float = 0.0
    cost_per_1k_tokens: float = 0.0  # 0.0 for local
    consecutive_failures: int = 0


class ModelRegistry:
    """
    سجل النماذج المركزي (Model Registry):
    - يسجل كافة النماذج المتاحة وقدراتها وسعتها وسرعتها.
    - يراقب حالة النماذج (Health Monitoring) ويختار النموذج الأمثل بناءً على معايير الجودة والتكلفة.
    """

    def __init__(self):
        self._models: Dict[str, ModelProfile] = {}
        self._seed_default_models()

    def _seed_default_models(self):
        # 1. Local Primary: Qwen2.5-Coder (Ollama)
        self.register_model(ModelProfile(
            model_id="local_qwen",
            provider_type="local",
            model_name="qwen2.5-coder:14b",
            capabilities={
                AgentCapability.WEB_ANALYSIS,
                AgentCapability.HTTP_ANALYSIS,
                AgentCapability.JAVASCRIPT_ANALYSIS,
                AgentCapability.VULNERABILITY_ANALYSIS,
                AgentCapability.SECRET_DETECTION,
                AgentCapability.TRAFFIC_ANALYSIS
            },
            context_window=32768,
            cost_per_1k_tokens=0.0
        ))

        # 2. Cloud Deep Reasoning: Gemini / Claude / OpenRouter
        self.register_model(ModelProfile(
            model_id="cloud_reasoning",
            provider_type="cloud",
            model_name="gemini-2.0-flash",
            capabilities={
                AgentCapability.PLANNING,
                AgentCapability.DEEP_REASONING,
                AgentCapability.CRITIC_VALIDATION,
                AgentCapability.REPORT_SYNTHESIS,
                AgentCapability.OSINT_ANALYSIS
            },
            context_window=65536,
            cost_per_1k_tokens=0.001
        ))

        # 3. Deterministic Heuristic Engine
        self.register_model(ModelProfile(
            model_id="deterministic_engine",
            provider_type="deterministic",
            model_name="heuristic_rule_engine",
            capabilities=set(AgentCapability),
            context_window=100000,
            cost_per_1k_tokens=0.0
        ))

    def register_model(self, profile: ModelProfile):
        self._models[profile.model_id] = profile
        logger.info(f"[ModelRegistry] Registered {profile.provider_type} model '{profile.model_id}'.")

    def get_model(self, model_id: str) -> Optional[ModelProfile]:
        return self._models.get(model_id)

    def select_best_model(
        self,
        required_capabilities: Set[AgentCapability],
        estimated_tokens: int = 1000,
        local_first: bool = True
    ) -> ModelProfile:
        """
        اختيار النموذج الأنسب للمهمة:
        1. تطبيق سياسة Local-First: إذا كان هناك نموذج محلي متاح ولديه القدرة ويسع الـ Context -> اختياره فوراً!
        2. إذا لم يتوفر نموذج محلي أو كانت المهمة تتطلب قدرات سحابية -> اختيار النموذج السحابي
        3. كبديل أخير -> اختيار المحرك الحتمي
        """
        # Step 1: Check online local models
        if local_first:
            for m in self._models.values():
                if m.provider_type == "local" and m.is_online:
                    if required_capabilities.issubset(m.capabilities) and estimated_tokens <= m.context_window:
                        return m

        # Step 2: Check cloud models
        for m in self._models.values():
            if m.provider_type == "cloud" and m.is_online:
                if any(c in m.capabilities for c in required_capabilities) and estimated_tokens <= m.context_window:
                    return m

        # Step 3: Fallback to local or deterministic
        for m in self._models.values():
            if m.provider_type == "local" and m.is_online:
                return m

        return self._models.get("deterministic_engine") or list(self._models.values())[0]

    def record_model_health(self, model_id: str, is_online: bool, latency_ms: float = 0.0):
        m = self._models.get(model_id)
        if m:
            m.is_online = is_online
            if is_online:
                m.consecutive_failures = 0
                m.average_latency_ms = (m.average_latency_ms + latency_ms) / 2.0 if m.average_latency_ms > 0 else latency_ms
            else:
                m.consecutive_failures += 1
