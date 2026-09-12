"""
HunterAI Gateway Router
Routes tasks to optimal models (Local First, Cloud Second, Deterministic Fallback)
incorporating token estimates, capability matching, and intelligent failure classification.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Set, Tuple

from hunter_ai.agents.capabilities import AgentCapability
from hunter_ai.context.manager import ContextManager
from hunter_ai.providers.fallback_engine import FallbackAction, FallbackEngine, FailureReason, FailureResolution
from hunter_ai.providers.model_registry import ModelProfile, ModelRegistry
from hunter_ai.schemas.task import HunterTask

logger = logging.getLogger(__name__)


class AIRouter:
    """
    موجه الذكاء الاصطناعي المركزي (AI Router):
    - يختار النموذج الأنسب بناءً على: (نوع المهمة، حساسية البيانات، التكلفة، السرعة، الحجم).
    - يلتزم بسياسة Local-First للأمان والسرعة.
    """

    def __init__(self, model_registry: ModelRegistry):
        self.model_registry = model_registry

    def route_task(self, task: HunterTask) -> ModelProfile:
        # Calculate estimated tokens
        est_tokens = ContextManager.estimate_tokens(task.raw_payload)

        # Force local if sensitive data is involved
        if task.contains_sensitive_data:
            logger.info(f"[AIRouter] Task '{task.task_id}' contains sensitive data -> strictly forcing Local AI.")
            return self.model_registry.select_best_model(
                required_capabilities=task.required_capabilities,
                estimated_tokens=est_tokens,
                local_first=True
            )

        # Normal capability matching with Local First policy
        selected = self.model_registry.select_best_model(
            required_capabilities=task.required_capabilities,
            estimated_tokens=est_tokens,
            local_first=True
        )

        logger.info(f"[AIRouter] Selected model '{selected.model_id}' ({selected.provider_type}) for task '{task.task_id}'.")
        return selected

    def handle_execution_failure(
        self,
        task: HunterTask,
        current_model: ModelProfile,
        error: Optional[Exception] = None,
        raw_output: str = ""
    ) -> Tuple[FallbackAction, Optional[ModelProfile]]:
        """تشخيص الفشل وتحديد الإجراء البديل"""
        resolution = FallbackEngine.diagnose_and_resolve(
            error=error,
            raw_output=raw_output,
            context_tokens=ContextManager.estimate_tokens(task.raw_payload),
            model_context_limit=current_model.context_window,
            has_required_capability=task.required_capabilities.issubset(current_model.capabilities)
        )

        logger.warning(f"[AIRouter] Diagnosed failure on '{current_model.model_id}': {resolution.reason.value} -> {resolution.action.value}")

        if resolution.action == FallbackAction.SWITCH_TO_CLOUD:
            new_model = self.model_registry.get_model(resolution.recommended_model or "cloud_reasoning")
            return resolution.action, new_model

        if resolution.action == FallbackAction.SWITCH_TO_DETERMINISTIC_RULES:
            new_model = self.model_registry.get_model("deterministic_engine")
            return resolution.action, new_model

        return resolution.action, None
