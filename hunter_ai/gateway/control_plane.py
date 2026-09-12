"""
HunterAI Agent AI Control Plane (Main Orchestration Hub)
Provides an Agent-Agnostic Intelligence Layer for all specialized Agents
(ReconAgent, WebAgent, BurpAgent, AutonomousBrain).
"""
from __future__ import annotations

import logging
import time
from typing import Any, Callable, Dict, List, Optional

from hunter_ai.agents.registry import AgentRegistry
from hunter_ai.context.manager import ContextManager
from hunter_ai.gateway.router import AIRouter
from hunter_ai.intelligence.pipeline import CognitiveIntelligencePipeline
from hunter_ai.providers.fallback_engine import FallbackAction
from hunter_ai.providers.model_registry import ModelRegistry
from hunter_ai.schemas.result import HunterAIResult
from hunter_ai.schemas.task import HunterTask, TaskLifecycleState

logger = logging.getLogger(__name__)


class HunterAIControlPlane:
    """
    منصة التحكم والذكاء الاصطناعي المركزي (Agent AI Control Plane):
    - العقل الوسيط الموحد: يستقبل المهام من أي Agent.
    - يختار النموذج المناسب (Local-First)، يضغط السياق، ويشغل دورة الذكاء المعرفي (Planner -> Analyzer -> Critic -> Validator).
    - يرجع نتيجة نهائية موثوقة ذات درجة تأكيد محددة.
    """

    _instance: Optional[HunterAIControlPlane] = None

    def __init__(self):
        self.agent_registry = AgentRegistry()
        self.model_registry = ModelRegistry()
        self.router = AIRouter(self.model_registry)
        self.tasks_processed: List[HunterAIResult] = []

    @classmethod
    def get_instance(cls) -> HunterAIControlPlane:
        if cls._instance is None:
            cls._instance = HunterAIControlPlane()
        return cls._instance

    async def submit_task(
        self,
        task: HunterTask,
        custom_reasoner_fn: Optional[Callable[[HunterTask], Dict[str, Any]]] = None
    ) -> HunterAIResult:
        """
        إرسال مهمة جديدة للمنظومة الذكية والحصول على تحليل مؤكد ومتحقق منه
        """
        t0 = time.time()
        logger.info(f"[ControlPlane] Received task '{task.task_id}' from agent '{task.origin_agent}'.")

        # 1. State -> QUEUED
        task.transition_to(TaskLifecycleState.QUEUED)

        # 2. Prepare compressed task context via ContextManager
        task.raw_payload = ContextManager.prepare_compact_task_context(
            raw_payload=task.raw_payload,
            max_token_budget=8000
        )

        # 3. Route task to best model profile (Local-First)
        selected_model = self.router.route_task(task)

        # 4. Execute Multi-Stage Cognitive Intelligence Pipeline
        try:
            result = await CognitiveIntelligencePipeline.process_task(
                task=task,
                model_name=selected_model.model_name,
                reasoner_fn=custom_reasoner_fn
            )
        except Exception as e:
            logger.error(f"[ControlPlane] Execution error on model '{selected_model.model_name}': {e}. Initiating fallback...")
            action, fallback_model = self.router.handle_execution_failure(
                task=task,
                current_model=selected_model,
                error=e
            )

            # Retry with fallback model
            fb_model_name = fallback_model.model_name if fallback_model else "deterministic_rules"
            result = await CognitiveIntelligencePipeline.process_task(
                task=task,
                model_name=fb_model_name,
                reasoner_fn=custom_reasoner_fn
            )
            result.fallback_used = True

        result.latency_ms = round((time.time() - t0) * 1000, 1)
        self.tasks_processed.append(result)

        logger.info(
            f"[ControlPlane] Task '{task.task_id}' completed with status '{result.status}' "
            f"[Confidence: {result.confidence:.2f}, Model: {result.model}]."
        )
        return result

    def get_system_health(self) -> Dict[str, Any]:
        """الاستعلام عن الحالة التشغيلية للمنظومة والـ Agents والموديلات"""
        return {
            "control_plane_status": "ONLINE",
            "registered_agents": self.agent_registry.list_all(),
            "total_tasks_processed": len(self.tasks_processed),
            "models": {
                m_id: {
                    "provider": m.provider_type,
                    "online": m.is_online,
                    "avg_latency_ms": round(m.average_latency_ms, 1)
                }
                for m_id, m in self.model_registry._models.items()
            }
        }
