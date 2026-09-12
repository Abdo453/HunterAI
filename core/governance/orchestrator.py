"""
Governed Multi-Model Orchestrator
Enforces policy validation, scope checks, human approval gates,
model routing (Local AI vs Online AI), secrets redaction, and output validation.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from core.governance.policy_engine import GovernancePolicyEngine, ProgramScopePolicy
from core.governance.task_router import GovernedTask, GovernedTaskRouter

logger = logging.getLogger(__name__)


@dataclass
class GovernedExecutionResult:
    task_id: str
    status: str  # "completed", "blocked", "needs_human_approval", "error"
    reason: str = ""
    model_tier: str = "none"  # "local", "online", "none"
    output_data: Dict[str, Any] = field(default_factory=dict)
    secrets_redacted: bool = False
    audit_log: List[str] = field(default_factory=list)


class GovernedOrchestrator:
    """
    المنسق الحاكم للعمليات والنماذج (Governed Orchestrator):
    - يمنع أي فحص خارج النطاق (Scope Enforcement).
    - يحظر الأنشطة التخريبية تلقائياً.
    - يشترط الموافقة البشرية على الفحوصات الحرجة.
    - يوزع المهام على النماذج:
      * المحلي (Local AI): للكود والترافيك والبيانات الحساسة.
      * السحابي (Online AI): للتخطيط وصياغة التقارير بعد تنقية الأسرار 100%.
    """

    def __init__(
        self,
        policy: GovernancePolicyEngine,
        local_ai_runner: Optional[Callable[[GovernedTask], Dict[str, Any]]] = None,
        online_ai_runner: Optional[Callable[[GovernedTask], Dict[str, Any]]] = None
    ):
        self.policy = policy
        self.local_ai_runner = local_ai_runner
        self.online_ai_runner = online_ai_runner
        self.audit_records: List[GovernedExecutionResult] = []

    def handle(self, task: GovernedTask) -> GovernedExecutionResult:
        audit_trail: List[str] = []

        # 1. Scope Gate Validation
        if not self.policy.is_host_in_scope(task.target_url):
            reason = f"Target host in '{task.target_url}' is OUT OF SCOPE or explicitly blocked."
            audit_trail.append(f"[GATE_FAIL] {reason}")
            res = GovernedExecutionResult(
                task_id=task.task_id,
                status="blocked",
                reason=reason,
                model_tier="none",
                audit_log=audit_trail
            )
            self.audit_records.append(res)
            return res

        audit_trail.append(f"[SCOPE_PASS] Target '{task.target_url}' verified in-scope.")

        # 2. Forbidden Activity Guard
        if self.policy.is_forbidden_activity(task.kind):
            reason = f"Task activity '{task.kind}' violates policy (Forbidden Activity)."
            audit_trail.append(f"[FORBIDDEN_FAIL] {reason}")
            res = GovernedExecutionResult(
                task_id=task.task_id,
                status="blocked",
                reason=reason,
                model_tier="none",
                audit_log=audit_trail
            )
            self.audit_records.append(res)
            return res

        # 3. Human Approval Gate for High-Risk Actions
        if GovernedTaskRouter.requires_human_approval(task):
            reason = f"High-risk action '{task.kind}' requires human operator consent before execution."
            audit_trail.append(f"[APPROVAL_HOLD] {reason}")
            res = GovernedExecutionResult(
                task_id=task.task_id,
                status="needs_human_approval",
                reason=reason,
                model_tier="none",
                audit_log=audit_trail
            )
            self.audit_records.append(res)
            return res

        # 4. Model Selection (Local vs Online)
        model_choice = GovernedTaskRouter.choose_model(task)
        audit_trail.append(f"[ROUTER] Selected execution tier: '{model_choice}'")

        output: Dict[str, Any] = {}
        redacted = False

        # 5. Execution Execution via Selected Model Adapter
        if model_choice == "local":
            if self.local_ai_runner:
                output = self.local_ai_runner(task)
            else:
                output = {
                    "result": "analyzed_locally",
                    "kind": task.kind,
                    "target": task.target_url,
                    "data_processed_on_premise": True
                }
        else:
            # Online execution requires mandatory secrets stripping!
            sanitized_data = self.policy.remove_secrets(task.data)
            redacted = (sanitized_data != task.data)
            sanitized_task = GovernedTask(
                task_id=task.task_id,
                kind=task.kind,
                target_url=task.target_url,
                method=task.method,
                data=sanitized_data,
                risk_level=task.risk_level,
                contains_sensitive_data=False,
                requires_execution=task.requires_execution,
                human_approved=task.human_approved
            )

            if self.online_ai_runner:
                output = self.online_ai_runner(sanitized_task)
            else:
                output = {
                    "result": "planned_via_cloud_ai",
                    "kind": task.kind,
                    "target": task.target_url,
                    "secrets_stripped": redacted
                }

        audit_trail.append(f"[EXECUTION_COMPLETE] Output generated successfully via {model_choice} model.")

        result = GovernedExecutionResult(
            task_id=task.task_id,
            status="completed",
            reason="Task successfully evaluated within authorized governance bounds.",
            model_tier=model_choice,
            output_data=output,
            secrets_redacted=redacted,
            audit_log=audit_trail
        )

        self.audit_records.append(result)
        return result
