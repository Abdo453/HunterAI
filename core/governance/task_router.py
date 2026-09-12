"""
Governed Task Router
Defines unified task representation and routes tasks between Local AI and Online Cloud AI:
- Local AI: Source code, HTTP flows, secrets detection, sensitive customer/test data.
- Online Cloud AI: High-level planning, report writing, finding deduplication & summaries.
- Human Approval Gate: Flags high-risk active execution tasks.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from core.governance.policy_engine import HIGH_RISK_ACTIVITIES

logger = logging.getLogger(__name__)

LOCAL_ONLY_TASK_KINDS: Set[str] = {
    "source_analysis",
    "http_analysis",
    "secret_detection",
    "baseline_comparison",
    "raw_parameter_parsing",
    "token_entropy_analysis",
}

ONLINE_SUITABLE_TASK_KINDS: Set[str] = {
    "planning",
    "report_writing",
    "finding_summary",
    "executive_overview",
    "remediation_guidance",
}


@dataclass
class GovernedTask:
    task_id: str
    kind: str  # "source_analysis", "http_analysis", "planning", "ssrf", "report_writing", etc.
    target_url: str
    method: str = "GET"
    data: Dict[str, Any] = field(default_factory=dict)
    risk_level: str = "low"  # "low", "medium", "high", "critical"
    contains_sensitive_data: bool = False
    requires_execution: bool = False
    human_approved: bool = False
    expected_output: List[str] = field(default_factory=list)


class GovernedTaskRouter:
    """
    موجه المهام المحكوم (Governed Task Router):
    - يختار النموذج الأنسب (محلي أو سحابي) بناءً على حساسية البيانات ونوع العملية.
    - يضمن عدم تسريب أي كود أو حركة مرور أو مفاتيح سرية إلى النماذج السحابية.
    """

    @classmethod
    def choose_model(cls, task: GovernedTask) -> str:
        """
        تحديد النموذج المستهدف للمهمة:
        - "local": للمهام الحساسة والبيانات الخاصة وتحليل الكود والترافيك
        - "online": للتخطيط العام وصياغة التقارير وتلخيص النتائج الخالية من الأسرار
        """
        # 1. Any task flagged as containing sensitive data stays local 100%
        if task.contains_sensitive_data:
            return "local"

        # 2. Local-only technical categories
        if task.kind.lower() in LOCAL_ONLY_TASK_KINDS:
            return "local"

        # 3. Cloud-suitable conceptual categories
        if task.kind.lower() in ONLINE_SUITABLE_TASK_KINDS:
            return "online"

        # Default safe stance: Keep task local
        return "local"

    @classmethod
    def requires_human_approval(cls, task: GovernedTask) -> bool:
        """
        التحقق مما إذا كانت المهمة تتطلب موافقة بشرية مسبقة
        (فحوصات التنفيذ النشط عالية الخطورة)
        """
        if not task.requires_execution:
            return False

        # If already approved by human operator
        if task.human_approved:
            return False

        kind_lower = task.kind.lower()
        if kind_lower in HIGH_RISK_ACTIVITIES or task.risk_level.lower() in ("high", "critical"):
            return True

        return False
