"""
Multi-Objective Action Evaluator
Scores admissible candidate actions combining Expected Information Gain (EIG),
direct Goal Progress, Evidence Value, Reliability, and Cost.
"""
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field

from core.reasoning.action_model import ActionDescriptor


class ActionUtilityBreakdown(BaseModel):
    """
    تحليل تفصيلي لدرجة جدوى ومنفعة الأكشن المقترح
    """
    action_id: str
    tool_name: str
    eig: float = 0.0
    goal_progress: float = 0.0
    evidence_value: float = 0.0
    reliability: float = 0.90
    cost: float = 1.0
    total_utility: float = 0.0
    admissible: bool = True
    rejection_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class ActionEvaluator:
    """
    مقيّم جدوى الأكشن متعدد الأهداف
    """

    @staticmethod
    def evaluate(
        action: ActionDescriptor,
        eig: float,
        w_info: float = 2.0,
        w_goal: float = 2.5,
        w_evid: float = 1.5,
        w_rel: float = 1.0,
        w_cost: float = 0.5
    ) -> ActionUtilityBreakdown:
        """
        حساب الجدوى الكلية:
        Utility = w_info*EIG + w_goal*GoalDelta + w_evid*EvidenceValue + w_rel*Reliability - w_cost*Cost
        """
        if not action.admissible:
            return ActionUtilityBreakdown(
                action_id=action.action_id,
                tool_name=action.tool_name,
                admissible=False,
                rejection_reason=action.inadmissibility_reason or "Inadmissible"
            )

        utility = (
            (w_info * eig)
            + (w_goal * action.expected_goal_delta)
            + (w_evid * action.expected_evidence_value)
            + (w_rel * action.reliability)
            - (w_cost * action.estimated_cost)
        )

        return ActionUtilityBreakdown(
            action_id=action.action_id,
            tool_name=action.tool_name,
            eig=round(eig, 4),
            goal_progress=round(action.expected_goal_delta, 3),
            evidence_value=round(action.expected_evidence_value, 3),
            reliability=round(action.reliability, 3),
            cost=round(action.estimated_cost, 3),
            total_utility=round(utility, 4),
            admissible=True
        )
