"""
Decision Policy & Dynamic Profiles Framework
Switches decision-making policy between Exploration, Disambiguation, and Verification modes.
Applies strict hard gates before utility ranking.
"""
from enum import Enum
from typing import Dict, List, Tuple, Optional
from pydantic import BaseModel, Field

from core.reasoning.action_model import ActionDescriptor, ActionKind
from core.reasoning.action_evaluator import ActionEvaluator, ActionUtilityBreakdown
from core.reasoning.information_gain import InformationGainEngine
from core.reasoning.belief_state import BeliefState
from core.reasoning.uncertainty import UncertaintyModel


class PolicyMode(str, Enum):
    EXPLORATION = "EXPLORATION"           # High uncertainty / early investigation: discover surface
    DISAMBIGUATION = "DISAMBIGUATION"     # Competing hypotheses: maximize EIG / entropy reduction
    VERIFICATION = "VERIFICATION"         # Strong hypothesis: maximize proof & evidence quality


class PolicyProfile(BaseModel):
    """أوزان سياسة اتخاذ القرار المعيارية"""
    mode: PolicyMode
    w_info: float = 2.0
    w_goal: float = 2.5
    w_evid: float = 1.5
    w_rel: float = 1.0
    w_cost: float = 0.5


# Default calibrated profiles
DEFAULT_PROFILES: Dict[PolicyMode, PolicyProfile] = {
    PolicyMode.EXPLORATION: PolicyProfile(
        mode=PolicyMode.EXPLORATION,
        w_info=1.0,
        w_goal=1.5,
        w_evid=0.5,
        w_rel=1.0,
        w_cost=0.3
    ),
    PolicyMode.DISAMBIGUATION: PolicyProfile(
        mode=PolicyMode.DISAMBIGUATION,
        w_info=4.0,       # Maximum emphasis on separating competing hypotheses
        w_goal=1.0,
        w_evid=1.0,
        w_rel=1.2,
        w_cost=0.5
    ),
    PolicyMode.VERIFICATION: PolicyProfile(
        mode=PolicyMode.VERIFICATION,
        w_info=0.5,
        w_goal=4.0,       # Maximum emphasis on confirming finding and satisfying goal
        w_evid=3.5,
        w_rel=1.5,
        w_cost=0.5
    )
}


class EpistemicDecisionPolicy:
    """
    سياسة اتخاذ القرار المعرفي:
    تختار الأكشن الأمثل بعد الفحص الصارم للسياسات والنطاق
    """

    @staticmethod
    def determine_optimal_mode(belief_state: BeliefState) -> PolicyMode:
        """
        التحديد التلقائي للطور الأنسب استناداً إلى إنتروبيا المعتقدات وحالة الهدف
        """
        hyps = belief_state.hypotheses
        if not hyps or len(hyps) <= 1:
            return PolicyMode.EXPLORATION

        norm_entropy = UncertaintyModel.compute_normalized_entropy(hyps)
        max_prob = max(hyps.values()) if hyps else 0.0

        if max_prob >= 0.80:
            return PolicyMode.VERIFICATION
        elif norm_entropy > 0.40:
            return PolicyMode.DISAMBIGUATION
        else:
            return PolicyMode.VERIFICATION

    @classmethod
    def select_action(
        cls,
        candidates: List[ActionDescriptor],
        belief_state: BeliefState,
        scope_guard=None,
        mode: Optional[PolicyMode] = None,
        hypotheses_types: Optional[Dict[str, str]] = None
    ) -> Tuple[Optional[ActionDescriptor], List[ActionUtilityBreakdown], PolicyMode]:
        """
        تقييم المرشحين واختيار الأكشن ذو المنفعة القصوى
        """
        active_mode = mode or cls.determine_optimal_mode(belief_state)
        profile = DEFAULT_PROFILES[active_mode]

        breakdowns: List[ActionUtilityBreakdown] = []
        admissible_pairs: List[Tuple[ActionDescriptor, ActionUtilityBreakdown]] = []

        for candidate in candidates:
            # 1. Hard Gate Safety & Scope Check
            admissible, reason = candidate.check_admissibility(scope_guard=scope_guard)
            if not admissible:
                bd = ActionUtilityBreakdown(
                    action_id=candidate.action_id,
                    tool_name=candidate.tool_name,
                    admissible=False,
                    rejection_reason=reason
                )
                breakdowns.append(bd)
                continue

            # 2. Compute EIG
            eig = InformationGainEngine.compute_eig(
                prior_distribution=belief_state.hypotheses,
                action=candidate,
                hypotheses_types=hypotheses_types
            )

            # 3. Compute Multi-Objective Utility
            bd = ActionEvaluator.evaluate(
                action=candidate,
                eig=eig,
                w_info=profile.w_info,
                w_goal=profile.w_goal,
                w_evid=profile.w_evid,
                w_rel=profile.w_rel,
                w_cost=profile.w_cost
            )
            breakdowns.append(bd)
            admissible_pairs.append((candidate, bd))

        if not admissible_pairs:
            return None, breakdowns, active_mode

        # Sort by total utility descending
        admissible_pairs.sort(key=lambda pair: pair[1].total_utility, reverse=True)
        best_action, _ = admissible_pairs[0]
        return best_action, breakdowns, active_mode
