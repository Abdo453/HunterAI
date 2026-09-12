"""
Candidate Action Model & Admissibility Framework
Defines structured ActionDescriptors with predicted outcome distributions,
estimated costs, expected goal contributions, and policy admissibility gates.
"""
import uuid
import time
from enum import Enum
from typing import Dict, List, Any, Optional, Tuple
from pydantic import BaseModel, Field


class ActionKind(str, Enum):
    DISCOVERY = "DISCOVERY"                 # Surface and endpoint mapping
    BASELINE = "BASELINE"                   # Clean state reference (EIG may be 0, but essential)
    DISAMBIGUATION = "DISAMBIGUATION"       # Experiment separating competing hypotheses (Max EIG)
    VERIFICATION = "VERIFICATION"           # Controlled differential proof of finding
    EXPLOITATION = "EXPLOITATION"           # Controlled impact demonstration


class ActionDescriptor(BaseModel):
    """
    توصيف الأكشن المرشح مع توزيع المخرجات المتوقعة والتكلفة ومساهمته في الهدف
    """
    action_id: str = Field(default_factory=lambda: f"ACT-{uuid.uuid4().hex[:8]}")
    action_kind: ActionKind
    tool_name: str
    target: str
    command_args: str = ""
    rationale: str = ""

    # Predicted outcome distribution: {outcome_name: marginal_probability P(o | a)}
    predicted_outcomes: Dict[str, float] = Field(default_factory=dict)

    # Multi-objective criteria
    estimated_cost: float = 1.0             # Time / resource / detection cost
    reliability: float = 0.90               # Tool execution certainty [0.0, 1.0]
    expected_goal_delta: float = 0.0        # Direct progress towards mission goal [0.0, 1.0]
    expected_evidence_value: float = 0.0    # Quality of forensic evidence produced [0.0, 1.0]

    # Safety & Policy Status
    is_destructive: bool = False
    admissible: bool = True
    inadmissibility_reason: Optional[str] = None
    created_at: float = Field(default_factory=time.time)

    def check_admissibility(
        self,
        scope_guard=None,
        allow_active: bool = True
    ) -> Tuple[bool, str]:
        """
        فحص القبول الحتمي (Hard Gate) قبل التقييم
        """
        if self.is_destructive:
            self.admissible = False
            self.inadmissibility_reason = "Hard Gate: Destructive action prohibited."
            return False, self.inadmissibility_reason

        if not allow_active and self.action_kind in [ActionKind.DISAMBIGUATION, ActionKind.VERIFICATION, ActionKind.EXPLOITATION]:
            self.admissible = False
            self.inadmissibility_reason = "Hard Gate: Active testing disallowed in passive mode."
            return False, self.inadmissibility_reason

        if scope_guard:
            if hasattr(scope_guard, "evaluate_scope_decision"):
                dec = scope_guard.evaluate_scope_decision(self.target, action=self.tool_name)
                allowed = dec.allowed
                reason = dec.reason
            elif hasattr(scope_guard, "evaluate_scope"):
                dec = scope_guard.evaluate_scope(self.target, action=self.tool_name)
                allowed = dec.allowed
                reason = dec.reason
            elif hasattr(scope_guard, "is_target_in_scope"):
                allowed = scope_guard.is_target_in_scope(self.target)
                reason = "Target not in scope" if not allowed else "In scope"
            elif hasattr(scope_guard, "is_allowed"):
                allowed = scope_guard.is_allowed(self.target)
                reason = "Target not allowed" if not allowed else "Allowed"
            else:
                allowed = True
                reason = "Authorized"

            if not allowed:
                self.admissible = False
                self.inadmissibility_reason = f"Hard Gate: Target out of scope ({reason})."
                return False, self.inadmissibility_reason

        self.admissible = True
        self.inadmissibility_reason = None
        return True, "Admissible"
