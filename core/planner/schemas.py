"""
Goal Specifications and Mission Models for State-Space Search (Cairn-Inspired)
Enables goal-driven planning where the agent searches for state transitions to satisfy security predicates.
"""
import uuid
import time
from enum import Enum
from typing import Dict, List, Any, Optional, Tuple
from pydantic import BaseModel, Field

from agents.security_intelligence.schemas import FindingStatus
from core.state.security_state import SecurityState


class GoalType(str, Enum):
    DATA_ISOLATION_CHECK = "DATA_ISOLATION_CHECK"       # Verify horizontal data isolation / BOLA / IDOR
    UNAUTH_ACCESS_CHECK = "UNAUTH_ACCESS_CHECK"         # Test unauthenticated access to privileged assets / BFLA
    INJECTION_CHECK = "INJECTION_CHECK"                 # Verify SQLi, command injection, or template injection
    ATTACK_SURFACE_MAPPING = "ATTACK_SURFACE_MAPPING"   # Catalog unmapped endpoints and parameters
    AUTONOMOUS_VULNERABILITY_HUNT = "AUTONOMOUS_VULNERABILITY_HUNT" # General multi-vulnerability hunt


class SecurityGoal(BaseModel):
    """
    الهدف الأمني المحدد للمهمة (Goal Predicate):
    بدلاً من الـ Workflow الثابت، يُعطى الـ Agent هدفاً محدداً ويبحث في فضاء الحالات للوصول إليه
    """
    id: str = Field(default_factory=lambda: f"GOAL-{uuid.uuid4().hex[:8]}")
    title: str
    goal_type: GoalType
    target: str
    target_endpoints: List[str] = Field(default_factory=list)
    required_finding_status: FindingStatus = FindingStatus.CONFIRMED
    max_search_depth: int = 10
    created_at: float = Field(default_factory=time.time)

    def is_satisfied(self, state: SecurityState) -> Tuple[bool, str]:
        """
        فحص ما إذا كانت حالة الهجوم الحالية تحقق شروط نجاح الهدف (Goal Satisfaction Predicate)
        """
        # 1. Attack Surface Mapping Goal
        if self.goal_type == GoalType.ATTACK_SURFACE_MAPPING:
            if len(state.endpoints) >= 5 or len(state.assets) >= 2:
                return True, f"Attack surface mapped with {len(state.endpoints)} endpoints and {len(state.assets)} assets."
            return False, f"Mapping in progress: {len(state.endpoints)} endpoints discovered."

        # 2. Data Isolation Check (BOLA / IDOR)
        if self.goal_type == GoalType.DATA_ISOLATION_CHECK:
            for v in state.vulnerabilities.values():
                if v.vulnerability_type in ["BOLA", "IDOR"] and v.status == self.required_finding_status:
                    return True, f"Goal satisfied: {v.vulnerability_type} on {v.endpoint} reached status {v.status.value}."
            return False, "Data isolation vulnerability not yet confirmed."

        # 3. Unauthenticated Access Check (BFLA / Auth Bypass)
        if self.goal_type == GoalType.UNAUTH_ACCESS_CHECK:
            for v in state.vulnerabilities.values():
                if v.vulnerability_type in ["BFLA", "Auth_Bypass"] and v.status == self.required_finding_status:
                    return True, f"Goal satisfied: {v.vulnerability_type} reached status {v.status.value}."
            return False, "Unauthorized access not yet proven."

        # 4. Injection Check (SQLi, CMDi, etc.)
        if self.goal_type == GoalType.INJECTION_CHECK:
            for v in state.vulnerabilities.values():
                if v.vulnerability_type in ["SQLi", "CMDi", "SSTI"] and v.status == self.required_finding_status:
                    return True, f"Goal satisfied: {v.vulnerability_type} injection confirmed on {v.endpoint}."
            return False, "Injection vulnerability not yet confirmed."

        # 5. General Vulnerability Hunt
        if self.goal_type == GoalType.AUTONOMOUS_VULNERABILITY_HUNT:
            confirmed = [v for v in state.vulnerabilities.values() if v.status == self.required_finding_status]
            if len(confirmed) >= 1:
                return True, f"Goal satisfied: Found {len(confirmed)} confirmed vulnerability ({confirmed[0].vulnerability_type})."
            return False, "No confirmed vulnerabilities found yet in state."

        return False, "Goal condition evaluation pending."


class MissionReport(BaseModel):
    """
    تقرير انتهاء المهمة وتتبع مسار البحث في فضاء الحالات
    """
    goal_id: str
    goal_title: str
    target: str
    achieved: bool
    steps_taken: int
    findings_confirmed: List[str] = Field(default_factory=list)
    state_snapshot: Dict[str, Any] = Field(default_factory=dict)
    execution_steps: List[Dict[str, Any]] = Field(default_factory=list)
    conclusion: str = ""
    completed_at: float = Field(default_factory=time.time)
