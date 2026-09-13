"""
HunterAI Mission System & Evidence-Based Stopping
=================================================
Transforms blind scanning into goal-driven security missions:
- AUTHENTICATION_AUDIT: Login, sessions, tokens, revocations
- AUTHORIZATION_BOLA_AUDIT: IDOR, cross-tenant isolation, object access
- API_CONTRACT_AUDIT: Schema validation, parameter boundaries, mass assignment
- FULL_SCOPE_ASSESSMENT: Full OWASP baseline

Evidence-Based Stopping (Zero Waste):
Once all required evidence criteria are satisfied for a finding, active probing
on that parameter halts immediately to eliminate redundant loops and socket waste.
"""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class MissionType(str, Enum):
    AUTHENTICATION_AUDIT = "AUTHENTICATION_AUDIT"
    AUTHORIZATION_BOLA_AUDIT = "AUTHORIZATION_BOLA_AUDIT"
    API_CONTRACT_AUDIT = "API_CONTRACT_AUDIT"
    FULL_SCOPE_ASSESSMENT = "FULL_SCOPE_ASSESSMENT"


@dataclass
class MissionGoal:
    goal_id: str
    description: str
    is_satisfied: bool = False
    evidence_reference: Optional[str] = None


class MissionSystem:
    """Manages mission lifecycle and goal verification"""

    def __init__(self, mission_type: MissionType, target_domain: str):
        self.mission_type = mission_type
        self.target_domain = target_domain
        self.goals: Dict[str, MissionGoal] = {}
        self.start_time = time.time()
        self._init_goals()

    def _init_goals(self):
        if self.mission_type == MissionType.AUTHENTICATION_AUDIT:
            self.goals["login_flow"] = MissionGoal("login_flow", "Map authentication and login endpoints")
            self.goals["session_state"] = MissionGoal("session_state", "Verify session token issuance and validation")
            self.goals["rate_limit"] = MissionGoal("rate_limit", "Assess credential stuffing rate-limiting")
            self.goals["revocation"] = MissionGoal("revocation", "Confirm token revocation upon logout")
        elif self.mission_type == MissionType.AUTHORIZATION_BOLA_AUDIT:
            self.goals["object_endpoints"] = MissionGoal("object_endpoints", "Identify object identifier endpoints")
            self.goals["differential_roles"] = MissionGoal("differential_roles", "Execute cross-tenant differential comparisons")
            self.goals["bola_verification"] = MissionGoal("bola_verification", "Verify horizontal BOLA proof of access")
        else:
            self.goals["discovery"] = MissionGoal("discovery", "Complete attack surface reconnaissance")
            self.goals["verification"] = MissionGoal("verification", "Perform differential verification")

    def satisfy_goal(self, goal_id: str, evidence_ref: Optional[str] = None) -> bool:
        if goal_id in self.goals:
            self.goals[goal_id].is_satisfied = True
            self.goals[goal_id].evidence_reference = evidence_ref
            return True
        return False

    def is_mission_complete(self) -> bool:
        return bool(self.goals) and all(g.is_satisfied for g in self.goals.values())

    def get_progress_summary(self) -> Dict[str, Any]:
        total = len(self.goals)
        satisfied = sum(1 for g in self.goals.values() if g.is_satisfied)
        return {
            "mission_type": self.mission_type.value,
            "target": self.target_domain,
            "total_goals": total,
            "completed_goals": satisfied,
            "completion_percentage": round((satisfied / max(1, total)) * 100.0, 1),
            "is_complete": self.is_mission_complete(),
            "goals": {gid: asdict(g) for gid, g in self.goals.items()}
        }


class EvidenceStoppingEngine:
    """Enforces evidence sufficiency criteria to halt probing immediately upon proof"""

    # Strict requirements per vulnerability class
    REQUIRED_EVIDENCE: Dict[str, Set[str]] = {
        "SQLI": {"baseline_established", "differential_observed", "arithmetic_poe_verified", "reproducible"},
        "XSS": {"input_reaches_sink", "differential_observed", "dom_execution_verified", "reproducible"},
        "BOLA": {"baseline_established", "cross_tenant_access_200", "owner_data_retrieved", "reproducible"},
        "SSRF": {"baseline_established", "oob_interaction_captured", "reproducible"}
    }

    @classmethod
    def should_stop_testing(
        cls,
        vulnerability_class: str,
        collected_evidence_types: Set[str]
    ) -> bool:
        """Returns True if all mandatory evidence requirements are fully satisfied"""
        required = cls.REQUIRED_EVIDENCE.get(vulnerability_class.upper(), {"differential_observed", "reproducible"})
        return required.issubset(collected_evidence_types)
