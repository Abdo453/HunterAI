"""
HunterAI Scan Health Score & Observability Dashboard
====================================================
Evaluates overall scan execution quality across 6 health dimensions:
- Scope Integrity (100% if 0 leaks)
- Evidence Integrity
- Endpoint Coverage
- Auth Coverage
- Verification Coverage
- Tool Reliability
Provides clear plain-English wait diagnostics explaining WHY an agent is paused.
"""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class AgentWaitState(str, Enum):
    ACTIVE_EXECUTING = "ACTIVE_EXECUTING"
    WAITING_FOR_OPERATOR_APPROVAL = "WAITING_FOR_OPERATOR_APPROVAL"
    RATE_LIMIT_COOLDOWN = "RATE_LIMIT_COOLDOWN"
    EVIDENCE_GOAL_SATISFIED = "EVIDENCE_GOAL_SATISFIED"
    WAF_BACKOFF = "WAF_BACKOFF"
    SESSION_RENEWAL = "SESSION_RENEWAL"
    COMPLETED = "COMPLETED"


@dataclass
class ScanHealthReport:
    overall_reliability_pct: float
    grade: str  # EXCELLENT, HEALTHY, COMPROMISED
    scope_integrity_pct: float
    evidence_integrity_pct: float
    endpoint_coverage_pct: float
    auth_coverage_pct: float
    verification_coverage_pct: float
    tool_reliability_pct: float
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ScanHealthScoreEngine:
    """Calculates quantitative assessment reliability"""

    @classmethod
    def calculate_health(
        cls,
        scope_violations: int,
        evidence_corrupted: int,
        probed_endpoints: int,
        total_endpoints: int,
        tested_roles: int,
        total_roles: int,
        verified_findings: int,
        total_findings: int,
        tool_failures: int,
        total_tool_calls: int
    ) -> ScanHealthReport:
        # 1. Scope Integrity
        scope_pct = 100.0 if scope_violations == 0 else max(0.0, 100.0 - (scope_violations * 25.0))

        # 2. Evidence Integrity
        evi_pct = 100.0 if evidence_corrupted == 0 else max(0.0, 100.0 - (evidence_corrupted * 20.0))

        # 3. Endpoint Coverage
        ep_pct = round((probed_endpoints / max(1, total_endpoints)) * 100.0, 1)

        # 4. Auth Coverage
        auth_pct = round((tested_roles / max(1, total_roles)) * 100.0, 1)

        # 5. Verification Coverage
        ver_pct = round((verified_findings / max(1, total_findings)) * 100.0, 1) if total_findings > 0 else 100.0

        # 6. Tool Reliability
        tool_pct = round(((total_tool_calls - tool_failures) / max(1, total_tool_calls)) * 100.0, 1)

        # Weighted overall reliability
        overall = round(
            (0.25 * scope_pct) +
            (0.25 * evi_pct) +
            (0.15 * ep_pct) +
            (0.15 * auth_pct) +
            (0.10 * ver_pct) +
            (0.10 * tool_pct),
            1
        )

        grade = "EXCELLENT" if overall >= 90.0 else "HEALTHY" if overall >= 75.0 else "COMPROMISED"

        return ScanHealthReport(
            overall_reliability_pct=overall,
            grade=grade,
            scope_integrity_pct=scope_pct,
            evidence_integrity_pct=evi_pct,
            endpoint_coverage_pct=ep_pct,
            auth_coverage_pct=auth_pct,
            verification_coverage_pct=ver_pct,
            tool_reliability_pct=tool_pct
        )


class AgentStateObserver:
    """Explains why agents are waiting or halted in plain natural language"""

    @classmethod
    def diagnose_wait_state(cls, state: AgentWaitState, context: Optional[Dict[str, Any]] = None) -> str:
        ctx = context or {}
        if state == AgentWaitState.WAITING_FOR_OPERATOR_APPROVAL:
            return f"Agent halted: State-mutating action '{ctx.get('action_id')}' requires operator sign-off in ApprovalQueue."
        elif state == AgentWaitState.RATE_LIMIT_COOLDOWN:
            return f"Agent throttled: Backing off for {ctx.get('delay_sec', 1.0)}s to prevent server destabilization."
        elif state == AgentWaitState.EVIDENCE_GOAL_SATISFIED:
            return f"Agent stopped: All mandatory evidence requirements achieved for endpoint '{ctx.get('endpoint')}'. Zero waste."
        elif state == AgentWaitState.WAF_BACKOFF:
            return "Agent cooling down: Temporary 429/403 block observed; mutating headers."
        elif state == AgentWaitState.COMPLETED:
            return "Mission goals fully achieved. Execution concluded."
        return "Agent actively executing task in pipeline."
