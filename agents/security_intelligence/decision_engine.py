"""
Security Decision Engine
Translates analytical findings and confidence scores into structured, risk-prioritized action recommendations.
"""
import logging
from typing import List, Optional
from agents.security_intelligence.schemas import (
    IntelligenceFinding,
    SecurityDecision,
    ActionPriority,
    ConfidenceLevel
)

log = logging.getLogger("security_intelligence.decision")


class SecurityDecisionEngine:
    """محرك اتخاذ القرارات الأمنية: تقديم التوجيهات الدقيقة والمبررة للـ AutonomousBrain"""

    def evaluate_finding_decision(self, finding: IntelligenceFinding) -> SecurityDecision:
        """
        تحديد الإجراء الأمني الأنسب بناءً على درجة الثقة والخطورة
        """
        score = finding.confidence_score
        vuln = finding.vulnerability_type

        if score >= 0.85:
            priority = ActionPriority.IMMEDIATE
            action = f"Generate verified vulnerability report and trigger educational walkthrough for {vuln}."
            safe_check = None
            rationale = f"High confidence ({score:.2f}) supported by solid evidence and verified by Critic."
            req_ev = []
        elif score >= 0.60:
            priority = ActionPriority.HIGH
            action = f"Perform safe authorized cross-user comparison on {finding.title} to elevate confidence."
            safe_check = f"Send benign request with User B session to compare response status on {finding.title}."
            rationale = f"Promising hypothesis ({score:.2f}) with behavioral indicators, needs cross-user comparison."
            req_ev = ["Cross-user response comparison", "Session ownership differential"]
        else:
            priority = ActionPriority.NORMAL
            action = f"Log hypothesis in Target Memory and continue passive traffic monitoring on {finding.target}."
            safe_check = None
            rationale = f"Low/Moderate confidence ({score:.2f}). Insufficient evidence to justify active exploration."
            req_ev = ["Observe additional API calls with different parameters"]

        return SecurityDecision(
            target=finding.target,
            finding_id=finding.id,
            recommended_action=action,
            action_priority=priority,
            rationale=rationale,
            required_evidence_to_confirm=req_ev,
            safe_active_check_suggested=safe_check,
            is_safe_to_automate=(priority != ActionPriority.IMMEDIATE)
        )
