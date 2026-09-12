"""
Agent Self-Criticism Engine (Anti-Hallucination & False-Positive Filter)
Critically reviews hypotheses, challenges assumptions, and enforces evidence-based gating.
"""
import logging
from typing import Dict, List, Any, Optional
from agents.security_intelligence.schemas import SecurityHypothesis, EvidenceItem, EvidenceType, HypothesisStatus
from agents.security_intelligence.false_positive_memory import FalsePositiveMemory
from agents.security_intelligence.config import SecurityIntelligenceConfig

log = logging.getLogger("security_intelligence.critic")


class CriticEngine:
    """محرك النقد الذاتي: التشكيك المنهجي في الافتراضات ومنع الإنذارات الكاذبة والهلوسة"""

    def __init__(self, fp_memory: Optional[FalsePositiveMemory] = None):
        self.fp_memory = fp_memory or FalsePositiveMemory()

    def review_hypothesis(
        self,
        hypothesis: SecurityHypothesis,
        evidence_items: List[EvidenceItem]
    ) -> Dict[str, Any]:
        """
        مراجعة نقدية دقيقة للفرضية:
        - هل هناك دليل حقيقي أم مجرد افتراض نظري؟
        - هل يتطابق السلوك مع False Positive مسجل سابقاً؟
        - ما هي الأدلة الناقصة؟
        """
        adjustment = 0.0
        critic_notes: List[str] = []
        is_rejected = False
        rejection_reason = ""

        # 1. Check False Positive Memory
        pattern_str = hypothesis.target_endpoint + " " + " ".join(hypothesis.parameters)
        known_fp = self.fp_memory.is_known_false_positive(
            pattern=pattern_str,
            vuln_type=hypothesis.vulnerability_type,
            endpoint=hypothesis.target_endpoint
        )
        if known_fp:
            adjustment -= SecurityIntelligenceConfig.CRITIC_FALSE_POSITIVE_MATCH_PENALTY
            critic_notes.append(f"⚠️ Matched historical False Positive pattern: '{known_fp.get('reason')}'. Confidence penalized.")
            is_rejected = True
            rejection_reason = f"Historical False Positive: {known_fp.get('reason')}"

        # 2. Check Evidence Completeness
        if not evidence_items:
            adjustment -= SecurityIntelligenceConfig.CRITIC_MISSING_EVIDENCE_PENALTY
            critic_notes.append("⚠️ No direct evidence collected yet. Hypothesis relies entirely on static heuristics.")
        else:
            # Check for high-weight evidence
            has_diff = any(e.type in [EvidenceType.BEHAVIOR_DIFF, EvidenceType.AUTH_ANOMALY] for e in evidence_items)
            if has_diff:
                adjustment += SecurityIntelligenceConfig.CRITIC_BEHAVIORAL_DIFF_BONUS
                critic_notes.append("✅ Strong behavioral / authorization differential verified in evidence.")
            else:
                critic_notes.append("ℹ️ Missing cross-user behavioral comparison evidence.")

        # 3. Challenge Alternative Explanations
        if hypothesis.vulnerability_type == "BOLA":
            has_cross_user_ev = any("cross" in e.description.lower() or "user" in e.description.lower() for e in evidence_items)
            if not has_cross_user_ev:
                adjustment -= 0.15
                critic_notes.append("🔍 Caution: Endpoint identifier may point to public or unauthenticated assets (requires cross-user verification).")

        if hypothesis.vulnerability_type == "SQLi":
            has_db_error_or_timing = any(e.type in [EvidenceType.ERROR_DISCLOSURE, EvidenceType.TIMING_LEAK] for e in evidence_items)
            if not has_db_error_or_timing:
                adjustment -= 0.20
                critic_notes.append("🔍 Caution: No database error or time-delay differential confirmed in response.")

        return {
            "is_valid": not is_rejected,
            "rejection_reason": rejection_reason,
            "adjustment": round(adjustment, 3),
            "critic_notes": " \n".join(critic_notes)
        }
