"""
Multi-Tier Confidence Engine
Calculates granular confidence scores (0.00 - 1.00) and maps them to qualitative risk tiers.
"""
from typing import Dict, Any, List
from agents.security_intelligence.schemas import ConfidenceLevel, SecurityHypothesis, EvidenceItem
from agents.security_intelligence.config import SecurityIntelligenceConfig


class ConfidenceEngine:
    """محرك حساب درجات الثقة الرياضية والنوعية"""

    @staticmethod
    def score_to_level(score: float) -> ConfidenceLevel:
        s = max(0.0, min(1.0, score))
        if s < SecurityIntelligenceConfig.CONFIDENCE_UNKNOWN_MAX:
            return ConfidenceLevel.UNKNOWN
        elif s < SecurityIntelligenceConfig.CONFIDENCE_WEAK_MAX:
            return ConfidenceLevel.WEAK
        elif s < SecurityIntelligenceConfig.CONFIDENCE_POSSIBLE_MAX:
            return ConfidenceLevel.POSSIBLE
        elif s < SecurityIntelligenceConfig.CONFIDENCE_STRONG_MAX:
            return ConfidenceLevel.STRONG
        elif s < SecurityIntelligenceConfig.CONFIDENCE_HIGH_MAX:
            return ConfidenceLevel.HIGH
        else:
            return ConfidenceLevel.CONFIRMED

    @staticmethod
    def calculate_hypothesis_confidence(
        hypothesis: SecurityHypothesis,
        evidence_items: List[EvidenceItem],
        critic_adjustment: float = 0.0
    ) -> Dict[str, Any]:
        """
        حساب درجة الثقة بالاعتماد على:
        1. الوزن الأساسي للفرضية
        2. الأدلة الحاضرة مقابل الأدلة المطلوبة
        3. تعديلات وملاحظات الـ Critic
        """
        base_conf = hypothesis.confidence
        
        # Evidence coverage calculation
        if hypothesis.evidence_required:
            covered_evidence = min(len(evidence_items), len(hypothesis.evidence_required))
            coverage_ratio = covered_evidence / len(hypothesis.evidence_required)
        else:
            coverage_ratio = 1.0 if evidence_items else 0.5

        # Weighted sum of evidence
        evidence_weight_sum = sum(e.weight for e in evidence_items)
        avg_evidence_weight = (evidence_weight_sum / max(1, len(evidence_items))) if evidence_items else 0.3

        # Formula: 40% Base hypothesis + 40% Evidence strength/coverage + Critic adjustment
        raw_score = (base_conf * 0.35) + (coverage_ratio * avg_evidence_weight * 0.65) + critic_adjustment
        final_score = max(0.05, min(1.0, raw_score))

        level = ConfidenceEngine.score_to_level(final_score)

        return {
            "score": round(final_score, 3),
            "level": level,
            "coverage_ratio": round(coverage_ratio, 2),
            "evidence_count": len(evidence_items),
            "critic_adjustment": round(critic_adjustment, 3)
        }
