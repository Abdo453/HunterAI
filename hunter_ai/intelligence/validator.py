"""
HunterAI Confidence Engine & Finding Validator
Calculates calibrated confidence scores (0.0 to 1.0) and assigns tiers:
- 0.90 to 1.00: High Confidence (Definitive, verified proof)
- 0.70 to 0.89: Medium Confidence (Strong evidence, requires minor confirmation)
- 0.50 to 0.69: Low Confidence (Theoretical hypothesis)
- < 0.50: Needs Human Review (Insufficient or contested evidence)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

from hunter_ai.intelligence.critic import CriticReviewResult

logger = logging.getLogger(__name__)


@dataclass
class ValidationScorecard:
    final_confidence: float
    confidence_tier: str  # "High", "Medium", "Low", "Needs_Review"
    is_acceptable_for_reporting: bool
    summary: str


class FindingValidator:
    """
    محقق ومقيم درجات التأكيد (Finding Validator & Confidence Engine):
    - يطبق معادلة رياضية لحساب الثقة بالأدلة.
    - يخصم من النتيجة إذا وجه الـ Critic أي تشكيك.
    """

    @classmethod
    def calculate_confidence(
        cls,
        base_confidence: float,
        evidence_count: int,
        has_reproducible_poc: bool,
        critic_review: CriticReviewResult
    ) -> ValidationScorecard:
        # Start with base score
        score = base_confidence

        # Evidence count factor (+0.05 per evidence up to +0.15)
        evidence_boost = min(0.15, evidence_count * 0.05)
        score += evidence_boost

        # Reproducible PoC bonus (+0.10)
        if has_reproducible_poc:
            score += 0.10

        # Apply critic penalty
        score -= critic_review.confidence_penalty

        # Clamp between 0.0 and 1.0
        final_score = max(0.0, min(1.0, round(score, 3)))

        # Determine Tier
        if final_score >= 0.90:
            tier = "High"
            acceptable = True
        elif final_score >= 0.70:
            tier = "Medium"
            acceptable = True
        elif final_score >= 0.50:
            tier = "Low"
            acceptable = False
        else:
            tier = "Needs_Review"
            acceptable = False

        summary = (
            f"Confidence: {final_score:.3f} [{tier}]. "
            f"Critic Verdict: {critic_review.verdict}. "
            f"Evidence Items: {evidence_count}."
        )

        return ValidationScorecard(
            final_confidence=final_score,
            confidence_tier=tier,
            is_acceptable_for_reporting=acceptable,
            summary=summary
        )
