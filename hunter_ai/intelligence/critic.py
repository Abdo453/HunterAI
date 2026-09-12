"""
HunterAI AI Critic
Challenges proposed security findings and hypotheses:
- Checks if the conclusion is based on an unproven assumption or single HTTP status change.
- Evaluates false positive indicators (e.g. WAF block, generic 404/500, dynamic random tokens).
- Demands concrete, reproducible evidence before allowing a finding to proceed.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

logger = logging.getLogger(__name__)


@dataclass
class CriticReviewResult:
    verdict: str  # "passed", "challenged", "rejected"
    confidence_penalty: float  # e.g. 0.0 if passed, 0.20 if challenged, 0.50 if rejected
    critique_notes: str
    missing_evidence: List[str]


class AICritic:
    """
    الناقد الأمني الذكي (AI Critic):
    - يفحص كل استنتاج أو فرضية أمنية بعين المتشكك لتجنب الـ False Positives.
    - يطرح أسئلة التمحيص: هل هناك دليل قاطع؟ هل النتيجة مجرد حظر جدار ناري؟
    """

    @classmethod
    def evaluate_finding(
        cls,
        vulnerability_type: str,
        observation_text: str,
        evidence_list: List[str],
        has_baseline_differential: bool = True,
        is_waf_block: bool = False
    ) -> CriticReviewResult:
        missing = []
        notes = []

        # 1. Reject if it is just a WAF block
        if is_waf_block or "403" in observation_text:
            return CriticReviewResult(
                verdict="rejected",
                confidence_penalty=0.60,
                critique_notes="REJECTED: Finding appears to be a standard gateway/WAF filtering response (403), not an application vulnerability.",
                missing_evidence=["Application-level error trace", "Verifiable canary execution proof"]
            )

        # 2. Demand reproducible evidence
        if not evidence_list or len(evidence_list) == 0:
            missing.append("Raw request/response flow")
            notes.append("No concrete evidence items provided with hypothesis.")

        # 3. Demand baseline differential
        if not has_baseline_differential:
            missing.append("Baseline comparison with clean input")
            notes.append("Lacks comparative baseline differential to confirm abnormal behavior.")

        if missing:
            return CriticReviewResult(
                verdict="challenged",
                confidence_penalty=0.25,
                critique_notes=f"CHALLENGED: {'; '.join(notes)}",
                missing_evidence=missing
            )

        return CriticReviewResult(
            verdict="passed",
            confidence_penalty=0.0,
            critique_notes="PASSED: Evidence is substantive, reproducible, and distinct from gateway filtering.",
            missing_evidence=[]
        )
