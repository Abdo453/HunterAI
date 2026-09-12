"""
Refusal & Safety Filter Detector
Detects AI model refusal signatures ("I cannot fulfill", "ethical guidelines", "as an AI language model", etc.)
and triggers automated fallback to local models or deterministic security heuristics.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import List, Tuple

logger = logging.getLogger(__name__)

# Signatures indicative of an AI safety refusal rather than a genuine technical response
REFUSAL_SIGNATURES = [
    re.compile(r"i cannot (?:assist|help|fulfill|provide|generate|comply)", re.IGNORECASE),
    re.compile(r"i am unable to (?:assist|help|fulfill|provide|generate)", re.IGNORECASE),
    re.compile(r"against (?:my|our) (?:safety|ethical|content) (?:guidelines|policies)", re.IGNORECASE),
    re.compile(r"(?:violate|violates) (?:safety|usage) policies", re.IGNORECASE),
    re.compile(r"as an ai language model", re.IGNORECASE),
    re.compile(r"cannot assist with (?:hacking|cyberattacks|exploits|penetration)", re.IGNORECASE),
    re.compile(r"i'm sorry, but i can't assist with that", re.IGNORECASE),
    re.compile(r"cannot provide instructions for (?:attacking|compromising|bypassing)", re.IGNORECASE),
    re.compile(r"sorry, but i cannot", re.IGNORECASE),
]


@dataclass
class RefusalCheckResult:
    is_refusal: bool
    matched_signature: str = ""
    confidence: float = 0.0
    snippet: str = ""


class RefusalDetector:
    """
    كاشف رفض نماذج الذكاء الاصطناعي (Refusal Detector):
    - يحلل النص العائد من النموذج بدقة لاكتشاف ما إذا كان النموذج قد اعتذر أو رفض الإجابة.
    - يُميّز بين الرد الفني الحقيقي واعتذارات فلاتر الأمان التلقائية.
    """

    @classmethod
    def check_response(cls, response_text: str) -> RefusalCheckResult:
        if not response_text or len(response_text.strip()) == 0:
            return RefusalCheckResult(
                is_refusal=True,
                matched_signature="EMPTY_RESPONSE",
                confidence=1.0,
                snippet="Empty or null response received from AI model."
            )

        text_sample = response_text[:500].strip()

        for pattern in REFUSAL_SIGNATURES:
            match = pattern.search(text_sample)
            if match:
                logger.warning(f"[RefusalDetector] AI Refusal detected: '{match.group(0)}'")
                return RefusalCheckResult(
                    is_refusal=True,
                    matched_signature=match.group(0),
                    confidence=0.98,
                    snippet=text_sample[:150]
                )

        # If response is extremely short and contains negative apologies
        if len(text_sample) < 100 and any(w in text_sample.lower() for w in ["sorry", "apologize", "cannot fulfill"]):
            return RefusalCheckResult(
                is_refusal=True,
                matched_signature="SHORT_APOLOGY",
                confidence=0.85,
                snippet=text_sample
            )

        return RefusalCheckResult(
            is_refusal=False,
            matched_signature="",
            confidence=0.0,
            snippet=""
        )
