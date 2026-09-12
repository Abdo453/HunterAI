"""
Safety Rewriter
Converts aggressive or offensive testing prompts into authorized, defensive,
lab-oriented validation requests without attempting evasion or safety bypass.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

REWRITE_RULES = [
    (
        re.compile(r"""(?i)bypass\s+waf""", re.IGNORECASE),
        "evaluate WAF defensive filtering rules in an authorized test environment to measure detection coverage"
    ),
    (
        re.compile(r"""(?i)hack\s+(?:the\s+)?system""", re.IGNORECASE),
        "audit application security configuration and evaluate defensive controls"
    ),
    (
        re.compile(r"""(?i)exploit\s+(?:vulnerability|sql|rce|ssrf)""", re.IGNORECASE),
        "design a non-destructive verification proof using benign test inputs and provide remediation guidance"
    ),
    (
        re.compile(r"""(?i)dump\s+database""", re.IGNORECASE),
        "verify whether query parameters are properly isolated with parameterized statements"
    ),
]


@dataclass
class RewrittenTaskPlan:
    original_intent: str
    defensive_formulation: str
    testing_environment: str  # "owned_lab", "staging", "authorized_scope"
    safe_canary_definition: str
    remediation_focus: str


class SafetyRewriter:
    """
    محول ومراجع السلامة (Safety Rewriter):
    - لا يحاول أبداً التحايل على الـ AI أو إجباره على كسر القيود.
    - يحول نية الفحص إلى:
      1. تقييم دفاعي داخل معمل آمن (Lab Evaluation).
      2. اختبار غير تخريبي لقياس مدى فاعلية القواعد الوقائية.
      3. اقتراح إصلاحات وتصحيح تكوينات برمجية (Patching & Remediation).
    """

    @classmethod
    def rewrite_to_defensive_task(
        cls,
        raw_intent: str,
        target_env: str = "authorized_scope"
    ) -> RewrittenTaskPlan:
        rewritten = raw_intent
        for pattern, repl in REWRITE_RULES:
            rewritten = pattern.sub(repl, rewritten)

        # Standard safe canary definition
        canary = "benign alphanumeric marker ('HNT_CANARY_SAFE') with zero-noise payload"
        remediation = "Apply strict input allowlisting, prepared statements, and least-privilege authorization"

        return RewrittenTaskPlan(
            original_intent=raw_intent,
            defensive_formulation=rewritten.strip(),
            testing_environment=target_env,
            safe_canary_definition=canary,
            remediation_focus=remediation
        )
