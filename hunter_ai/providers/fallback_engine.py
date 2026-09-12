"""
HunterAI Failure Classifier & Smart Fallback Engine
Classifies model failures into:
- TIMEOUT
- CONTEXT_TOO_LARGE
- LOW_CONFIDENCE
- MODEL_ERROR
- UNSUPPORTED_CAPABILITY
- POLICY_BLOCK
- INVALID_OUTPUT
and determines the optimal recovery action instead of blindly switching models.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class FailureReason(str, Enum):
    TIMEOUT = "timeout"
    CONTEXT_TOO_LARGE = "context_too_large"
    LOW_CONFIDENCE = "low_confidence"
    MODEL_ERROR = "model_error"
    UNSUPPORTED_CAPABILITY = "unsupported_capability"
    POLICY_BLOCK = "policy_block"
    INVALID_OUTPUT = "invalid_output"
    NONE = "none"


class FallbackAction(str, Enum):
    COMPRESS_CONTEXT_AND_RETRY = "compress_context_and_retry"
    SWITCH_TO_CLOUD = "switch_to_cloud"
    SWITCH_TO_LOCAL = "switch_to_local"
    SWITCH_TO_DETERMINISTIC_RULES = "switch_to_deterministic_rules"
    HALT_AND_REPORT_ERROR = "halt_and_report_error"
    REPAIR_STRUCTURE = "repair_structure"


@dataclass
class FailureResolution:
    reason: FailureReason
    action: FallbackAction
    recommended_model: Optional[str] = None
    explanation: str = ""


class FallbackEngine:
    """
    محرك تصنيف الأخطاء والمعالجة التلقائية (Fallback Engine):
    - لا ينتقل للسحابة لمجرد اعتذار بسيط، بل يحدد طبيعة الفشل بالضبط.
    - يوجه النظام للحل الهندسي المناسب (ضغط السياق، إصلاح الـ JSON، أو تبديل الموديل).
    """

    @classmethod
    def diagnose_and_resolve(
        cls,
        error: Optional[Exception] = None,
        raw_output: str = "",
        context_tokens: int = 0,
        model_context_limit: int = 16384,
        confidence_score: float = 1.0,
        has_required_capability: bool = True
    ) -> FailureResolution:
        # 1. Capability check
        if not has_required_capability:
            return FailureResolution(
                reason=FailureReason.UNSUPPORTED_CAPABILITY,
                action=FallbackAction.SWITCH_TO_CLOUD,
                recommended_model="cloud/specialist_reasoning",
                explanation="Active model lacks declared capability for this task. Delegating to specialist cloud model."
            )

        # 2. Context limit exceeded
        if context_tokens > model_context_limit:
            return FailureResolution(
                reason=FailureReason.CONTEXT_TOO_LARGE,
                action=FallbackAction.COMPRESS_CONTEXT_AND_RETRY,
                explanation=f"Context tokens ({context_tokens}) exceed model limit ({model_context_limit}). Compressing payload before retry."
            )

        # 3. Timeout error
        if error and ("timeout" in str(error).lower() or "timed out" in str(error).lower()):
            return FailureResolution(
                reason=FailureReason.TIMEOUT,
                action=FallbackAction.SWITCH_TO_CLOUD,
                recommended_model="cloud/fast",
                explanation="Local model execution timed out. Switching to high-throughput cloud model."
            )

        # 4. Low confidence score
        if confidence_score < 0.60:
            return FailureResolution(
                reason=FailureReason.LOW_CONFIDENCE,
                action=FallbackAction.SWITCH_TO_CLOUD,
                recommended_model="cloud/deep_reasoning",
                explanation=f"Low initial confidence ({confidence_score:.2f}). Escalating to deep reasoning model for verification."
            )

        # 5. Invalid structured output (malformed JSON)
        if raw_output and "{" not in raw_output and "}" not in raw_output:
            return FailureResolution(
                reason=FailureReason.INVALID_OUTPUT,
                action=FallbackAction.REPAIR_STRUCTURE,
                explanation="Model did not return valid structured data. Passing to deterministic JSON repair parser."
            )

        # 6. Generic model error
        if error:
            return FailureResolution(
                reason=FailureReason.MODEL_ERROR,
                action=FallbackAction.SWITCH_TO_DETERMINISTIC_RULES,
                recommended_model="deterministic_rules",
                explanation=f"Model communication error ({error}). Activating deterministic heuristic fallback."
            )

        return FailureResolution(
            reason=FailureReason.NONE,
            action=FallbackAction.HALT_AND_REPORT_ERROR,
            explanation="No actionable failure detected."
        )
