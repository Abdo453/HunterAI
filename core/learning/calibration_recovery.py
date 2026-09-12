"""
Confidence Calibration & Failure Recovery Engine
1. ConfidenceCalibrationTracker: Measures Expected Calibration Error (ECE) across probability bins.
2. FailureRecoveryEngine: Detects hypothesis refutation, prevents repetitive looping,
   and abductively spawns alternative hypotheses upon dead ends.
"""
import math
import logging
from typing import Dict, List, Any, Optional, Tuple
from pydantic import BaseModel, Field

from core.hypotheses.tracker import HypothesisState

log = logging.getLogger("core.learning.calibration_recovery")


class CalibrationBin(BaseModel):
    bin_lower: float
    bin_upper: float
    count: int = 0
    correct_count: int = 0
    total_confidence: float = 0.0

    @property
    def empirical_accuracy(self) -> float:
        return self.correct_count / self.count if self.count > 0 else 0.0

    @property
    def mean_confidence(self) -> float:
        return self.total_confidence / self.count if self.count > 0 else 0.0


class ConfidenceCalibrationTracker:
    """
    متتبع معايرة الثقة الاحتمالية:
    يحسب Expected Calibration Error (ECE) لمعرفة هل ثقة الـ Agent تمثل الحقيقة بدقة
    """

    def __init__(self, num_bins: int = 5):
        self.num_bins = num_bins
        self.bins: List[CalibrationBin] = []
        step = 1.0 / num_bins
        for i in range(num_bins):
            self.bins.append(CalibrationBin(
                bin_lower=round(i * step, 2),
                bin_upper=round((i + 1) * step, 2)
            ))

    def record_prediction(self, confidence: float, actual_correct: bool):
        """تسجيل توقع احتمالي والنتيجة الفعلية"""
        clamped_conf = min(1.0, max(0.0, confidence))
        for b in self.bins:
            if b.bin_lower <= clamped_conf <= b.bin_upper:
                b.count += 1
                b.total_confidence += clamped_conf
                if actual_correct:
                    b.correct_count += 1
                break

    def compute_ece(self) -> float:
        """
        حساب خطأ المعايرة المتوقع (Expected Calibration Error):
        ECE = sum ( (count_m / N) * | acc_m - conf_m | )
        0.0 تعني معايرة مثالية 100%
        """
        total_samples = sum(b.count for b in self.bins)
        if total_samples == 0:
            return 0.0

        ece = 0.0
        for b in self.bins:
            if b.count > 0:
                weight = b.count / total_samples
                gap = abs(b.empirical_accuracy - b.mean_confidence)
                ece += weight * gap

        return round(ece, 4)


class RecoveryDecision(BaseModel):
    refuted_hypothesis: str
    action_taken: str                  # DISCARD_AND_PIVOT, SWITCH_TO_EXPLORATION
    alternative_hypotheses: List[str]
    justification: str


class FailureRecoveryEngine:
    """
    محرك التعافي من الفشل وإعادة توجيه الفرضيات:
    يمنع الـ Agent من تكرار محاولات فاشلة عندما ينخفض احتمال الفرضية
    """

    @staticmethod
    def handle_refutation(
        refuted_hypothesis: str,
        prior_probability: float,
        current_probability: float,
        observed_signals: List[str]
    ) -> Optional[RecoveryDecision]:
        """
        فحص هل انهارت الفرضية تحت عتبة الثقة (مثلاً P < 0.15)
        واستدعاء فرضيات بديلة منطقية
        """
        if current_probability >= 0.20:
            return None  # Hypothesis still viable

        # Generate contextual alternative hypotheses based on observed context
        alternatives = []
        if "sql" in refuted_hypothesis.lower():
            alternatives = [
                "Safe_Parameterized_Query",
                "WAF_Input_Normalization_Block",
                "Application_Validation_Rejection"
            ]
        elif "bola" in refuted_hypothesis.lower():
            alternatives = [
                "Strict_Tenant_Authorization_Enforced",
                "Public_Shared_Static_Resource"
            ]
        else:
            alternatives = ["Generic_Application_Defense", "Static_Endpoint"]

        justification = (
            f"Hypothesis '{refuted_hypothesis}' collapsed from P={prior_probability:.2f} "
            f"to P={current_probability:.2f}. Discarding and pivoting to alternative hypotheses: "
            f"{', '.join(alternatives)}."
        )

        return RecoveryDecision(
            refuted_hypothesis=refuted_hypothesis,
            action_taken="DISCARD_AND_PIVOT",
            alternative_hypotheses=alternatives,
            justification=justification
        )
