"""
Epistemic Uncertainty & Shannon Entropy Model
Quantifies epistemic uncertainty across competing security hypotheses:
Computes Shannon entropy H(B), normalized entropy, and information delta.
"""
import math
import logging
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field

log = logging.getLogger("core.reasoning.uncertainty")


class EntropyRecord(BaseModel):
    """
    سجل التغير في إنتروبيا الشك وكمية المعلومات المستفادة
    """
    prior_entropy: float
    posterior_entropy: float
    entropy_delta: float          # Information gain in bits (prior - post)
    normalized_entropy: float     # In range [0.0, 1.0]

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class UncertaintyModel:
    """
    نموذج عدم اليقين المعرفي:
    يحسب إنتروبيا شانون على فضاء الفرضيات المتنافسة
    H(B) = - sum( p_i * log2(p_i) )
    """

    @staticmethod
    def compute_entropy(distribution: Dict[str, float]) -> float:
        """
        حساب إنتروبيا شانون (Shannon Entropy):
        H = 0 تعني يقيناً تاماً (فرضية واحدة مؤكدة 100%)
        H = log2(N) تعني أقصى درجات الشك (توزيع متساوٍ Uniform)
        """
        if not distribution or len(distribution) <= 1:
            return 0.0

        total = sum(distribution.values())
        if total <= 0.0:
            return 0.0

        entropy = 0.0
        for p in distribution.values():
            prob = p / total
            if prob > 1e-9:
                entropy -= prob * math.log2(prob)

        return round(max(0.0, entropy), 4)

    @staticmethod
    def compute_normalized_entropy(distribution: Dict[str, float]) -> float:
        """
        الإنتروبيا المعيارية في النطاق [0.0, 1.0]:
        1.0 تعني جهلاً تاماً وتساوياً في الشك بين كل الفرضيات
        0.0 تعني استقراراً ويقيناً كاملاً
        """
        n = len(distribution)
        if n <= 1:
            return 0.0

        h = UncertaintyModel.compute_entropy(distribution)
        max_h = math.log2(n)
        if max_h <= 0.0:
            return 0.0

        return round(min(1.0, max(0.0, h / max_h)), 4)

    @staticmethod
    def record_transition(
        prior_dist: Dict[str, float],
        posterior_dist: Dict[str, float]
    ) -> EntropyRecord:
        """
        حساب مقدار انخفاض الشك (Information Gain) بعد تنفيذ فحص أو ورود دليل
        """
        prior_h = UncertaintyModel.compute_entropy(prior_dist)
        post_h = UncertaintyModel.compute_entropy(posterior_dist)
        delta = round(prior_h - post_h, 4)
        norm_h = UncertaintyModel.compute_normalized_entropy(posterior_dist)

        return EntropyRecord(
            prior_entropy=prior_h,
            posterior_entropy=post_h,
            entropy_delta=delta,
            normalized_entropy=norm_h
        )
