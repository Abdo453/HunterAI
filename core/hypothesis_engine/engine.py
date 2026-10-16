"""
HunterAI Bayesian Hypothesis Engine (ACH - Analysis of Competing Hypotheses)
تحليل الفرضيات المتنافسة لتقليل الضوضاء وتحديد الفرضية الأقوى الأدلة
مقتبس من فكرة HunterAI Architecture Layer 3: Epistemic Reasoning Plane
"""
from __future__ import annotations

import logging
import math
import time
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum

log = logging.getLogger("hunter_ai.hypothesis")


class HypothesisStatus(str):
    ACTIVE = "active"
    SUPPORTED = "supported"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


@dataclass
class Evidence:
    """قطعة أدلة واحدة تدعم أو تدحض فرضية"""
    evidence_id: str
    description: str
    source: str
    strength: float  # 0.0 → 1.0: قوة الأدلة
    supports: bool  # True = تدعم الفرضية, False = تدحضها
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "evidence_id": self.evidence_id,
            "description": self.description,
            "source": self.source,
            "strength": self.strength,
            "supports": self.supports,
            "timestamp": self.timestamp,
        }


@dataclass
class Hypothesis:
    """فرضية أمنية واحدة"""
    hypothesis_id: str
    description: str
    prior_probability: float = 0.5  # 0.0 → 1.0: الاحتمال الأولي
    posterior_probability: float = 0.5  # الاحتمال النهائي بعد الأدلة
    status: str = HypothesisStatus.ACTIVE
    evidence: List[Evidence] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def add_evidence(self, evidence: Evidence):
        self.evidence.append(evidence)
        self.updated_at = time.time()
        self._update_probability()

    def _update_probability(self):
        """تحديث الاحتمال باستخدام Bayesian updating مبسط"""
        p = self.prior_probability
        for e in self.evidence:
            if e.supports:
                # الأدلة الداعمة تزيد الاحتمال
                likelihood_ratio = 1.0 + e.strength
                p = (p * likelihood_ratio) / (p * likelihood_ratio + (1 - p))
            else:
                # الأدلة المدحضة تقلل الاحتمال
                likelihood_ratio = 1.0 - e.strength
                p = (p * likelihood_ratio) / (p * likelihood_ratio + (1 - p))
        self.posterior_probability = round(p, 4)

        # تحديد الحالة بناءً على الاحتمال النهائي
        if p >= 0.75:
            self.status = HypothesisStatus.SUPPORTED
        elif p <= 0.25:
            self.status = HypothesisStatus.REFUTED
        elif p <= 0.40:
            self.status = HypothesisStatus.INCONCLUSIVE
        else:
            self.status = HypothesisStatus.ACTIVE

    def to_dict(self) -> dict:
        return {
            "hypothesis_id": self.hypothesis_id,
            "description": self.description,
            "prior_probability": self.prior_probability,
            "posterior_probability": self.posterior_probability,
            "status": self.status,
            "evidence_count": len(self.evidence),
            "evidence": [e.to_dict() for e in self.evidence],
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class HypothesisEngine:
    """
    محرك الفرضيات Bayesian — يدير فرضيات أمنية متعددة،
    يضيف الأدلة لكل فرضية، ويحدد الفرضية الأقوى بناءً على الأدلة.
    """

    def __init__(self):
        self.hypotheses: Dict[str, Hypothesis] = {}
        self._hypothesis_counter = 0

    def create_hypothesis(
        self,
        description: str,
        prior_probability: float = 0.5,
    ) -> str:
        """إنشاء فرضية جديدة وإرجاع معرفها"""
        self._hypothesis_counter += 1
        hyp_id = f"hyp_{self._hypothesis_counter:04d}"
        self.hypotheses[hyp_id] = Hypothesis(
            hypothesis_id=hyp_id,
            description=description,
            prior_probability=prior_probability,
        )
        log.debug(f"[HypothesisEngine] Created hypothesis {hyp_id}: {description}")
        return hyp_id

    def add_evidence_to_hypothesis(
        self,
        hypothesis_id: str,
        evidence_id: str,
        description: str,
        source: str,
        strength: float,
        supports: bool,
    ) -> bool:
        """إضافة أدلة لفرضية معينة"""
        hyp = self.hypotheses.get(hypothesis_id)
        if not hyp:
            return False

        evidence = Evidence(
            evidence_id=evidence_id,
            description=description,
            source=source,
            strength=strength,
            supports=supports,
        )
        hyp.add_evidence(evidence)
        return True

    def get_hypothesis(self, hypothesis_id: str) -> Optional[Hypothesis]:
        return self.hypotheses.get(hypothesis_id)

    def list_hypotheses(self) -> List[Hypothesis]:
        return list(self.hypotheses.values())

    def get_supported_hypotheses(self) -> List[Hypothesis]:
        """إرجاع الفرضيات المدعومة فقط (احتمال >= 0.75)"""
        return [h for h in self.hypotheses.values() if h.status == "supported"]

    def get_best_hypothesis(self) -> Optional[Hypothesis]:
        """إرجاع الفرضية ذات الاحتمال النهائي الأعلى"""
        if not self.hypotheses:
            return None
        return max(self.hypotheses.values(), key=lambda h: h.posterior_probability)

    def get_all_hypotheses_sorted(self) -> List[Hypothesis]:
        """إرجاع جميع الفرضيات مرتبة حسب الاحتمال النهائي تنازلياً"""
        return sorted(self.hypotheses.values(), key=lambda h: h.posterior_probability, reverse=True)

    def clear(self):
        self.hypotheses.clear()
        self._hypothesis_counter = 0

    def summary(self) -> dict:
        supported = len(self.get_supported_hypotheses())
        refuted = sum(1 for h in self.hypotheses.values() if h.status == "refuted")
        active = sum(1 for h in self.hypotheses.values() if h.status == "active")
        inconclusive = sum(1 for h in self.hypotheses.values() if h.status == "inconclusive")
        return {
            "total": len(self.hypotheses),
            "supported": supported,
            "refuted": refuted,
            "active": active,
            "inconclusive": inconclusive,
            "best_hypothesis": self.get_best_hypothesis().to_dict() if self.get_best_hypothesis() else None,
        }


# مثيل افتراضي يمكن استخدامه في toda the system
hypothesis_engine: Optional[HypothesisEngine] = None


def get_hypothesis_engine() -> HypothesisEngine:
    global hypothesis_engine
    if hypothesis_engine is None:
        hypothesis_engine = HypothesisEngine()
    return hypothesis_engine
