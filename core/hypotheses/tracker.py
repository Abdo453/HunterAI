"""
Hypothesis State Machine & Lifecycle Tracker
Manages hypotheses across their epistemic states:
UNTESTED -> IN_PROGRESS -> VALIDATED / REFUTED / CONTRADICTED
"""
import uuid
import time
from enum import Enum
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field


class HypothesisState(str, Enum):
    UNTESTED = "UNTESTED"           # Newly generated from graph topology or observation
    IN_PROGRESS = "IN_PROGRESS"     # Currently being probed by specialist agent
    VALIDATED = "VALIDATED"         # Conclusive evidence collected (differential verified)
    REFUTED = "REFUTED"             # Direct evidence proved non-vulnerable / 404 / filtered
    CONTRADICTED = "CONTRADICTED"   # Defensive behavior contradicts vulnerability assumptions


class TrackedHypothesis(BaseModel):
    """
    الفرضية الأمنية المتابعة بدقة في فضاء المعرفة
    """
    id: str = Field(default_factory=lambda: f"HYP-{uuid.uuid4().hex[:8]}")
    title: str
    vuln_type: str
    target_node_id: str
    target_endpoint: str
    prior_probability: float = 0.50
    posterior_probability: float = 0.50
    status: HypothesisState = HypothesisState.UNTESTED
    required_evidence_types: List[str] = Field(default_factory=list)
    supporting_evidence_ids: List[str] = Field(default_factory=list)
    contradicting_evidence_ids: List[str] = Field(default_factory=list)
    experiment_log: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)


class HypothesisTracker:
    """
    بنك الفرضيات النشطة:
    يتتبع دورة حياة كل فرضية أمنية وتاريخ التجارب المنفذة عليها
    """

    def __init__(self):
        self.hypotheses: Dict[str, TrackedHypothesis] = {}

    def register_hypothesis(self, hyp: TrackedHypothesis) -> TrackedHypothesis:
        self.hypotheses[hyp.id] = hyp
        return hyp

    def get_hypothesis(self, hyp_id: str) -> Optional[TrackedHypothesis]:
        return self.hypotheses.get(hyp_id)

    def update_status(
        self,
        hyp_id: str,
        new_status: HypothesisState,
        note: str = ""
    ) -> Optional[TrackedHypothesis]:
        hyp = self.hypotheses.get(hyp_id)
        if not hyp:
            return None
        prev = hyp.status
        hyp.status = new_status
        hyp.updated_at = time.time()
        hyp.experiment_log.append({
            "timestamp": hyp.updated_at,
            "action": "status_transition",
            "from_status": prev.value,
            "to_status": new_status.value,
            "note": note
        })
        return hyp

    def record_evidence_link(
        self,
        hyp_id: str,
        evidence_id: str,
        is_supporting: bool,
        new_posterior: Optional[float] = None
    ) -> Optional[TrackedHypothesis]:
        hyp = self.hypotheses.get(hyp_id)
        if not hyp:
            return None
        if is_supporting:
            if evidence_id not in hyp.supporting_evidence_ids:
                hyp.supporting_evidence_ids.append(evidence_id)
        else:
            if evidence_id not in hyp.contradicting_evidence_ids:
                hyp.contradicting_evidence_ids.append(evidence_id)

        if new_posterior is not None:
            hyp.posterior_probability = max(0.0, min(1.0, new_posterior))

        hyp.updated_at = time.time()
        return hyp

    def get_top_hypotheses(self, n: int = 5) -> List[TrackedHypothesis]:
        """إرجاع الفرضيات الأعلى احتمالية التي لا تزال قابلة للاختبار"""
        active = [h for h in self.hypotheses.values() if h.status in [HypothesisState.UNTESTED, HypothesisState.IN_PROGRESS]]
        active.sort(key=lambda h: h.posterior_probability, reverse=True)
        return active[:n]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_count": len(self.hypotheses),
            "status_breakdown": {
                s.value: len([h for h in self.hypotheses.values() if h.status == s])
                for s in HypothesisState
            },
            "hypotheses": [h.model_dump() for h in self.hypotheses.values()]
        }
