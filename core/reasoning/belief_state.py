"""
Belief State & Versioned Epistemic History Engine
Maintains an append-only, versioned representation of the agent's world model:
Hypotheses probability distributions, verified empirical Facts, pending Unknowns, and raw Observations.
Supports forensic replay of reasoning decisions at any historical version.
"""
import copy
import time
import uuid
from typing import Dict, List, Set, Any, Optional
from pydantic import BaseModel, Field


class BeliefSnapshot(BaseModel):
    """
    لقطة غير قابلة للتعديل تمثل حالة المعرفة عند إصدار زمني محدد
    """
    version: int
    timestamp: float = Field(default_factory=time.time)
    hypotheses: Dict[str, float] = Field(default_factory=dict)  # normalized P(H)
    facts: List[str] = Field(default_factory=list)
    unknowns: List[str] = Field(default_factory=list)
    observations_count: int = 0
    action_taken: Optional[str] = None
    justification: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class BeliefState:
    """
    حالة المعتقد والمعرفة الاستقصائية (Epistemic Belief State):
    تحفظ توزيع احتمالات الفرضيات، الحقائق المثبتة، والمجاهيل، مع سجل زمني تسلسلي
    """

    def __init__(self, investigation_id: Optional[str] = None):
        self.investigation_id = investigation_id or f"INV-{uuid.uuid4().hex[:8]}"
        self.version = 0
        self.hypotheses: Dict[str, float] = {}  # {hypothesis_id: probability}
        self.facts: Set[str] = set()
        self.unknowns: Set[str] = set()
        self.observations: List[Dict[str, Any]] = []
        self.evidence_refs: List[str] = []
        self.history: List[BeliefSnapshot] = []

        # Record initial baseline v0
        self._commit_snapshot(justification="Initial Epistemic State")

    def set_hypotheses(self, hyps: Dict[str, float], justification: str = "", action_taken: Optional[str] = None):
        """
        تحديث توزيع احتمالات الفرضيات مع التطبيع الصارم ليكون مجموعها 1.0
        """
        if not hyps:
            self.hypotheses = {}
        else:
            total = sum(hyps.values())
            if total > 0.0:
                self.hypotheses = {h: round(p / total, 4) for h, p in hyps.items()}
            else:
                uniform = round(1.0 / len(hyps), 4)
                self.hypotheses = {h: uniform for h in hyps}

        self.version += 1
        self._commit_snapshot(justification=justification, action_taken=action_taken)

    def add_fact(self, fact: str, justification: str = ""):
        """إضافة حقيقة مثبتة وإزالتها من قائمة المجاهيل إن وجدت"""
        if fact not in self.facts:
            self.facts.add(fact)
            self.unknowns.discard(fact)
            self.version += 1
            self._commit_snapshot(justification=justification or f"Added fact: {fact}")

    def add_unknown(self, unknown: str):
        """تسجيل مجهول يحتاج إلى استكشاف أو فحص"""
        if unknown not in self.facts:
            self.unknowns.add(unknown)

    def add_observation(self, observation: Dict[str, Any]):
        """تسجيل ملاحظة حسية خام جديدة"""
        self.observations.append({
            "timestamp": time.time(),
            "version": self.version,
            "data": observation
        })

    def link_evidence(self, evidence_id: str):
        """ربط مرجع دليل جنائي معتمد بالحالة"""
        if evidence_id not in self.evidence_refs:
            self.evidence_refs.append(evidence_id)

    def replay(self, version: int) -> Optional[BeliefSnapshot]:
        """
        إعادة تشغيل وتفقد الحالة المعرفية بدقة عند أي إصدار سابق
        """
        for snap in self.history:
            if snap.version == version:
                return snap
        return None

    def get_latest_snapshot(self) -> BeliefSnapshot:
        return self.history[-1]

    def _commit_snapshot(self, justification: str = "", action_taken: Optional[str] = None):
        snapshot = BeliefSnapshot(
            version=self.version,
            timestamp=time.time(),
            hypotheses=dict(self.hypotheses),
            facts=sorted(list(self.facts)),
            unknowns=sorted(list(self.unknowns)),
            observations_count=len(self.observations),
            action_taken=action_taken,
            justification=justification
        )
        self.history.append(snapshot)
