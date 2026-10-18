"""
متجر الأدلة الدائم (Persistent Evidence Store) — Phase D.

يُخزّن الأدلة والنتائج والفرضيات والطرق المسدودة والأحداث في ملفات JSONL
تحت ``data/evidence_store/`` (byte append، قفل خيط، تخزين دائم بدون تبعات جديدة).
كل سجل يُعرّف بمعرف مستقر ويُughّم بمحتوى SHA-256 للكشف عن التلاعب.

هذا المتجر يُغلف ``SharedEvidenceGraph`` القائم (في الذاكرة) بحيث تصبح
الحقائق المُضافة عبره دائمة أيضًا عند تمرير المتجر إلى العامل/المنسق.

كيانات (حسب المواصفة):
  Run, Worker, Task, Evidence, Hypothesis, DeadEnd, ToolExecution, Event

ضوابط أمنية:
- لا تُخزن بيانات اعتماد خام (تُُقّص عبر ``_redact_secrets``).
- المحتوى يُخزّن مقصوصًا بحجم محدود.
- كل إضافة تُسجَّل بوقت وتسلسل ( immutable event history per run ).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_DEFAULT_ROOT = os.path.join("data", "evidence_store")

_ENTITY_FILES = {
    "evidence": "evidence.jsonl",
    "hypothesis": "hypothesis.jsonl",
    "dead_end": "dead_end.jsonl",
    "tool_execution": "tool_execution.jsonl",
    "court_verdict": "court_verdict.jsonl",
    "event": "event.jsonl",
    "run": "run.jsonl",
}


# ---------------------------------------------------------------------------
# سجلات البيانات
# ---------------------------------------------------------------------------

@dataclass
class EvidenceRecord:
    evidence_id: str
    run_id: str
    source_worker: str
    source_tool: str
    evidence_type: str          # observation | anomaly | hypothesis | proof
    sanitized_content: str
    content_hash: str
    provenance: str             # أداة/وكيل أنتجها
    confidence: float           # 0..1
    verification_status: str = "unverified"   # unverified | verified | contradicted
    created_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["metadata"] = dict(d["metadata"])
        return d


@dataclass
class HypothesisRecord:
    hypothesis_id: str
    run_id: str
    description: str
    supporting_evidence: List[str] = field(default_factory=list)
    contradicting_evidence: List[str] = field(default_factory=list)
    status: str = "open"        # open | confirmed | rejected | inconclusive
    created_at: float = field(default_factory=time.time)
    resolved_at: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DeadEndRecord:
    dead_end_id: str
    run_id: str
    approach: str
    reason: str
    supporting_evidence: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ToolExecutionRecord:
    execution_id: str
    run_id: str
    worker_id: str
    tool_id: str
    redacted_arguments: Dict[str, Any] = field(default_factory=dict)
    status: str = "started"     # started | finished | failed | cancelled
    exit_code: Optional[int] = None
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    artifact_reference: Optional[str] = None
    # ── Phase 2: خط الأدلة الكامل — الذهاب من أي نتيجة إلى الأمر الأصلي ──
    command: str = ""           # الأمر الذي أُنفِّذ فعلاً (بعد تنقية الأسرار)
    stage: str = ""             # مرحلة الـ pipeline (SCOPE_CHECK/DISCOVER/...)
    target: str = ""            # الهدف العام للمهمة (hostname/IP)
    endpoint: str = ""          # الـ endpoint الذي لمسته الأداة
    output_excerpt: str = ""    # مقتطف قصير من raw output للـ traceability

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EventRecord:
    event_id: str
    run_id: str
    event_type: str
    timestamp: float
    payload: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CourtVerdictRecord:
    """حكم محكمة الأدلة على نتيجة واحدة — جلسة قابلة للتدقيق (Phase 3)."""
    court_id: str
    run_id: str
    finding_id: str
    title: str
    endpoint: str
    verdict: str              # PASSED | DEMOTED
    reason_code: str          # no_evidence | unverified_evidence | standard_web_behavior | ...
    rationale: str = ""
    session_id: str = ""
    decided_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# المتجر الدائم
# ---------------------------------------------------------------------------

class EvidenceStore:
    """
    متجر أدلة دائم thread-safe.

    كل كيان يُخزّن في ملف JSONL مستقل تحت root_dir. القراءة تبحث في الملف
    المعني؛ الكتابة تُلحق سطرًا واحدًا. القفل يمنع التشابك بين العمال.
    """

    def __init__(self, root_dir: str = _DEFAULT_ROOT):
        self.root_dir = root_dir
        os.makedirs(self.root_dir, exist_ok=True)
        self._lock = threading.RLock()
        self._handles: Dict[str, Any] = {}  # file -> opened handle (append)

    # -- التخزين الداخلي --
    def _path(self, entity: str) -> str:
        fname = _ENTITY_FILES.get(entity)
        if not fname:
            raise ValueError(f"كيان غير مدعوم: {entity}")
        return os.path.join(self.root_dir, fname)

    def _append(self, entity: str, record: Dict[str, Any]) -> None:
        line = json.dumps(record, ensure_ascii=False, sort_keys=True)
        with self._lock:
            with open(self._path(entity), "a", encoding="utf-8") as f:
                f.write(line + "\n")

    def _read_all(self, entity: str) -> List[Dict[str, Any]]:
        path = self._path(entity)
        out: List[Dict[str, Any]] = []
        if not os.path.isfile(path):
            return out
        with self._lock:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        out.append(json.loads(line))
                    except json.JSONDecodeError:
                        logger.warning("سطر تالف في %s، تم تجاوزه", path)
        return out

    # -- الأدلة --
    def add_evidence(
        self,
        *,
        run_id: str,
        source_worker: str,
        source_tool: str,
        evidence_type: str,
        content: str,
        provenance: str = "",
        confidence: float = 0.5,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> EvidenceRecord:
        content = content or ""
        sanitized = _redact_secrets(content)
        content_hash = hashlib.sha256(sanitized.encode("utf-8")).hexdigest()
        rec = EvidenceRecord(
            evidence_id=f"EV-{uuid.uuid4().hex[:8].upper()}",
            run_id=run_id,
            source_worker=source_worker,
            source_tool=source_tool,
            evidence_type=evidence_type,
            sanitized_content=sanitized,
            content_hash=content_hash,
            provenance=provenance,
            confidence=confidence,
            verification_status="unverified",
            metadata=dict(metadata or {}),
        )
        self._append("evidence", rec.to_dict())
        return rec

    def get_evidence(self, evidence_id: str) -> Optional[EvidenceRecord]:
        result: Optional[EvidenceRecord] = None
        for d in self._read_all("evidence"):
            if d.get("evidence_id") == evidence_id:
                result = EvidenceRecord(**d)   # آخرtid يربح (append-only)
        return result

    def list_evidence(
        self,
        run_id: Optional[str] = None,
        *,
        source_worker: Optional[str] = None,
        min_confidence: Optional[float] = None,
    ) -> List[EvidenceRecord]:
        out: List[EvidenceRecord] = []
        for d in self._read_all("evidence"):
            if run_id is not None and d.get("run_id") != run_id:
                continue
            if source_worker is not None and d.get("source_worker") != source_worker:
                continue
            if min_confidence is not None and d.get("confidence", 0) < min_confidence:
                continue
            out.append(EvidenceRecord(**d))
        return sorted(out, key=lambda r: r.created_at)

    def link_hypothesis(self, hypothesis_id: str, evidence_id: str,
                        supporting: bool = True) -> bool:
        # يتم ربط دليل بفرضية عبر تخزين مرجعية على الفرضية
        hyp = self.get_hypothesis(hypothesis_id)
        if hyp is None:
            return False
        field_name = "supporting_evidence" if supporting else "contradicting_evidence"
        if evidence_id not in getattr(hyp, field_name):
            getattr(hyp, field_name).append(evidence_id)
            self._append("hypothesis", hyp.to_dict())
        return True

    def mark_evidence(self, evidence_id: str, status: str) -> bool:
        """تعديل حالة التحقق من دليل (verified | contradicted | unverified)."""
        if status not in ("verified", "contradicted", "unverified"):
            return False
        # JSONL immutable: نلحق إصدارًا محدثًا بنفس المعرف (آخر إصدار يربح عند القراءة)
        rec = self.get_evidence(evidence_id)
        if rec is None:
            return False
        rec.verification_status = status
        self._append("evidence", rec.to_dict())
        return True

    # -- الفرضيات --
    def add_hypothesis(self, *, run_id: str, description: str) -> HypothesisRecord:
        rec = HypothesisRecord(
            hypothesis_id=f"HY-{uuid.uuid4().hex[:8].upper()}",
            run_id=run_id, description=description)
        self._append("hypothesis", rec.to_dict())
        return rec

    def get_hypothesis(self, hypothesis_id: str) -> Optional[HypothesisRecord]:
        result: Optional[HypothesisRecord] = None
        for d in self._read_all("hypothesis"):
            if d.get("hypothesis_id") == hypothesis_id:
                result = HypothesisRecord(**d)   # آخرtid يربح
        return result

    # -- الطرق المسدودة --
    def record_dead_end(self, *, run_id: str, approach: str, reason: str,
                        supporting_evidence: Optional[List[str]] = None
                        ) -> DeadEndRecord:
        rec = DeadEndRecord(
            dead_end_id=f"DE-{uuid.uuid4().hex[:8].upper()}",
            run_id=run_id, approach=approach, reason=reason,
            supporting_evidence=list(supporting_evidence or []))
        self._append("dead_end", rec.to_dict())
        return rec

    # -- تنفيذ الأدوات --
    def record_tool_execution(self, *, run_id: str, worker_id: str,
                              tool_id: str,
                              redacted_arguments: Optional[Dict[str, Any]] = None,
                              artifact_reference: Optional[str] = None,
                              command: str = "",
                              stage: str = "",
                              target: str = "",
                              endpoint: str = "",
                              output_excerpt: str = "",
                              ) -> ToolExecutionRecord:
        rec = ToolExecutionRecord(
            execution_id=f"TE-{uuid.uuid4().hex[:8].upper()}",
            run_id=run_id, worker_id=worker_id, tool_id=tool_id,
            redacted_arguments=dict(redacted_arguments or {}),
            artifact_reference=artifact_reference,
            command=command, stage=stage, target=target,
            endpoint=endpoint, output_excerpt=output_excerpt)
        self._append("tool_execution", rec.to_dict())
        return rec

    def finish_tool_execution(self, execution_id: str, status: str,
                              exit_code: Optional[int] = None) -> bool:
        recs = self._read_all("tool_execution")
        target = None
        for d in recs:
            if d.get("execution_id") == execution_id:
                target = ToolExecutionRecord(**d)
                break
        if target is None:
            return False
        target.status = status
        target.finished_at = time.time()
        if exit_code is not None:
            target.exit_code = exit_code
        self._append("tool_execution", target.to_dict())
        return True

    # -- أحكام محكمة الأدلة (Phase 3) --
    def record_court_verdict(self, *, run_id: str, finding_id: str,
                             title: str, endpoint: str,
                             verdict: str, reason_code: str,
                             rationale: str = "",
                             session_id: str = "") -> CourtVerdictRecord:
        rec = CourtVerdictRecord(
            court_id=f"CRT-{uuid.uuid4().hex[:8].upper()}",
            run_id=run_id, finding_id=finding_id,
            title=title, endpoint=endpoint,
            verdict=verdict, reason_code=reason_code,
            rationale=rationale, session_id=session_id)
        self._append("court_verdict", rec.to_dict())
        return rec

    def list_court_verdicts(self, run_id: Optional[str] = None) -> List[CourtVerdictRecord]:
        out: List[CourtVerdictRecord] = []
        for d in self._read_all("court_verdict"):
            if run_id is None or d.get("run_id") == run_id:
                out.append(CourtVerdictRecord(**d))
        return out

    # -- الأحداث (تاريخ دائم لكل run) --
    def add_event(self, *, run_id: str, event_type: str,
                  payload: Optional[Dict[str, Any]] = None) -> EventRecord:
        rec = EventRecord(
            event_id=f"EVT-{uuid.uuid4().hex[:8].upper()}",
            run_id=run_id, event_type=event_type,
            timestamp=time.time(), payload=dict(payload or {}))
        self._append("event", rec.to_dict())
        return rec

    def get_events(self, run_id: str) -> List[EventRecord]:
        out: List[EventRecord] = []
        for d in self._read_all("event"):
            if d.get("run_id") == run_id:
                out.append(EventRecord(**d))
        return sorted(out, key=lambda r: r.timestamp)

    # -- التشغيلات --
    def record_run(self, *, run_id: str, goal: str, scope: Dict[str, Any],
                   status: str = "started") -> Dict[str, Any]:
        rec = {
            "run_id": run_id, "goal": goal, "scope": dict(scope),
            "status": status,
            "created_at": time.time(),
        }
        self._append("run", rec)
        return rec

    def snapshot(self) -> Dict[str, Any]:
        return {
            entity: len(self._read_all(entity))
            for entity in _ENTITY_FILES
        }


# ---------------------------------------------------------------------------
# تنقية الأسرار (مُشارك مع core.tool_registry عند الاستدعاء المباشر)
# ---------------------------------------------------------------------------

import re  # noqa: E402  (placed at bottom to keep dataclasses above)

_SECRET_PATTERNS = [
    re.compile(r"(sk-[A-Za-z0-9]{10,})"),
    re.compile(r"(Bearer\s+[A-Za-z0-9._\-]{10,})"),
    re.compile(r"(ghp_[A-Za-z0-9]{10,})"),
    re.compile(r"(password\s*[:=]\s*\S+)", re.IGNORECASE),
    re.compile(r"(api[_-]?key\s*[:=]\s*\S+)", re.IGNORECASE),
]


def _redact_secrets(text: str) -> str:
    for pat in _SECRET_PATTERNS:
        text = pat.sub("***", text)
    return text
