"""الرسم البياني المشترك للإثباتات (Shared Evidence Graph) — Phase 7.

يوحّد التعاون بين الوكلاء عبر حالة مشتركة بدل الـ blackboards المكررة:
- Facts  : حقائق مُتحقَّق منها (بمصدر ودرجة ثقة) — الـ workers يقرؤونها ويبنون عليها
- Intents: نوايا خطة قيد التنفيذ (لمنع تكرار العمل)
- Locks  : أقفال موارد (target/tool) لمنع تضارب الوكلاء
- InsightBus: نشر اكتشافات فورية لجميع المشتركين

تصميم آمن: كل كتابة تحمل source وconfidence، والقراءة تحترم الحد الأدنى.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set


@dataclass(frozen=True)
class Fact:
    """حقيقة مُتحقَّق منها — الوحدة الأساسية للمعرفة المشتركة."""

    key: str                 # مفتاح منطقي موحد (مثل "port:443", "vuln:sqli:/login")
    value: str
    source: str = ""         # أي وكيل/أداة أنتجها
    confidence: float = 1.0  # 0..1
    created_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key, "value": self.value, "source": self.source,
            "confidence": round(self.confidence, 3),
            "created_at": self.created_at, "metadata": self.metadata,
        }


@dataclass
class Intent:
    """نية خطة قيد التنفيذ — تمنع تكرار العمل بين الوكلاء."""

    intent_id: str
    description: str
    owner: str = ""          # الوكيل المسؤول
    target: str = ""
    state: str = "planned"   # planned | active | done | failed
    created_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None


class SharedEvidenceGraph:
    """رسم بياني مشترك thread-safe للإثباتات والنية والاقفال."""

    def __init__(
        self,
        *,
        min_confidence: float = 0.5,
        on_fact: Optional[Callable[[Fact], None]] = None,
        on_insight: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    ):
        self.min_confidence = min_confidence
        self.on_fact = on_fact
        self.on_insight = on_insight
        self._lock = threading.RLock()
        self._facts: Dict[str, Fact] = {}
        self._intents: Dict[str, Intent] = {}
        self._resource_locks: Dict[str, str] = {}   # resource_key -> owner
        self._subscribers: List[Callable] = []

    # ── Facts ─────────────────────────────────────────────────────────────
    def add_fact(self, fact: Fact) -> bool:
        """إضافة/تحديث حقيقة؛ تتجاهل الأدنى ثقة عن الموجود الأقوى."""
        with self._lock:
            existing = self._facts.get(fact.key)
            if existing and existing.confidence >= fact.confidence:
                return False  # الموجود أقوى — لا نستبدله
            self._facts[fact.key] = fact
        if self.on_fact is not None:
            try:
                self.on_fact(fact)
            except Exception:  # noqa: BLE001
                pass
        self.publish("fact_added", {"key": fact.key, "source": fact.source})
        return True

    def get_fact(self, key: str) -> Optional[Fact]:
        with self._lock:
            return self._facts.get(key)

    def facts(
        self,
        *,
        prefix: str = "",
        min_confidence: Optional[float] = None,
        source: str = "",
    ) -> List[Fact]:
        thr = self.min_confidence if min_confidence is None else min_confidence
        with self._lock:
            out = []
            for f in self._facts.values():
                if prefix and not f.key.startswith(prefix):
                    continue
                if f.confidence < thr:
                    continue
                if source and f.source != source:
                    continue
                out.append(f)
            return sorted(out, key=lambda x: x.created_at)

    def has_fact(self, key: str, *, min_confidence: Optional[float] = None) -> bool:
        f = self.get_fact(key)
        if f is None:
            return False
        thr = self.min_confidence if min_confidence is None else min_confidence
        return f.confidence >= thr

    # ── Intents ───────────────────────────────────────────────────────────
    def begin_intent(self, intent_id: str, description: str, *,
                     owner: str = "", target: str = "") -> Intent:
        with self._lock:
            intent = Intent(
                intent_id=intent_id, description=description,
                owner=owner, target=target, state="active")
            self._intents[intent_id] = intent
            return intent

    def finish_intent(self, intent_id: str, state: str = "done") -> bool:
        with self._lock:
            intent = self._intents.get(intent_id)
            if intent is None:
                return False
            intent.state = state
            intent.finished_at = time.time()
            return True

    def is_intent_active(self, intent_id: str) -> bool:
        with self._lock:
            intent = self._intents.get(intent_id)
            return bool(intent and intent.state == "active")

    def active_intents(self) -> List[Intent]:
        with self._lock:
            return [i for i in self._intents.values() if i.state == "active"]

    # ── Locks ─────────────────────────────────────────────────────────────
    def acquire_lock(self, resource: str, owner: str) -> bool:
        """قفل مورد؛ يعود False إذا كان مقفولًا لوكيل آخر."""
        with self._lock:
            holder = self._resource_locks.get(resource)
            if holder is not None and holder != owner:
                return False
            self._resource_locks[resource] = owner
            return True

    def release_lock(self, resource: str, owner: str) -> bool:
        with self._lock:
            if self._resource_locks.get(resource) == owner:
                del self._resource_locks[resource]
                return True
            return False

    def lock_holder(self, resource: str) -> Optional[str]:
        with self._lock:
            return self._resource_locks.get(resource)

    # ── Insight Bus ───────────────────────────────────────────────────────
    def subscribe(self, handler: Callable[[str, Dict[str, Any]], None]) -> None:
        with self._lock:
            self._subscribers.append(handler)

    def publish(self, event: str, payload: Dict[str, Any]) -> None:
        if self.on_insight is not None:
            try:
                self.on_insight(event, payload)
            except Exception:  # noqa: BLE001
                pass
        with self._lock:
            handlers = list(self._subscribers)
        for h in handlers:
            try:
                h(event, payload)
            except Exception:  # noqa: BLE001
                pass

    # ── تقارير ────────────────────────────────────────────────────────────
    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "facts_count": len(self._facts),
                "active_intents": len(self.active_intents()),
                "locks": dict(self._resource_locks),
                "facts_by_prefix": self._prefix_counts(),
            }

    def _prefix_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for k in self._facts:
            prefix = k.split(":", 1)[0]
            counts[prefix] = counts.get(prefix, 0) + 1
        return counts
