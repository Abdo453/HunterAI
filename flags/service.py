"""خدمة الفلوغات الموحدة — تربط الاستخراج بالمخزن وتتابع اكتمال multi-flag.

تدفق المهمة:
1. نص جديد (مخرجات worker / أداة) → ingest()
2. استخراج مرشّحات → تحقق من القالب → تخزين مع dedupe
3. بعد كل ingest يُعاد حساب التقدم: أُجيب عن كل الفلوغات المتوقعة؟
4. عند القبول/الرفض من المنصة → mark_accepted / mark_false_positive
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from flags.extractor import extract_flag_candidates
from flags.models import FlagCandidate, FlagStatus
from flags.store import FlagStore

logger = logging.getLogger(__name__)


@dataclass
class FlagProgress:
    """تقدم جلسة multi-flag."""

    expected: int = 0                 # 0 = غير معروف (single-flag implicitly)
    accepted_count: int = 0
    pending_count: int = 0
    rejected_count: int = 0
    complete: bool = False
    best_candidate: str = ""

    def to_dict(self) -> Dict:
        return {
            "expected": self.expected,
            "accepted": self.accepted_count,
            "pending": self.pending_count,
            "rejected": self.rejected_count,
            "complete": self.complete,
            "best_candidate": self.best_candidate,
        }


class FlagService:
    """خدمة إدارة الفلوغات لجلسة/مهام واحدة."""

    def __init__(
        self,
        *,
        flag_format: str = "",
        expected_count: int = 1,
        store_path: str = "",
        on_candidate: Optional[Callable[[FlagCandidate], None]] = None,
    ):
        self.flag_format = flag_format
        self.expected = max(0, int(expected_count))
        self.store = FlagStore(store_path)
        self.on_candidate = on_candidate  # callback عند مرشّح جديد

    # ── الاستخراج والتخزين ────────────────────────────────────────────────
    def ingest(
        self,
        text: str,
        *,
        source: str = "",
        worker: str = "",
    ) -> List[FlagCandidate]:
        """استخراج مرشّحات من نص وتخزين الجديدة منها فقط."""
        candidates = extract_flag_candidates(
            text,
            flag_format=self.flag_format,
            source=source,
            worker=worker,
        )
        fresh: List[FlagCandidate] = []
        for c in candidates:
            is_new = self.store.add(c)
            if is_new:
                fresh.append(c)
                if self.on_candidate is not None:
                    try:
                        self.on_candidate(c)
                    except Exception:  # noqa: BLE001
                        pass
        return fresh

    # ── التقدم ────────────────────────────────────────────────────────────
    def progress(self) -> FlagProgress:
        counts = self.store.counts()
        best = self.store.best()
        accepted = counts.get(FlagStatus.ACCEPTED, 0)
        pending = (counts.get(FlagStatus.CANDIDATE, 0)
                   + counts.get(FlagStatus.VERIFIED, 0))
        rejected = counts.get(FlagStatus.REJECTED, 0)
        if self.expected > 1:
            # وضع multi-flag: لا يكتمل إلا بعد قبول المنصة لكل الفلوغات
            complete = accepted >= self.expected
        else:
            # وضع الفلوغ الواحد: مرشّح بثقة عالية أو قبول منصة يكفي
            complete = bool(accepted >= 1 or (best and best.confidence >= 0.8))
        return FlagProgress(
            expected=self.expected,
            accepted_count=accepted,
            pending_count=pending,
            rejected_count=rejected,
            complete=complete,
            best_candidate=best.value if best else "",
        )

    # ── علامات المنصة ─────────────────────────────────────────────────────
    def mark_accepted(self, value: str) -> bool:
        for c in self.store.all():
            if c.value.strip() == value.strip():
                return self.store.mark(c.fingerprint, FlagStatus.ACCEPTED)
        return False

    def mark_submitted(self, value: str) -> bool:
        for c in self.store.all():
            if c.value.strip() == value.strip():
                return self.store.mark(c.fingerprint, FlagStatus.SUBMITTED)
        return False

    def mark_false_positive(self, value_or_fp: str) -> bool:
        """رفض مرشّح بالقيمة أو البصمة — يفتح الحل من جديد."""
        for c in self.store.all():
            if (c.value.strip() == value_or_fp.strip()
                    or c.fingerprint == value_or_fp.strip()):
                return self.store.mark_false_positive(c.fingerprint)
        return False

    # ── توليد تقرير ───────────────────────────────────────────────────────
    def summary(self) -> Dict:
        prog = self.progress()
        return {
            "progress": prog.to_dict(),
            "counts": self.store.counts(),
            "candidates": [c.to_dict() for c in self.store.all()[:20]],
        }
