"""مخزن مرشّحات الفلوغات — dedupe + ranking + false positive + persistence."""
from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Dict, List, Optional

from flags.models import FlagCandidate, FlagStatus

logger = logging.getLogger(__name__)


class FlagStore:
    """مخزن thread-safe لمرشّحات جلسة واحدة (run/session).

    التخزين: ملف JSON في مجلد الجلسة (قابل للقراءة اليدوية بعد التشغيل).
    """

    def __init__(self, store_path: str = ""):
        self._lock = threading.Lock()
        self._by_fp: Dict[str, FlagCandidate] = {}
        self._path = Path(store_path) if store_path else None
        self._load()

    def _load(self) -> None:
        if self._path is None or not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            for item in data.get("candidates", []):
                c = FlagCandidate.from_dict(item)
                self._by_fp[c.fingerprint] = c
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("flag store load failed: %s", exc)

    def _save(self) -> None:
        if self._path is None:
            return
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "candidates": [c.to_dict() for c in self._all_sorted()],
            }
            self._path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2),
                encoding="utf-8")
        except OSError as exc:
            logger.warning("flag store save failed: %s", exc)

    def _all_sorted(self) -> List[FlagCandidate]:
        return sorted(
            self._by_fp.values(),
            key=lambda c: (c.confidence, c.found_at),
            reverse=True)

    # ── عمليات ────────────────────────────────────────────────────────────
    def add(self, candidate: FlagCandidate) -> bool:
        """إضافة مرشّح؛ يعود True إذا كان جديدًا (لم يكن مكررًا)."""
        with self._lock:
            fp = candidate.fingerprint
            if fp in self._by_fp:
                # دمج: نرفع الثقة إن جاءت من مصدر أقوى
                existing = self._by_fp[fp]
                existing.confidence = max(existing.confidence, candidate.confidence)
                if candidate.format_ok:
                    existing.format_ok = True
                self._save()
                return False
            self._by_fp[fp] = candidate
            self._save()
            return True

    def add_many(self, candidates: List[FlagCandidate]) -> int:
        return sum(1 for c in candidates if self.add(c))

    def mark(self, fingerprint: str, status: str) -> bool:
        """تغيير حالة مرشّح (مثل rejected عند علامة false positive)."""
        if status not in FlagStatus.ALL:
            raise ValueError(f"حالة غير معروفة: {status}")
        with self._lock:
            c = self._by_fp.get(fingerprint)
            if c is None:
                return False
            c.status = status
            if status == FlagStatus.REJECTED:
                c.confidence = 0.0
            self._save()
            return True

    def mark_false_positive(self, fingerprint: str) -> bool:
        return self.mark(fingerprint, FlagStatus.REJECTED)

    def best(self, *, min_confidence: float = 0.0,
             exclude_rejected: bool = True) -> Optional[FlagCandidate]:
        with self._lock:
            for c in self._all_sorted():
                if exclude_rejected and c.status == FlagStatus.REJECTED:
                    continue
                if c.confidence >= min_confidence:
                    return c
        return None

    def accepted(self) -> List[FlagCandidate]:
        with self._lock:
            return [c for c in self._by_fp.values()
                    if c.status == FlagStatus.ACCEPTED]

    def pending(self) -> List[FlagCandidate]:
        """مرشّحات جاهزة للإرسال (candidate أو verified، غير مرفوضة)."""
        with self._lock:
            return [c for c in self._all_sorted()
                    if c.status in (FlagStatus.CANDIDATE, FlagStatus.VERIFIED)]

    def all(self) -> List[FlagCandidate]:
        with self._lock:
            return self._all_sorted()

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_fp)

    def counts(self) -> Dict[str, int]:
        with self._lock:
            out: Dict[str, int] = {s: 0 for s in FlagStatus.ALL}
            for c in self._by_fp.values():
                out[c.status] = out.get(c.status, 0) + 1
            return out
