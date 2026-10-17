"""نماذج نظام الفلوغات."""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


class FlagStatus:
    CANDIDATE = "candidate"      # مُستخرَج لكن غير مُقدَّم بعد
    SUBMITTED = "submitted"      # أُرسل للمنصة
    ACCEPTED = "accepted"        # المنصة قبّلته
    REJECTED = "rejected"        # المنصة رفضته (أو علامة false positive يدوية)
    VERIFIED = "verified"        # تحقق محلي (match القالب + سياق قوي)

    ALL = (CANDIDATE, SUBMITTED, ACCEPTED, REJECTED, VERIFIED)


@dataclass
class FlagCandidate:
    """مرشّح فلوغ واحد."""

    value: str
    format_ok: bool = False           # مطابقة لقالب Flag المُعلن
    confidence: float = 0.0           # 0..1
    status: str = FlagStatus.CANDIDATE
    source: str = ""                  # من أين استُخرج (engine/step/tool)
    context: str = ""                 # ~200 حرف حول الاكتشاف
    worker: str = ""                  # أي وكيل وجده
    found_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        """بصمة فريدة للـ dedupe: القيمة بعد التطبيع."""
        normalized = self.value.strip()
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "value": self.value,
            "format_ok": self.format_ok,
            "confidence": round(self.confidence, 3),
            "status": self.status,
            "source": self.source,
            "context": self.context,
            "worker": self.worker,
            "found_at": self.found_at,
            "fingerprint": self.fingerprint,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "FlagCandidate":
        return cls(
            value=str(d.get("value") or ""),
            format_ok=bool(d.get("format_ok")),
            confidence=float(d.get("confidence") or 0.0),
            status=str(d.get("status") or FlagStatus.CANDIDATE),
            source=str(d.get("source") or ""),
            context=str(d.get("context") or ""),
            worker=str(d.get("worker") or ""),
            found_at=float(d.get("found_at") or time.time()),
            metadata=dict(d.get("metadata") or {}),
        )
