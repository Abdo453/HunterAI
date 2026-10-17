"""واجهة منصة CTF الموحدة (Abstract Base)."""
from __future__ import annotations

import abc
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class SubmitStatus:
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    DUPLICATE = "duplicate"        # مقبول سابقًا (CTFd)
    WRONG = "wrong"                # رفض صريح
    THROTTLED = "throttled"        # مُنعت بسبب معدّل الإرسال/cooldown
    ERROR = "error"

    POSITIVE = (ACCEPTED, DUPLICATE)


@dataclass
class CTFChallenge:
    """تحدٍّ مُطبَّع من أي منصة."""

    id: str
    title: str
    category: str = ""
    description: str = ""
    value: int = 0
    solved_by_me: bool = False
    url: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SubmitResult:
    """نتيجة إرسال فلوغ مُطبَّعة."""

    status: str
    message: str = ""
    challenge_id: str = ""
    flag: str = ""
    elapsed_s: float = 0.0
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def accepted(self) -> bool:
        return self.status in SubmitStatus.POSITIVE


class CTFPlatform(abc.ABC):
    """عقد كل منصة CTF."""

    name: str = ""

    def __init__(self, base_url: str, token: str = "",
                 timeout_s: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout_s = timeout_s

    # ── المصادقة ──────────────────────────────────────────────────────────
    @abc.abstractmethod
    def auth_ok(self) -> bool:
        """Probe مصادقة بسيط: هل الرمز صالح الآن؟"""

    # ── التحديات ──────────────────────────────────────────────────────────
    @abc.abstractmethod
    def list_challenges(self) -> List[CTFChallenge]:
        """جلب كل التحديات (متزامنة — تُلفّ في thread من المستدعي)."""

    # ── الإرسال ────────────────────────────────────────────────────────────
    @abc.abstractmethod
    def submit(self, challenge_id: str, flag: str) -> SubmitResult:
        """إرسال فلوغ لتحدٍّ؛ يعيد نتيجة مُطبَّعة."""

    # ── ربط المرشّحات ─────────────────────────────────────────────────────
    def find_challenge_by_title(self, title: str) -> Optional[CTFChallenge]:
        low = title.strip().lower()
        for ch in self.list_challenges():
            if ch.title.strip().lower() == low:
                return ch
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "base_url": self.base_url}
