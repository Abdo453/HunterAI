"""جسر FlagService ↔ منصات CTF — إرسال تلقائي للمرشّحات.

يربط المخزن (candidates) بالمنصة (submit) عبر SubmitThrottler:
- يرسل أفضل المرشّحات غير المرفوضة
- يحدّث الحالة (accepted/wrong/duplicate/throttled) في المخزن
- يحترم cooldown و Retry-After للحماية من الحظر
- يوقف الإرسال فورًا عند اكتمال multi-flag
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from ctf.base import CTFPlatform, SubmitResult, SubmitStatus
from ctf.throttler import SubmitThrottler
from flags.models import FlagCandidate, FlagStatus
from flags.service import FlagService

logger = logging.getLogger(__name__)


@dataclass
class SubmitSummary:
    """ملخص جولة إرسال واحدة."""

    submitted: int = 0
    accepted: int = 0
    wrong: int = 0
    duplicate: int = 0
    throttled: int = 0
    errors: int = 0
    stopped_early: bool = False
    results: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "submitted": self.submitted,
            "accepted": self.accepted,
            "wrong": self.wrong,
            "duplicate": self.duplicate,
            "throttled": self.throttled,
            "errors": self.errors,
            "stopped_early": self.stopped_early,
        }


class FlagSubmitter:
    """يرسل مرشّحات FlagService إلى منصة CTF واحدة."""

    def __init__(
        self,
        flag_service: FlagService,
        platform: CTFPlatform,
        *,
        challenge_id: str = "",
        challenge_title: str = "",
        throttler: Optional[SubmitThrottler] = None,
        max_submits: int = 15,
        on_result: Optional[Callable[[SubmitResult], None]] = None,
    ):
        self.flags = flag_service
        self.platform = platform
        self.challenge_id = challenge_id
        self.challenge_title = challenge_title
        self.throttler = throttler or SubmitThrottler()
        self.max_submits = max_submits
        self.on_result = on_result

    def _resolve_challenge_id(self) -> str:
        """تحديد معرّف التحدي: بالمعرّف الصريح أو بالعنوان."""
        if self.challenge_id:
            return self.challenge_id
        if self.challenge_title:
            try:
                ch = self.platform.find_challenge_by_title(self.challenge_title)
                if ch:
                    return ch.id
            except Exception as exc:  # noqa: BLE001
                logger.warning("resolve challenge failed: %s", exc)
        return ""

    def submit_pending(self, *, dry_run: bool = False) -> SubmitSummary:
        """إرسال كل المرشّحات الجاهزة (بحد أقصى max_submits)."""
        summary = SubmitSummary()
        pending = self.flags.store.pending()
        if not pending:
            return summary

        challenge_id = self._resolve_challenge_id()
        if not challenge_id:
            logger.warning(
                "لا يمكن تحديد التحدي — تحقّق من العنوان/المعرّف")
            summary.errors += 1
            return summary

        for cand in pending[: self.max_submits]:
            # إيقاف مبكر عند اكتمال الهدف
            if self.flags.progress().complete:
                summary.stopped_early = True
                break

            if dry_run:
                summary.results.append({
                    "flag": cand.value, "status": "dry_run"})
                summary.submitted += 1
                continue

            # انتظار إذن المُقيِّد (cooldown)
            if not self.throttler.permit(timeout_s=120.0):
                summary.throttled += 1
                summary.stopped_early = True
                break

            result = self.platform.submit(challenge_id, cand.value)
            self.throttler.record()
            summary.submitted += 1

            if result.status == SubmitStatus.THROTTLED:
                summary.throttled += 1
                retry = float(result.raw.get("retry_after") or 30)
                self.throttler.penalize(retry)
                summary.stopped_early = True
                break

            if result.accepted:
                self.flags.mark_accepted(cand.value)
                summary.accepted += 1
            elif result.status == SubmitStatus.WRONG:
                self.flags.mark_false_positive(cand.value)
                summary.wrong += 1
            elif result.status == SubmitStatus.ERROR:
                summary.errors += 1
            else:
                summary.errors += 1

            summary.results.append({
                "flag": cand.value, "status": result.status,
                "message": result.message,
            })
            if self.on_result is not None:
                try:
                    self.on_result(result)
                except Exception:  # noqa: BLE001
                    pass

        return summary
