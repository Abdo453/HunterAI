"""مُقيِّد معدّل إرسال الفلوغات — حماية من الحظر (Brute-force protection).

CTFd وrCTF يفرضان حدود إرسال (مثل 10 محاولات / 60 ثانية). هذا المُقيِّد:
- يفرض تأخيرًا أدنى بين الإرسالات
- يحترم رأس Retry-After عند 429
- يعيد permit() قبل كل إرسال و record() بعده
"""
from __future__ import annotations

import threading
import time
from typing import Optional


class SubmitThrottler:
    def __init__(self, min_interval_s: float = 3.0, max_per_window: int = 10,
                 window_s: float = 60.0):
        self.min_interval_s = min_interval_s
        self.max_per_window = max_per_window
        self.window_s = window_s
        self._lock = threading.Lock()
        self._last_submit = 0.0
        self._window: list = []

    def _prune(self, now: float) -> None:
        cutoff = now - self.window_s
        self._window = [t for t in self._window if t > cutoff]

    def seconds_until_permit(self) -> float:
        """كم ثانية حتى يُسمح بإرسال آخر (0 = مسموح الآن)."""
        with self._lock:
            now = time.time()
            wait_interval = max(0.0, self.min_interval_s - (now - self._last_submit))
            self._prune(now)
            if len(self._window) >= self.max_per_window:
                wait_window = max(0.0, self.window_s - (now - self._window[0]))
            else:
                wait_window = 0.0
            return max(wait_interval, wait_window)

    def permit(self, timeout_s: float = 120.0) -> bool:
        """ينتظر حتى يسمح المُقيِّد (أو timeout)."""
        deadline = time.time() + timeout_s
        while True:
            wait = self.seconds_until_permit()
            if wait <= 0:
                return True
            if time.time() + wait > deadline:
                return False
            time.sleep(min(wait, 1.0))

    def record(self) -> None:
        """تسجيل إرسال فعلي (بعد permit())."""
        with self._lock:
            now = time.time()
            self._last_submit = now
            self._window.append(now)

    def penalize(self, retry_after_s: float) -> None:
        """عقوبة مباشرة من الخادم (مثال: Retry-After عند 429)."""
        with self._lock:
            self._last_submit = time.time() + max(0.0, retry_after_s)
