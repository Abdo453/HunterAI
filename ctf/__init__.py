"""تكامل منصات CTF (CTFd / rCTF / GZCTF) — Phase 4.

بنية:
- base.py        : واجهة CTFPlatform الموحدة (auth, list_challenges, submit)
- ctfd.py        : عميل CTFd عبر REST API
- rctf.py        : عميل rCTF
- gzctf.py       : عميل GZCTF
- throttler.py   : تقييد معدّل الإرسال واحترام cooldown (حماية من الحظر)

كل عميل يعيد تطبيع البيانات إلى نفس النماذج (CTFChallenge, SubmitResult).
"""
from ctf.base import (
    CTFChallenge, CTFPlatform, SubmitResult, SubmitStatus,
)
from ctf.ctfd import CTFdPlatform
from ctf.rctf import RCTFPlatform
from ctf.gzctf import GZCTFPlatform
from ctf.throttler import SubmitThrottler
from ctf.bridge import FlagSubmitter, SubmitSummary

__all__ = [
    "CTFChallenge", "CTFPlatform", "SubmitResult", "SubmitStatus",
    "CTFdPlatform", "RCTFPlatform", "GZCTFPlatform", "SubmitThrottler",
    "FlagSubmitter", "SubmitSummary",
]
