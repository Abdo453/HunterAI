"""FP Guards — قواعد منع النتائج الكاذبة (False Positives) في OSINT"""
from __future__ import annotations

import re
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from core.osint.platform_registry import is_generic_username

log = logging.getLogger("osint.fp_guards")


@dataclass
class FPGuardResult:
    """نتيجة فحص guard واحد"""
    guard_name: str
    passed: bool
    reason: str
    penalty: float = 0.0   #خصم يُضاف إلى confidence لو لم يمر guard


class FPGuards:
    """
    مجموعة قواعد تُطبّق على كل سجل evidence قبل دخوله الـ Correlation Engine.
    أي سجل يفشل في guard حاسم (مثل generic username) يُرفَض أو يُخصم ثقته بشدة.
    """

    # أنماط صفحات الـ soft-404 (تُعيد 200 لكنها تقول "غير موجود")
    SOFT404_PATTERNS = [
        r"page not found",
        r"not found",
        r"user not found",
        r"profile not found",
        r"account not found",
        r"does not exist",
        r"no such user",
        r"this account doesn't exist",
        r"لم يتم العثور",
        r"غير موجود",
        r"user does not exist",
        r"page unavailable",
    ]

    # نطاقات عامة لا تُعتبر منصات اجتماعية/هوية
    NON_IDENTITY_DOMAINS = {
        "google.com", "bing.com", "yahoo.com", "duckduckgo.com",
        "wikipedia.org", "mozilla.org", "apple.com", "microsoft.com",
        "adobe.com", "cloudflare.com", "akamai.com",
    }

    def __init__(self, custom_generic_usernames: Optional[List[str]] = None):
        self.extra_generic = set(
            u.lower().strip() for u in (custom_generic_usernames or [])
        )

    # ── Guards حاسمة ──────────────────────────────────────────────

    def check_generic_username(self, username: str) -> FPGuardResult:
        """
        G1: لو الـ username عام (admin, test, user...) لا يُعتبر هوية مميزة.
        """
        u = username.strip().lower()
        if u in self.extra_generic or is_generic_username(u):
            return FPGuardResult(
                guard_name="generic_username",
                passed=False,
                reason=f"Generic username '{username}' — not a distinctive identity",
                penalty=0.30,
            )
        return FPGuardResult(guard_name="generic_username", passed=True, reason="OK")

    def check_soft404(self, html_or_text: str, url: str) -> FPGuardResult:
        """
        G2: لو الصفحة تُعيد نص "غير موجود" رغم status 200 → Soft-404 → ترفض.
        """
        text = (html_or_text or "").lower()
        for pat in self.SOFT404_PATTERNS:
            if re.search(pat, text, re.IGNORECASE):
                return FPGuardResult(
                    guard_name="soft404",
                    passed=False,
                    reason=f"Soft-404 detected on {url} — pattern '{pat}' matched",
                    penalty=0.50,
                )
        return FPGuardResult(guard_name="soft404", passed=True, reason="OK")

    def check_redirect_to_homepage(self, final_url: str, match_url: str) -> FPGuardResult:
        """
        G4: لو الرابط حُوّل (redirect) إلى الصفحة الرئيسية للمنصة → غير صالح.
        """
        if not final_url or not match_url:
            return FPGuardResult(guard_name="redirect_check", passed=True, reason="No redirect data")
        f = final_url.rstrip("/")
        m = match_url.rstrip("/")
        if f == m:
            return FPGuardResult(guard_name="redirect_check", passed=True, reason="OK")
        # لو اُختزل الرابط إلى نطاق المنصة فقط
        if f in m or m in f:
            return FPGuardResult(
                guard_name="redirect_check",
                passed=False,
                reason=f"Redirect collapsed to homepage: {match_url} → {final_url}",
                penalty=0.40,
            )
        return FPGuardResult(guard_name="redirect_check", passed=True, reason="OK")

    def check_single_source_penalty(
        self, platform: str, tool_names: List[str]
    ) -> FPGuardResult:
        """
        G5: أي cluster من منصة واحدة ولا يوجد confirming من أداة ثانية
        لا يتجاوز label=weak أبدًا (يُطبّق في الـ Correlation، ليس هنا).
        """
        distinct = set(tool_names)
        if len(distinct) < 2:
            return FPGuardResult(
                guard_name="single_source",
                passed=True,  # لا نرفض، ن특penalty في confidence model
                reason=f"Single source detection on {platform}",
                penalty=0.20,
            )
        return FPGuardResult(guard_name="single_source", passed=True, reason="Multi-source")

    def check_non_identity_domain(self, url: str) -> FPGuardResult:
        """
        استبعاد النطاقات العامة التي ليست منصات هوية.
        """
        for d in self.NON_IDENTITY_DOMAINS:
            if d in url.lower():
                return FPGuardResult(
                    guard_name="non_identity_domain",
                    passed=False,
                    reason=f"URL belongs to non-identity domain: {d}",
                    penalty=0.60,
                )
        return FPGuardResult(guard_name="non_identity_domain", passed=True, reason="OK")

    # ── تشغيل كل guards على سجل واحد ──────────────────────────────

    def evaluate_record(
        self,
        record: Any,  # IdentityEvidenceRecord
        html_text: str = "",
        final_url: str = "",
    ) -> List[FPGuardResult]:
        """
        يُرجع قائمة نتائج guards للسجل.
        """
        results: List[FPGuardResult] = []

        results.append(self.check_generic_username(record.query_value))
        results.append(self.check_soft404(html_text, record.match_url))
        results.append(self.check_redirect_to_homepage(final_url, record.match_url))
        results.append(self.check_non_identity_domain(record.match_url))
        # single-source يُقيّم لاحقًا مع cluster وليس على سجل منفرد

        return results

    def total_penalty(self, results: List[FPGuardResult]) -> float:
        return sum(r.penalty for r in results if not r.passed)

    def critical_failures(self, results: List[FPGuardResult]) -> List[str]:
        return [r.guard_name for r in results if not r.passed and r.penalty >= 0.50]
