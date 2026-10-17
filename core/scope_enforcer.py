"""
فرض نطاق الشبكة (Scope Enforcer) — مرحلة G.

يعزز core/scope_guard.py القائم بفحوصات عند وقت التنفيذ، وليس فقط عند الإنشاء:
- حظر خدمات metadata السحابية والمحلية (169.254.169.254، إلخ)
- منع loopback و RFC1918 ما لم يُصرح بها صراحةً في النطاق
- التحقق من عناوين إعادة التوجيه (redirects) ضد النطاق المصرح به
- حدود معدل (rate limits) لكل هدف
- سجل تدقيق لكل قرار نطاق (للمراجعة الأمنية)

يتم استخدامه من core/tool_registry.CliTool.authorize ومن core/coordinator
قبل أي عملية شبكية.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from core.scope_guard import ScopeGuard

logger = logging.getLogger(__name__)


class ScopeDecision:
    ALLOWED = "ALLOWED"
    DENIED_SCOPE = "DENIED_SCOPE"
    DENIED_METADATA = "DENIED_METADATA"
    DENIED_LOCAL = "DENIED_LOCAL"
    DENIED_RATE_LIMIT = "DENIED_RATE_LIMIT"
    DENIED_REDIRECT = "DENIED_REDIRECT"


# عناوين نطاقات metadata التي تُحظر دائمًا (حتى لو ظهرت في النطاق يدويًا)
METADATA_HOSTS: List[str] = [
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.azure.com",
    "169.254.169.254",
    "local-metadata",
    "instance-data",
]

# نطاقات RFC1918 خاصة (تُحظر ما لم تُصرح صراحةً)
PRIVATE_IPV4_NETS: List[str] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
]

# Loopback
LOOPBACK_HOSTS: List[str] = ["127.0.0.1", "::1", "localhost"]


class ScopeEnforcer:
    """
    مفرض نطاق الشبكة. يُغلف ScopeGuard القائم ويضيف invariants غير قابلة للتجاوز
    وفحوصات وقت التشغيل.
    """

    def __init__(
        self,
        guard: ScopeGuard,
        *,
        rate_limit_per_min: Optional[int] = 60,
        allow_private_by_default: bool = False,
        on_decision: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.guard = guard
        self.rate_limit_per_min = rate_limit_per_min
        self.allow_private_by_default = allow_private_by_default
        self.on_decision = on_decision
        self._host_timestamps: Dict[str, List[float]] = {}
        self._audit: List[Dict[str, Any]] = []

    # ── القرار الرئيسي ──────────────────────────────────────────────────

    def enforce_target(self, target: str) -> Tuple[bool, str]:
        """
        التحقق من أن الهدف مسموح به في النطاق وفقًا لجميع invariant.
        يعيد (مسموح، سبب).
        """
        if not target or not target.strip():
            return self._record(target, ScopeDecision.DENIED_SCOPE, "الهدف فارغ")

        clean = target.strip().lower()
        host = self._extract_host(clean)

        # 1. invariant engine من scope_guard (loopback/metadata/RFC1918 غير المصرح)
        inv_ok, inv_reason = self._check_invariants(host)
        if not inv_ok:
            return self._record(target, ScopeDecision.DENIED_LOCAL, inv_reason)

        # 2. حظر خدمات metadata حتى لو مدرجة في النطاق
        if self._is_metadata_host(host):
            return self._record(
                target, ScopeDecision.DENIED_METADATA,
                f"خدمة metadata محظورة: {host}")

        # 3. نطاق scope_guard (in_scope/out_of_scope patterns)
        guard_ok, guard_reason = self.guard.is_in_scope(target)
        if not guard_ok:
            return self._record(target, ScopeDecision.DENIED_SCOPE, guard_reason)

        # 4. حدود المعدل لكل هدف
        if not self._check_rate_limit(host):
            return self._record(
                target, ScopeDecision.DENIED_RATE_LIMIT,
                f"تجاوز حد المعدل للهدف: {host}")

        return self._record(target, ScopeDecision.ALLOWED, "within scope")

    def enforce_redirect(
        self, original_target: str, redirect_target: str
    ) -> Tuple[bool, str]:
        """
        التحقق من أن عنوان إعادة التوجيه يبقى داخل النطاق المصرح.
        يُستدعى قبل اتباع أي إعادة توجيه HTTP.
        """
        allowed, reason = self.enforce_target(redirect_target)
        if not allowed:
            return self._record(
                original_target, ScopeDecision.DENIED_REDIRECT,
                f"إعادة توجيه خارج النطاق: {redirect_target} ({reason})")
        return True, "redirect within scope"

    # ── المساعدة الداخلية ──────────────────────────────────────────────

    def _extract_host(self, target: str) -> str:
        """استخراج المضيف من عنوان URL أو مضيف صريح."""
        from urllib.parse import urlparse

        clean = target
        if clean.startswith("http://") or clean.startswith("https://"):
            parsed = urlparse(clean)
            return (parsed.hostname or clean).lower()
        # إزالة المسار والمنفذ إذا وُجدا
        host = clean.split("/", 1)[0].split(":", 1)[0]
        return host.lower()

    def _check_invariants(self, host: str) -> Tuple[bool, str]:
        """فحص invariant غير قابلة للتجاوز (loopback/private/metadata)."""
        # loopback صريح — مسموح فقط إن وُجد في in_scope صراحةً (عبر guard لاحقًا)
        if host in ("127.0.0.1", "::1", "localhost"):
            # يُترك للقرار النهائي للguard؛ لكن نُنبه إن لم يُصرح
            return True, "loopback (deferred to guard)"

        # عناوين IP الخاصة (RFC1918) — تُحظر ما لم تُصرح صراحةً
        try:
            ip = ipaddress.IPv4Address(host)
            if ip.is_private:
                if self.allow_private_by_default:
                    return True, "private IP (allowed by default)"
                return False, f"عنوان IP خاص غير مصرح به: {host}"
        except ValueError:
            pass

        return True, "invariants OK"

    def _is_metadata_host(self, host: str) -> bool:
        h = host.lower()
        for m in METADATA_HOSTS:
            if h == m or h.endswith("." + m.lstrip("*.")):
                return True
        return False

    def _check_rate_limit(self, host: str) -> bool:
        if self.rate_limit_per_min is None:
            return True
        now = time.time()
        window = now - 60.0
        timestamps = self._host_timestamps.setdefault(host, [])
        # إزالة التوقيتات القديمة
        self._host_timestamps[host] = [t for t in timestamps if t > window]
        if len(self._host_timestamps[host]) >= self.rate_limit_per_min:
            return False
        self._host_timestamps[host].append(now)
        return True

    def _record(
        self, target: str, decision: str, reason: str
    ) -> Tuple[bool, str]:
        entry = {
            "target": target,
            "decision": decision,
            "reason": reason,
            "timestamp": time.time(),
        }
        self._audit.append(entry)
        if self.on_decision is not None:
            try:
                self.on_decision(entry)
            except Exception:  # noqa: BLE001
                logger.warning("on_decision callback failed: %s", exc)
        allowed = decision == ScopeDecision.ALLOWED
        logger.info("نطاق %s: %s — %s", target, decision, reason)
        return allowed, reason

    # ── الاستعلام والتدقيق ─────────────────────────────────────────────

    def audit_log(self) -> List[Dict[str, Any]]:
        return list(self._audit)

    def clear_audit(self) -> None:
        self._audit.clear()
