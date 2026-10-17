"""
اختبارات مفرض نطاق الشبكة (core/scope_enforcer.py) — مرحلة G.
يختبر: block metadata services، loopback/private IP، scope guard، rate limit، re
direct، سجل التدقيق. لا يستهدف أي نظام خارجي.
"""
import pytest

from core.scope_enforcer import ScopeEnforcer, ScopeDecision
from core.scope_guard import ScopeGuard


def _enforcer(**kwargs):
    guard = ScopeGuard(in_scope=["example.com", "93.184.216.34/32"])
    return ScopeEnforcer(guard, **kwargs)


class TestScopeEnforcer:
    def test_allowed_in_scope(self):
        e = _enforcer()
        ok, reason = e.enforce_target("https://example.com/page")
        assert ok is True
        assert reason == "within scope"

    def test_out_of_scope_blocked(self):
        # totallydifferent.com خارج النطاق تمامًا (ليس نطاقات فرعية لـ example.com)
        e = _enforcer()
        ok, reason = e.enforce_target("https://totallydifferent.com/page")
        assert ok is False
        assert "خارج النطاق" in reason or "outside authorized scope" in reason

    def test_metadata_host_blocked(self):
        e = _enforcer()
        # 169.254.169.254 خدمة metadata تُحظر (سواء عبر invariant أو через metadata check)
        ok, reason = e.enforce_target("http://169.254.169.254/latest/meta-data/")
        assert ok is False
        low = reason.lower()
        assert any(k in low for k in ("metadata", "خاص", "private", "inviolable"))

    def test_metadata_google_blocked(self):
        e = _enforcer()
        ok, reason = e.enforce_target("http://metadata.google.internal/computeMetadata/v1/")
        assert ok is False
        assert "metadata" in reason.lower()

    def test_private_ip_blocked_by_default(self):
        # 10.0.0.5 خاص (RFC1918) وتُحظر بواسطة invariant engine في ScopeGuard
        e = _enforcer()
        ok, reason = e.enforce_target("http://10.0.0.5/internal")
        assert ok is False
        assert "خاص" in reason or "private" in reason.lower() or "inviolable" in reason.lower()

    def test_public_ip_in_scope_allowed(self):
        # 93.184.216.34 (example.com IP) موجود في范围 ⇒ مسموح
        e = _enforcer()
        ok, reason = e.enforce_target("http://93.184.216.34/page")
        assert ok is True

    def test_redirect_enforcement(self):
        e = _enforcer()
        # إعادة توجيه إلى نطاق خارج النطاق ⇒ مرفوضة
        ok, reason = e.enforce_redirect(
            "https://example.com/page", "https://totallydifferent.com/else")
        assert ok is False
        assert "إعادة توجيه" in reason or "redirect" in reason.lower()

    def test_redirect_allowed_within_scope(self):
        e = _enforcer()
        ok, reason = e.enforce_redirect(
            "https://example.com/page", "https://sub.example.com/else")
        assert ok is True

    def test_audit_log_recorded(self):
        e = _enforcer()
        e.enforce_target("https://example.com/page")
        e.enforce_target("https://totallydifferent.com/page")
        log = e.audit_log()
        assert len(log) == 2
        assert log[0]["decision"] == ScopeDecision.ALLOWED
        assert log[1]["decision"] == ScopeDecision.DENIED_SCOPE

    def test_empty_target_denied(self):
        e = _enforcer()
        ok, reason = e.enforce_target("")
        assert ok is False

    def test_rate_limit(self):
        e = _enforcer(rate_limit_per_min=2)
        assert e.enforce_target("https://example.com/a")[0] is True
        assert e.enforce_target("https://example.com/b")[0] is True
        # الثالثة يجب أن تُرفض بسبب المعدل (نفس النطاق example.com)
        ok, reason = e.enforce_target("https://example.com/c")
        assert ok is False
        assert "معدل" in reason or "rate" in reason.lower()
