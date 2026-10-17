"""
اختبارات محول بورب (core/burp_adapter.py) — مرحلة F.
يختبر: الفحص الصحي، القدرات، استرجاع الحركة، استيراد/تصدير النتائج، التدهور اللطيف،
فحص النطاق، إخفاء الأسرار. لا يستهدف أي نظام خارجي (يُستخدم عميل HTTP وهمي).
"""
import asyncio
import pytest

from core.burp_adapter import (
    BurpAdapter, BurpAdapterConfig, BurpTransaction, BurpFinding,
    BurpAdapterError, _redact_secrets, _redact_headers,
)
from core.scope_enforcer import ScopeEnforcer
from core.scope_guard import ScopeGuard


class FakeHttpResponse:
    def __init__(self, status_code: int, json_data=None, text: str = ""):
        self.status_code = status_code
        self._json = json_data or {}
        self.text = text

    @property
    def is_success(self):
        return 200 <= self.status_code < 300

    def json(self):
        return self._json


class FakeHttpClient:
    """عميل HTTP وهمي يُعيد استجابات محاكاة لبوابة بورب."""
    def __init__(self, responses=None):
        self.responses = responses or {}
        self.calls = []

    async def get(self, url, params=None, timeout=None):
        self.calls.append(("GET", url, params))
        for pattern, resp in self.responses.items():
            if pattern in url:
                return resp
        return FakeHttpResponse(404, {"error": "not found"})

    async def post(self, url, json=None, timeout=None):
        self.calls.append(("POST", url, json))
        for pattern, resp in self.responses.items():
            if pattern in url:
                return resp
        return FakeHttpResponse(404, {"error": "not found"})

    async def aclose(self):
        pass


def _adapter(fake_client=None, enabled=True, scope_in_scope=None):
    cfg = BurpAdapterConfig(enabled=enabled)
    guard = ScopeGuard(in_scope=scope_in_scope or ["example.com"])
    enforcer = ScopeEnforcer(guard)
    adapter = BurpAdapter(config=cfg, scope_enforcer=enforcer, http_client=fake_client)
    return adapter


class TestRedaction:
    def test_redact_secrets(self):
        out = _redact_secrets("token sk-abcdef123456 here")
        assert "sk-abcdef123456" not in out
        assert "***" in out

    def test_redact_headers(self):
        out = _redact_headers({"Authorization": "Bearer secret", "Content-Type": "application/json"})
        assert out["Authorization"] == "***"
        assert out["Content-Type"] == "application/json"


class TestAdapterHealth:
    @pytest.mark.asyncio
    async def test_disabled_degraded(self):
        adapter = _adapter(enabled=False)
        h = await adapter.health_check()
        assert h["available"] is False
        assert h["status"] == "degraded"

    @pytest.mark.asyncio
    async def test_connected(self):
        fake = FakeHttpClient(responses={
            "/health": FakeHttpResponse(200, {"status": "online", "port": 8085}),
        })
        adapter = _adapter(fake)
        h = await adapter.health_check()
        assert h["available"] is True
        assert h["status"] == "connected"

    @pytest.mark.asyncio
    async def test_unreachable_degraded_no_crash(self):
        # عميل يُرفع استثناء عند الاتصال
        class BrokenClient:
            async def get(self, *a, **k):
                raise ConnectionError("refused")
            async def post(self, *a, **k):
                raise ConnectionError("refused")
            async def aclose(self):
                pass
        adapter = _adapter(BrokenClient())
        h = await adapter.health_check()
        assert h["available"] is False
        assert h["status"] == "degraded"


class TestAdapterCapabilities:
    @pytest.mark.asyncio
    async def test_capabilities_when_disabled(self):
        adapter = _adapter(enabled=False)
        caps = await adapter.get_available_capabilities()
        assert caps["available"] is False
        assert "note" in caps

    @pytest.mark.asyncio
    async def test_capabilities_when_connected(self):
        fake = FakeHttpClient(responses={
            "/health": FakeHttpResponse(200, {"status": "online"}),
        })
        adapter = _adapter(fake)
        caps = await adapter.get_available_capabilities()
        assert caps["available"] is True
        assert caps["operations"]["retrieve_authorized_http_history"] is True
        assert caps["operations"]["import_supported_findings"] is True


class TestAdapterHistory:
    @pytest.mark.asyncio
    async def test_retrieve_history_denied_when_degraded(self):
        adapter = _adapter(enabled=False)
        with pytest.raises(BurpAdapterError, match="unavailable"):
            await adapter.retrieve_authorized_http_history(target="example.com")

    @pytest.mark.asyncio
    async def test_retrieve_history_scope_denied(self):
        fake = FakeHttpClient(responses={
            "/health": FakeHttpResponse(200, {"status": "online"}),
            "/captures": FakeHttpResponse(200, {"transactions": [
                {"tx_id": "t1", "target_host": "evil.com", "method": "GET",
                 "url": "https://evil.com/x", "status_code": 200,
                 "req_headers": {}, "req_body": "", "resp_headers": {},
                 "resp_body": "", "tool_source": "proxy"}
            ]}),
        })
        adapter = _adapter(fake, scope_in_scope=["example.com"])
        # evil.com خارج范围 ⇒ قائمة فارغة
        result = await adapter.retrieve_authorized_http_history(target="example.com")
        assert result == []

    @pytest.mark.asyncio
    async def test_retrieve_history_in_scope(self):
        fake = FakeHttpClient(responses={
            "/health": FakeHttpResponse(200, {"status": "online"}),
            "/captures": FakeHttpResponse(200, {"transactions": [
                {"tx_id": "t1", "target_host": "example.com", "method": "GET",
                 "url": "https://example.com/page",
                 "status_code": 200, "req_headers": {"Authorization": "Bearer secret"},
                 "req_body": "token sk-abcdef123456 here",
                 "resp_headers": {}, "resp_body": "ok", "tool_source": "proxy"}
            ]}),
        })
        adapter = _adapter(fake, scope_in_scope=["example.com"])
        result = await adapter.retrieve_authorized_http_history(target="example.com")
        assert len(result) == 1
        tx = result[0]
        assert isinstance(tx, BurpTransaction)
        # الأسرار مُنشفَة
        assert "sk-abcdef123456" not in tx.req_body
        assert "***" in tx.req_body
        assert tx.req_headers.get("Authorization") == "***"

    @pytest.mark.asyncio
    async def test_retrieve_request_not_found(self):
        fake = FakeHttpClient(responses={
            "/health": FakeHttpResponse(200, {"status": "online"}),
            "/captures/": FakeHttpResponse(404, {"error": "not found"}),
        })
        adapter = _adapter(fake)
        result = await adapter.retrieve_request("tx-missing")
        assert result is None


class TestAdapterFindings:
    @pytest.mark.asyncio
    async def test_import_findings(self):
        fake = FakeHttpClient(responses={
            "/health": FakeHttpResponse(200, {"status": "online"}),
            "/findings": FakeHttpResponse(200, {"findings": [
                {"finding_id": "f1", "target": "example.com",
                 "issue_name": "Reflected XSS", "severity": "High",
                 "confidence": "Certain", "evidence": "payload <script>",
                 "remediation": "escape output", "verified_by_burp": True}
            ]}),
        })
        adapter = _adapter(fake)
        findings = await adapter.import_supported_findings()
        assert len(findings) == 1
        f = findings[0]
        assert isinstance(f, BurpFinding)
        assert f.verified_by_burp is True
        assert f.provenance == "burp_extension"

    @pytest.mark.asyncio
    async def test_export_findings(self):
        adapter = _adapter()
        result = await adapter.export_supported_findings([
            {"title": "XSS", "target": "example.com",
             "severity": "High", "evidence": "payload", "remediation": "fix"}
        ])
        assert result["exported_count"] == 1
        assert result["format"] == "burp_iscan_issue_json"
        assert len(result["findings"]) == 1
        assert result["findings"][0]["issue_name"] == "[HunterAI] XSS"


class TestAdapterAnalysis:
    @pytest.mark.asyncio
    async def test_submit_job_scope_violation(self):
        fake = FakeHttpClient(responses={
            "/health": FakeHttpResponse(200, {"status": "online"}),
        })
        adapter = _adapter(fake, scope_in_scope=["example.com"])
        with pytest.raises(BurpAdapterError, match="outside scope"):
            await adapter.submit_supported_analysis_job(
                target="evil.com", job_type="passive_scan")

    @pytest.mark.asyncio
    async def test_submit_and_retrieve_job(self):
        fake = FakeHttpClient(responses={
            "/health": FakeHttpResponse(200, {"status": "online"}),
            "/analysis/jobs/job-1": FakeHttpResponse(200, {
                "job_id": "job-1", "status": "finished",
                "results": {"vulns_found": 2}
            }),
            "/analysis/jobs": FakeHttpResponse(200, {"job_id": "job-1", "status": "submitted"}),
        })
        adapter = _adapter(fake, scope_in_scope=["example.com"])
        submitted = await adapter.submit_supported_analysis_job(
            target="example.com", job_type="passive_scan")
        assert submitted["accepted"] is True
        assert submitted["job_id"] == "job-1"

        results = await adapter.retrieve_analysis_results("job-1")
        assert results["found"] is True
        assert results["status"] == "finished"
        assert results["results"]["vulns_found"] == 2


class TestAdapterSnapshot:
    def test_snapshot_and_audit(self):
        adapter = _adapter()
        snap = adapter.snapshot()
        assert "status" in snap
        assert "config" in snap
        assert isinstance(adapter.audit_log(), list)
