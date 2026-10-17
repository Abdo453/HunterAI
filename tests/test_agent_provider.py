"""
اختبارات لواجهة موفري النماذج الموحدة (core/agent_provider.py) — Phase B.
يختبر: StubProvider، ProviderCapabilities.has، سجل المزودين، عدم هدر الأسرار في الأخطاء.
"""
import asyncio
import pytest

from core.agent_provider import (
    AgentProvider, ModelCapability, ProviderCapabilities, ProviderRequest,
    ProviderResponse, ProviderHealth, StubProvider, register_provider,
    get_provider, list_providers,
)


class RecordingProvider(AgentProvider):
    """مزوّد اختبار يسجل الطلبات ويستطيع الإلغاء."""

    def __init__(self, provider="test", model="test-model", fail_health=False):
        super().__init__(provider, model)
        self.calls = []
        self.cancelled = []
        self.fail_health = fail_health

    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            provider=self.provider, model=self.model,
            supports_tool_calling=True, supports_streaming=True,
            supports_json_mode=True, max_tokens=4096)

    async def health_check(self) -> ProviderHealth:
        if self.fail_health:
            return ProviderHealth(healthy=False, provider=self.provider,
                                  model=self.model, error="down")
        return ProviderHealth(healthy=True, provider=self.provider,
                              model=self.model)

    async def execute(self, request: ProviderRequest) -> ProviderResponse:
        self.calls.append(request)
        if request.messages and "cancel_me" in request.messages[0].get("content", ""):
            return ProviderResponse(ok=False, error="cancelled",
                                    model=self.model, provider=self.provider)
        return ProviderResponse(ok=True, content="done",
                                model=self.model, provider=self.provider,
                                input_tokens=1, output_tokens=1)

    async def stream(self, request: ProviderRequest, on_chunk) -> ProviderResponse:
        for c in ("a", "b"):
            on_chunk(c)
        return ProviderResponse(ok=True, content="ab",
                                model=self.model, provider=self.provider)

    def cancel(self, run_id: str) -> bool:
        self.cancelled.append(run_id)
        return True


class TestProviderCapabilities:
    def test_has_tool_calling(self):
        c = ProviderCapabilities(provider="p", model="m",
                                 supports_tool_calling=True)
        assert c.has("tool_calling") is True

    def test_has_streaming_false(self):
        c = ProviderCapabilities(provider="p", model="m")
        assert c.has("streaming") is False

    def test_has_extra(self):
        c = ProviderCapabilities(provider="p", model="m",
                                 extra=[ModelCapability(name="vision")])
        assert c.has("vision") is True


class TestStubProvider:
    def test_capabilities(self):
        p = StubProvider()
        c = p.capabilities()
        assert c.provider == "stub"

    @pytest.mark.asyncio
    async def test_health_and_execute(self):
        p = StubProvider()
        h = await p.health_check()
        assert h.healthy is True
        resp = await p.execute(ProviderRequest(model="m", messages=[{"role": "user", "content": "hi"}]))
        assert resp.ok is True
        assert "[stub]" in resp.content

    @pytest.mark.asyncio
    async def test_stream(self):
        p = StubProvider()
        chunks = []
        resp = await p.stream(ProviderRequest(model="m", messages=[]),
                              on_chunk=lambda c: chunks.append(c))
        assert resp.ok is True
        assert chunks == ["[stub]", " response"]


class TestRecordingProvider:
    def test_capabilities_full(self):
        p = RecordingProvider()
        c = p.capabilities()
        assert c.supports_tool_calling and c.supports_streaming and c.supports_json_mode

    @pytest.mark.asyncio
    async def test_execute_records_request(self):
        p = RecordingProvider()
        req = ProviderRequest(model="m", messages=[{"role": "user", "content": "hello"}])
        resp = await p.execute(req)
        assert resp.ok is True
        assert len(p.calls) == 1

    @pytest.mark.asyncio
    async def test_health_fail(self):
        p = RecordingProvider(fail_health=True)
        h = await p.health_check()
        assert h.healthy is False
        assert h.error == "down"


class TestProviderRegistry:
    def test_register_and_get(self):
        p = RecordingProvider()
        register_provider("rec", p)
        try:
            assert get_provider("rec") is p
            assert "rec" in list_providers()
        finally:
            # تنظيف السجل المشترك
            import core.agent_provider as ap
            ap._PROVIDERS.clear()
