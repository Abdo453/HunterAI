"""LEDGER-022: real token streaming through the unified LLM router.

The router streams whenever an adapter exposes ``stream()`` (all cloud
adapters + local Ollama); adapters that cannot stream fall back to a single
whole-answer delta. Nothing here fabricates progressive tokens.
"""
from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest

from models.base_model import Message, ModelResponse

from core.llm_router import CLOUD_PROVIDERS, LLMRouter


def _run(coro):
    return asyncio.run(coro)


def _collector(sink):
    async def cb(delta):
        sink.append(delta)
    return cb


class _StreamingProvider:
    """Cloud-style adapter that streams token by token."""

    def __init__(self, chunks):
        self.chunks = list(chunks)

    async def is_available(self):
        return True

    async def stream(self, msgs, on_token=None):
        for c in self.chunks:
            if on_token:
                await on_token(c)
        return ModelResponse(content="".join(self.chunks), model_name="streaming", role="api")

    async def chat(self, msgs):  # pragma: no cover - must not be used
        raise AssertionError("chat() should not be called when stream() works")


class _NonStreamingProvider:
    """Adapter with no stream() — the router must emit one whole delta."""

    async def chat(self, msgs):
        return ModelResponse(content="whole answer", model_name="plain", role="api")


# ── router: forced target ────────────────────────────────────────────────────
def test_dispatch_stream_uses_provider_streamer(monkeypatch):
    router = LLMRouter()
    monkeypatch.setattr(router, "_load_provider", lambda spec, model=None: _StreamingProvider(["Hel", "lo"]))

    toks = []
    res = _run(router.complete_stream(
        [{"role": "user", "content": "hi"}],
        prefer="api:gemini:gemini-2.0-flash",
        on_token=_collector(toks),
    ))

    assert res.content == "Hello"
    assert toks == ["Hel", "lo"]


def test_dispatch_stream_falls_back_to_single_delta(monkeypatch):
    router = LLMRouter()
    monkeypatch.setattr(router, "_load_provider", lambda spec, model=None: _NonStreamingProvider())

    toks = []
    res = _run(router.complete_stream(
        [{"role": "user", "content": "hi"}],
        prefer="api:taskade:taskade-ai",
        on_token=_collector(toks),
    ))

    assert res.content == "whole answer"
    assert toks == ["whole answer"]  # one honest chunk, not fake tokens


def test_dispatch_stream_local_uses_ollama_chat_stream(monkeypatch):
    import models.ollama_manager as om

    seen = {}

    class FakeOllama:
        def __init__(self, host=None):
            pass

        async def chat_stream(self, model_name, messages, keep_alive=0,
                              temperature=0.3, num_ctx=4096, token_cb=None):
            seen["model"] = model_name
            for t in ("a", "b", "c"):
                if token_cb:
                    await token_cb(t)
            return "abc"

    monkeypatch.setattr(om, "OllamaManager", FakeOllama)

    toks = []
    res = _run(LLMRouter().complete_stream(
        [{"role": "user", "content": "x"}],
        prefer="local:qwen3:14b",
        on_token=_collector(toks),
    ))

    assert seen["model"] == "qwen3:14b"
    assert res.content == "abc"
    assert toks == ["a", "b", "c"]


def test_policy_stream_cloud_first(monkeypatch):
    router = LLMRouter(policy="cloud_first")
    gemini = CLOUD_PROVIDERS[0]
    monkeypatch.setattr(router, "cloud_specs", lambda only_available=True: [gemini])
    monkeypatch.setattr(router, "_load_provider", lambda spec, model=None: _StreamingProvider(["o", "k"]))

    toks = []
    res = _run(router.complete_stream([{"role": "user", "content": "hi"}], on_token=_collector(toks)))

    assert res.content == "ok"
    assert toks == ["o", "k"]


def test_unknown_provider_reports_error():
    toks = []
    res = _run(LLMRouter().complete_stream(
        [{"role": "user", "content": "hi"}],
        prefer="api:nope:whatever",
        on_token=_collector(toks),
    ))
    assert res.content == ""
    assert "unknown provider" in (res.error or "")
    assert toks == []


# ── Gemini provider: native SSE parsing ──────────────────────────────────────
class _FakeSSEResponse:
    def __init__(self, lines, status=200):
        self._lines = lines
        self.status_code = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    def aiter_lines(self):
        async def gen():
            for line in self._lines:
                yield line
        return gen()

    async def aread(self):
        return b"boom"


class _FakeAsyncClient:
    LINES: list = []

    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    def stream(self, method, url, json=None, headers=None):
        return _FakeSSEResponse(type(self).LINES)


def test_gemini_stream_parses_sse(monkeypatch):
    import models.api.gemini_provider as g

    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    lines = [
        'data: {"candidates":[{"content":{"parts":[{"text":"Hel"}]}}]}',
        'data: {"candidates":[{"content":{"parts":[{"text":"lo"}]}}]}',
        "data: [DONE]",
    ]
    client = type("_C", (_FakeAsyncClient,), {"LINES": lines})
    monkeypatch.setattr(g.httpx, "AsyncClient", client)

    toks = []
    res = _run(g.GeminiProvider(model="gemini-2.0-flash").stream(
        [Message(role="user", content="hi")],
        on_token=_collector(toks),
    ))

    assert res.content == "Hello"
    assert toks == ["Hel", "lo"]


# ── SmartOrchestrator surfaces token events ──────────────────────────────────
def test_smart_orchestrator_emits_token_events(monkeypatch):
    from core import llm_router as lr
    from core.smart_orchestrator import SmartOrchestrator

    class FakeRouter:
        async def complete_stream(self, messages, prefer=None, on_token=None):
            for t in ("Hel", "lo"):
                if on_token:
                    await on_token(t)
            return ModelResponse(content="Hello", model_name="gemini-2.0-flash", role="api")

    monkeypatch.setattr(lr, "get_llm_router", lambda: FakeRouter())

    events = []

    async def cb(ev):
        events.append(ev)

    orch = SmartOrchestrator(progress_callback=cb)
    result = _run(orch.chat("hi", selected_model="api:gemini:gemini-2.0-flash"))

    tokens = [e["delta"] for e in events if e.get("event") == "token"]
    assert tokens == ["Hel", "lo"]
    assert result["answer"] == "Hello"


# ── opt-in live cloud streaming (no network unless HUNTER_LIVE_LLM=1) ────────
def test_live_gemini_streaming_end_to_end():
    if os.getenv("HUNTER_LIVE_LLM") != "1":
        pytest.skip("set HUNTER_LIVE_LLM=1 to enable live cloud calls")
    try:
        from dotenv import load_dotenv
        load_dotenv(Path(__file__).resolve().parents[1] / ".env")
    except Exception:
        pass
    if not os.getenv("GEMINI_API_KEY"):
        pytest.skip("no GEMINI_API_KEY configured")

    toks = []
    res = _run(LLMRouter().complete_stream(
        [{"role": "user", "content": "List the numbers 1 through 12 separated by spaces, nothing else."}],
        prefer="api:gemini:gemini-3.8-flash",
        on_token=_collector(toks),
    ))
    if res.error:
        pytest.skip(f"live cloud unavailable: {res.error[:120]}")
    assert res.content.strip()
    assert toks, "expected at least one real token delta"
    assert "".join(toks) == res.content
