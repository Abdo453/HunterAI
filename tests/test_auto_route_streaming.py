"""LEDGER-025: real token streaming on the ``auto`` (smart-router) branch.

Selecting ``auto`` used to lose streaming in two independent places:

* ``SmartOrchestrator.chat(..., "auto")`` → ``ModelRouter._general_route``
  called the **non-streaming** ``LLMRouter.complete()``, so the flagship chat
  produced no deltas at all;
* the local routes (SECURITY/CODING/MIXED and the manual ``local:`` branch)
  already stream via ``chat_token`` events — which the Claude-like UI ignored.

Now the general route streams through ``complete_stream`` and the UI renders
both ``token`` (cloud) and ``chat_token`` (local) deltas. Nothing is faked: a
provider that cannot stream still delivers a single honest chunk.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from models.base_model import ModelResponse
from orchestrator.task_classifier import ClassificationResult, TaskType

_REPO_ROOT = Path(__file__).resolve().parents[1]


def _run(coro):
    return asyncio.run(coro)


class _FakeRouter:
    """Stand-in for ``core.llm_router.LLMRouter`` that streams honestly."""

    def __init__(self, chunks=("Hel", "lo")):
        self.chunks = tuple(chunks)
        self.received_on_token = False
        self.called = False

    async def complete_stream(self, messages, prefer=None, on_token=None):
        self.called = True
        self.received_on_token = on_token is not None
        for c in self.chunks:
            if on_token:
                await on_token(c)
        return ModelResponse(content="".join(self.chunks), model_name="fake", role="api")


def _general() -> ClassificationResult:
    return ClassificationResult(
        task_type=TaskType.GENERAL,
        confidence=0.5,
        reasoning="forced GENERAL for streaming test",
        security_score=0.0,
        coding_score=0.0,
        suggested_models=["qwen2.5-coder:14b"],
        use_local_first=False,
    )


def test_auto_branch_streams_tokens_to_ui(monkeypatch):
    """``auto`` → GENERAL emits real ``token`` deltas, not one silent answer."""
    from core import llm_router as lr
    from core.smart_orchestrator import SmartOrchestrator

    fake = _FakeRouter()
    monkeypatch.setattr(lr, "get_llm_router", lambda: fake)

    events = []

    async def cb(ev):
        events.append(ev)

    orch = SmartOrchestrator(progress_callback=cb)
    monkeypatch.setattr(orch.router.classifier, "classify", lambda *a, **k: _general())

    result = _run(orch.chat("hello there", selected_model="auto"))

    deltas = [e["delta"] for e in events if e.get("event") == "token"]
    assert deltas == ["Hel", "lo"]
    assert result["answer"] == "Hello"
    assert result["route"] == "GENERAL"
    assert fake.called, "general route must use the streaming completion"


def test_general_route_uses_streaming_completion(monkeypatch):
    """The router must receive a real ``on_token`` callback (not ``complete``)."""
    from core import llm_router as lr
    from core.smart_orchestrator import SmartOrchestrator

    fake = _FakeRouter()
    monkeypatch.setattr(lr, "get_llm_router", lambda: fake)
    orch = SmartOrchestrator(progress_callback=None)
    monkeypatch.setattr(orch.router.classifier, "classify", lambda *a, **k: _general())

    _run(orch.chat("hi", selected_model="auto"))
    assert fake.called
    assert fake.received_on_token


def test_general_route_forwards_explicit_on_token(monkeypatch):
    """Calling ``ModelRouter.route`` directly threads ``on_token`` downstream."""
    from core import llm_router as lr
    from core.smart_orchestrator import SmartOrchestrator

    fake = _FakeRouter(chunks=("a", "b", "c"))
    monkeypatch.setattr(lr, "get_llm_router", lambda: fake)
    orch = SmartOrchestrator(progress_callback=None)
    monkeypatch.setattr(orch.router.classifier, "classify", lambda *a, **k: _general())

    sink = []

    async def on_token(delta):
        sink.append(delta)

    out = _run(orch.router.route("hi", "", on_token=on_token))

    assert sink == ["a", "b", "c"]
    assert out["final"] == "abc"


def test_chat_ui_renders_local_chat_token_deltas():
    """The Claude-like UI must render ``chat_token`` (local) as well as ``token``."""
    js = (_REPO_ROOT / "ui" / "web" / "static" / "chat.js").read_text(encoding="utf-8")
    assert '"chat_token"' in js
    assert "d.delta ?? d.token" in js
