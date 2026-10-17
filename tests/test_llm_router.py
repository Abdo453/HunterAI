"""LEDGER-020 (M3a): Unified LLM Router — cloud-first, local fallback.

The router must expose ONE catalog of every model (local + all cloud providers)
and follow the owner policy: prefer a cloud provider when its API key exists,
otherwise use the local Ollama server. Nothing is hard-wired to a single
provider anymore.
"""
from __future__ import annotations

import asyncio

import pytest

from core.llm_router import CLOUD_PROVIDERS, LLMRouter
from models.base_model import ModelResponse

_ALL_KEYS = (
    "GEMINI_API_KEY", "DEEPSEEK_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
    "GROQ_API_KEY", "OPENROUTER_API_KEY", "TASKADE_API_KEY",
)


class _FakeProvider:
    def __init__(self, content: str = "", error: str = None):
        self._content = content
        self._error = error
        self.name = "fake"
        self.role = "api"

    async def is_available(self) -> bool:
        return True

    async def chat(self, messages):
        return ModelResponse(content=self._content, model_name="fake", role="api", error=self._error)


def _clear_keys(monkeypatch):
    for k in _ALL_KEYS:
        monkeypatch.delenv(k, raising=False)


# ── policy ───────────────────────────────────────────────────────────────────

def test_policy_defaults_to_cloud_first(monkeypatch):
    monkeypatch.delenv("HUNTER_LLM_POLICY", raising=False)
    assert LLMRouter().policy == "cloud_first"


def test_policy_override_and_validation(monkeypatch):
    monkeypatch.setenv("HUNTER_LLM_POLICY", "local_first")
    assert LLMRouter().policy == "local_first"
    monkeypatch.setenv("HUNTER_LLM_POLICY", "nonsense")
    assert LLMRouter().policy == "cloud_first"  # falls back to default


# ── catalog ──────────────────────────────────────────────────────────────────

def test_catalog_lists_cloud_and_local(monkeypatch):
    _clear_keys(monkeypatch)
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "k2")
    monkeypatch.delenv("HUNTER_LLM_POLICY", raising=False)
    r = LLMRouter()

    async def _locals():
        return ["qwen2.5-coder:14b", "WhiteRabbitNeo/Llama-3.1:latest"]

    monkeypatch.setattr(r, "local_models", _locals)
    cat = asyncio.run(r.catalog())

    assert cat["policy"] == "cloud_first"
    assert cat["cloud_available"] is True
    assert cat["local_available"] is True
    assert {c["provider"] for c in cat["cloud"]} == {"gemini", "deepseek"}

    ids = {c["id"] for c in cat["choices"]}
    assert "api:gemini:gemini-3.8-flash" in ids
    assert "api:deepseek:deepseek-chat" in ids
    assert "local:qwen2.5-coder:14b" in ids

    # Cloud choices must come before local ones (owner preference).
    kinds = [c["kind"] for c in cat["choices"]]
    assert kinds.index("local") > 0
    assert all(k == "cloud" for k in kinds[: kinds.index("local")])


def test_catalog_without_keys_is_empty(monkeypatch):
    _clear_keys(monkeypatch)
    r = LLMRouter()

    async def _locals():
        return []

    monkeypatch.setattr(r, "local_models", _locals)
    cat = asyncio.run(r.catalog())
    assert cat["cloud_available"] is False
    assert cat["local_available"] is False
    assert cat["choices"] == []


def test_cloud_specs_are_priority_ordered(monkeypatch):
    _clear_keys(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    r = LLMRouter()
    ids = [s.id for s in r.cloud_specs()]
    assert ids == ["gemini", "openai"]  # gemini priority 10 < openai 40


# ── routing ──────────────────────────────────────────────────────────────────

def test_cloud_first_prefers_cloud(monkeypatch):
    _clear_keys(monkeypatch)
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    monkeypatch.setenv("HUNTER_LLM_POLICY", "cloud_first")
    r = LLMRouter()
    monkeypatch.setattr(r, "_load_provider", lambda spec, model=None: _FakeProvider(content="from-cloud"))

    async def _boom():
        raise AssertionError("local Ollama must NOT be contacted when cloud answers")

    monkeypatch.setattr(r, "local_models", _boom)

    res = asyncio.run(r.complete([{"role": "user", "content": "hi"}]))
    assert res.content == "from-cloud"


def test_falls_back_to_local_when_cloud_fails(monkeypatch):
    _clear_keys(monkeypatch)
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    monkeypatch.setenv("HUNTER_LLM_POLICY", "cloud_first")
    r = LLMRouter()
    monkeypatch.setattr(r, "_load_provider", lambda spec, model=None: _FakeProvider(content="", error="down"))

    async def _locals():
        return ["qwen2.5-coder:14b"]

    async def _chat(self, model_name, messages, **kwargs):
        return "from-local"

    monkeypatch.setattr(r, "local_models", _locals)
    monkeypatch.setattr("models.ollama_manager.OllamaManager.chat", _chat)

    res = asyncio.run(r.complete([{"role": "user", "content": "hi"}]))
    assert res.content == "from-local"


def test_local_only_never_touches_cloud(monkeypatch):
    _clear_keys(monkeypatch)
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    monkeypatch.setenv("HUNTER_LLM_POLICY", "local_only")
    r = LLMRouter()

    def _load(spec, model=None):
        raise AssertionError("cloud must NOT be called under local_only policy")

    async def _locals():
        return ["qwen2.5-coder:14b"]

    async def _chat(self, model_name, messages, **kwargs):
        return "local-answer"

    monkeypatch.setattr(r, "_load_provider", _load)
    monkeypatch.setattr(r, "local_models", _locals)
    monkeypatch.setattr("models.ollama_manager.OllamaManager.chat", _chat)

    res = asyncio.run(r.complete([{"role": "user", "content": "hi"}]))
    assert res.content == "local-answer"


def test_no_model_available_reports_error(monkeypatch):
    _clear_keys(monkeypatch)
    r = LLMRouter()

    async def _locals():
        return []

    monkeypatch.setattr(r, "local_models", _locals)
    res = asyncio.run(r.complete([{"role": "user", "content": "hi"}]))
    assert res.content == ""
    assert res.error


# ── explicit dispatch (prefer=) ──────────────────────────────────────────────

def test_prefer_local_dispatch(monkeypatch):
    r = LLMRouter()

    async def _chat(self, model_name, messages, **kwargs):
        return f"local:{model_name}"

    monkeypatch.setattr("models.ollama_manager.OllamaManager.chat", _chat)
    res = asyncio.run(r.complete([{"role": "user", "content": "hi"}], prefer="local:qwen2.5-coder:14b"))
    assert res.content == "local:qwen2.5-coder:14b"


def test_prefer_api_dispatch(monkeypatch):
    _clear_keys(monkeypatch)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "k")
    r = LLMRouter()
    monkeypatch.setattr(r, "_load_provider",
                        lambda spec, model=None: _FakeProvider(content=f"{spec.id}:{model}"))
    res = asyncio.run(r.complete([{"role": "user", "content": "hi"}],
                                 prefer="api:deepseek:deepseek-reasoner"))
    assert res.content == "deepseek:deepseek-reasoner"


def test_unknown_prefer_returns_error():
    r = LLMRouter()
    res = asyncio.run(r.complete([{"role": "user", "content": "hi"}], prefer="bogus:x"))
    assert res.error and "unrecognised" in res.error


# ── provider loading sanity ──────────────────────────────────────────────────

def test_load_provider_imports_real_adapter():
    r = LLMRouter()
    spec = next(s for s in CLOUD_PROVIDERS if s.id == "gemini")
    provider = r._load_provider(spec)
    assert provider.name == "gemini-3.8-flash"


# ── web endpoint ─────────────────────────────────────────────────────────────

def test_catalog_endpoint_registered():
    pytest.importorskip("fastapi")
    try:
        from ui.web import app as app_module
    except Exception as e:  # pragma: no cover - environment dependent
        pytest.skip(f"web app import failed: {e}")
    paths = {getattr(r, "path", None) for r in app_module.app.routes}
    assert "/api/models/catalog" in paths
