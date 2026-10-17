"""Unified LLM Router — one entry point for every model in the platform.
=========================================================================

Owner policy (see ``HUNTER_LLM_POLICY``): **cloud-first** — if any cloud
provider API key is present it is preferred, otherwise the router falls back to
the local Ollama server. Nothing is hard-wired to a single provider anymore.

Policies
--------
``cloud_first`` (default)  prefer cloud key, fall back to local Ollama
``local_first``            prefer local Ollama, fall back to cloud
``local_only``            Ollama only, never call the cloud
``cloud_only``            cloud only, never call Ollama

Catalog convention (consumed by the Web UI model picker)::

    api:<provider>:<model>     e.g. "api:gemini:gemini-2.0-flash"
    local:<ollama-model>       e.g. "local:qwen2.5-coder:14b"

This module reuses the existing provider adapters (``models/api/*``) and the
local ``OllamaManager`` — it invents no new transport.
"""
from __future__ import annotations

import importlib
import logging
import os
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Optional, Sequence, Tuple

from models.base_model import Message, ModelResponse

logger = logging.getLogger("hunter_ai.llm_router")

POLICY_ENV = "HUNTER_LLM_POLICY"
DEFAULT_POLICY = "cloud_first"
VALID_POLICIES = ("cloud_first", "local_first", "local_only", "cloud_only")


@dataclass(frozen=True)
class ProviderSpec:
    """Static description of a cloud provider adapter."""

    id: str
    env_key: str
    target: str          # "package.module:ClassName"
    default_model: str
    label: str
    priority: int        # lower = preferred
    models: Tuple[str, ...] = ()


# Ordered by *owner preference*: Gemini first, then DeepSeek, Claude, OpenAI,
# Groq, OpenRouter, Taskade. Availability is decided purely by the env key.
CLOUD_PROVIDERS: Tuple[ProviderSpec, ...] = (
    ProviderSpec("gemini", "GEMINI_API_KEY",
                 "models.api.gemini_provider:GeminiProvider",
                 "gemini-3.8-flash", "Google Gemini", 10,
                 ("gemini-3.8-flash", "gemini-flash-latest")),
    ProviderSpec("deepseek", "DEEPSEEK_API_KEY",
                 "models.api.deepseek_provider:DeepSeekProvider",
                 "deepseek-chat", "DeepSeek", 20,
                 ("deepseek-chat", "deepseek-reasoner")),
    ProviderSpec("anthropic", "ANTHROPIC_API_KEY",
                 "models.api.anthropic_provider:AnthropicProvider",
                 "claude-3-5-sonnet-20241022", "Anthropic Claude", 30,
                 ("claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022")),
    ProviderSpec("openai", "OPENAI_API_KEY",
                 "models.api.openai_provider:OpenAIProvider",
                 "gpt-4o", "OpenAI", 40,
                 ("gpt-4o", "gpt-4o-mini", "o3-mini")),
    ProviderSpec("groq", "GROQ_API_KEY",
                 "models.api.groq_provider:GroqProvider",
                 "llama-3.3-70b-versatile", "Groq", 50),
    ProviderSpec("openrouter", "OPENROUTER_API_KEY",
                 "models.api.openrouter_provider:OpenRouterProvider",
                 "anthropic/claude-3.5-sonnet", "OpenRouter", 60),
    ProviderSpec("taskade", "TASKADE_API_KEY",
                 "models.api.taskade_provider:TaskadeProvider",
                 "taskade-ai", "Taskade", 70),
)

# Local models that make good general-purpose fallbacks, in preference order.
_LOCAL_PREFERENCE = ("qwen", "llama", "mistral", "whiterabbit")


def _coerce_messages(messages: Sequence[Any]) -> List[Message]:
    """Accept Message objects, dicts or (role, content) tuples."""
    out: List[Message] = []
    for m in messages:
        if isinstance(m, Message):
            out.append(m)
        elif isinstance(m, dict):
            out.append(Message(role=str(m.get("role", "user")), content=str(m.get("content", ""))))
        elif isinstance(m, (list, tuple)) and len(m) == 2:
            out.append(Message(role=str(m[0]), content=str(m[1])))
    return out


class LLMRouter:
    """Cloud-first model router with a uniform ``complete()`` interface."""

    def __init__(self, ollama_host: Optional[str] = None, policy: Optional[str] = None):
        self.ollama_host = ollama_host or os.getenv("OLLAMA_HOST", "http://localhost:11434")
        self._policy = (policy or os.getenv(POLICY_ENV, DEFAULT_POLICY)).strip().lower()

    # ── policy ───────────────────────────────────────────────────────────────
    @property
    def policy(self) -> str:
        return self._policy if self._policy in VALID_POLICIES else DEFAULT_POLICY

    def _order(self, policy: str) -> Tuple[str, ...]:
        if policy == "local_only":
            return ("local",)
        if policy == "cloud_only":
            return ("cloud",)
        if policy == "local_first":
            return ("local", "cloud")
        return ("cloud", "local")

    # ── catalog ──────────────────────────────────────────────────────────────
    def cloud_specs(self, only_available: bool = True) -> List[ProviderSpec]:
        specs = sorted(CLOUD_PROVIDERS, key=lambda s: s.priority)
        if only_available:
            specs = [s for s in specs if os.getenv(s.env_key)]
        return specs

    def _load_provider(self, spec: ProviderSpec, model: Optional[str] = None):
        module_name, _, cls_name = spec.target.partition(":")
        module = importlib.import_module(module_name)
        cls = getattr(module, cls_name)
        return cls(model=model or spec.default_model)

    async def local_models(self) -> List[str]:
        try:
            from models.ollama_manager import OllamaManager

            mgr = OllamaManager(host=self.ollama_host)
            return list(await mgr.list_available() or [])
        except Exception as e:  # noqa: BLE001 - probe failures are non-fatal
            logger.debug(f"[LLMRouter] local model probe failed: {e}")
            return []

    def _pick_local(self, models: List[str]) -> Optional[str]:
        if not models:
            return None
        for needle in _LOCAL_PREFERENCE:
            for m in models:
                if needle in m.lower():
                    return m
        return models[0]

    def _choices(self, local: List[str], cloud: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for c in cloud:
            for m in c["models"]:
                out.append({
                    "id": f"api:{c['provider']}:{m}",
                    "kind": "cloud",
                    "provider": c["provider"],
                    "model": m,
                    "label": f"{c['label']} · {m}",
                    "available": True,
                })
        for m in local:
            out.append({
                "id": f"local:{m}",
                "kind": "local",
                "provider": "ollama",
                "model": m,
                "label": f"Ollama · {m}",
                "available": True,
            })
        return out

    async def catalog(self) -> Dict[str, Any]:
        """A single unified catalog of every usable model."""
        local = await self.local_models()
        cloud = [
            {
                "provider": s.id,
                "label": s.label,
                "default_model": s.default_model,
                "models": list(s.models or (s.default_model,)),
            }
            for s in self.cloud_specs(only_available=True)
        ]
        return {
            "policy": self.policy,
            "ollama_host": self.ollama_host,
            "cloud_available": bool(cloud),
            "local_available": bool(local),
            "local": {"available": bool(local), "models": local},
            "cloud": cloud,
            "choices": self._choices(local, cloud),
        }

    # ── completion ───────────────────────────────────────────────────────────
    async def complete(
        self,
        messages: Sequence[Any],
        prefer: Optional[str] = None,
        system_prompt: str = "",
        errors: Optional[List[str]] = None,
    ) -> ModelResponse:
        """Generate a completion following the configured policy.

        ``prefer`` (optional) forces a specific target:
          * ``"api:<provider>:<model>"`` — one cloud provider call (no fallback)
          * ``"local:<ollama-model>"``   — one local Ollama call (no fallback)
        """
        msgs = _coerce_messages(messages)
        if system_prompt and not any(m.role == "system" for m in msgs):
            msgs = [Message(role="system", content=system_prompt)] + msgs
        if not msgs:
            return ModelResponse(content="", model_name="none", role="router",
                                 error="no messages supplied")

        if prefer:
            return await self._dispatch(prefer, msgs)

        collected: List[str] = errors if errors is not None else []
        for kind in self._order(self.policy):
            res = (await self._complete_cloud(msgs, collected) if kind == "cloud"
                   else await self._complete_local(msgs, collected))
            if res and res.content:
                return res
        return ModelResponse(content="", model_name="none", role="router",
                             error="; ".join(collected) or "no model available")

    async def _complete_cloud(self, msgs: List[Message], errors: List[str]) -> Optional[ModelResponse]:
        for spec in self.cloud_specs(only_available=True):
            try:
                provider = self._load_provider(spec)
                if hasattr(provider, "is_available") and not await provider.is_available():
                    continue
                res = await provider.chat(msgs)
                if res and res.content:
                    logger.info(f"[LLMRouter] answered via {spec.id}:{res.model_name}")
                    return res
                if res and res.error:
                    errors.append(f"{spec.id}: {res.error}")
            except Exception as e:  # noqa: BLE001
                errors.append(f"{spec.id}: {e}")
        return None

    async def _complete_local(self, msgs: List[Message], errors: List[str]) -> Optional[ModelResponse]:
        models = await self.local_models()
        model = self._pick_local(models)
        if not model:
            errors.append("ollama: no local models available")
            return None
        try:
            from models.ollama_manager import OllamaManager

            mgr = OllamaManager(host=self.ollama_host)
            payload = [{"role": m.role, "content": m.content} for m in msgs]
            text = await mgr.chat(model_name=model, messages=payload)
            if text:
                logger.info(f"[LLMRouter] answered via local:{model}")
                return ModelResponse(content=text, model_name=model, role="local")
            errors.append(f"ollama:{model}: empty response")
        except Exception as e:  # noqa: BLE001
            errors.append(f"ollama: {e}")
        return None

    async def _dispatch(self, prefer: str, msgs: List[Message]) -> ModelResponse:
        if prefer.startswith("local:"):
            model = prefer[len("local:"):].strip()
            try:
                from models.ollama_manager import OllamaManager

                mgr = OllamaManager(host=self.ollama_host)
                payload = [{"role": m.role, "content": m.content} for m in msgs]
                text = await mgr.chat(model_name=model, messages=payload)
                return ModelResponse(content=text, model_name=model, role="local",
                                     error=None if text else "empty local response")
            except Exception as e:  # noqa: BLE001
                return ModelResponse(content="", model_name=model, role="local", error=str(e))

        if prefer.startswith("api:"):
            rest = prefer[len("api:"):]
            provider_id, _, model = rest.partition(":")
            spec = next((s for s in CLOUD_PROVIDERS if s.id == provider_id), None)
            if spec is None:
                return ModelResponse(content="", model_name=rest, role="api",
                                     error=f"unknown provider '{provider_id}'")
            try:
                provider = self._load_provider(spec, model=model or spec.default_model)
                res = await provider.chat(msgs)
                if res and res.content:
                    return res
                if res:
                    return res
                return ModelResponse(content="", model_name=model, role="api",
                                     error="empty response")
            except Exception as e:  # noqa: BLE001
                return ModelResponse(content="", model_name=model, role="api", error=str(e))

        return ModelResponse(content="", model_name=prefer, role="router",
                             error=f"unrecognised prefer target '{prefer}'")

    # ── streaming completion ─────────────────────────────────────────────────
    async def complete_stream(
        self,
        messages: Sequence[Any],
        prefer: Optional[str] = None,
        system_prompt: str = "",
        on_token: Optional[Callable[[str], Awaitable[None]]] = None,
        errors: Optional[List[str]] = None,
    ) -> ModelResponse:
        """Like :meth:`complete` but forwards token deltas to ``on_token``.

        Streaming is used whenever the chosen adapter implements ``stream()``
        (every cloud adapter + local Ollama). If an adapter cannot stream (e.g.
        Taskade), the full answer is delivered as a **single** delta: the UI
        shows one chunk — it never fabricates a token-by-token animation.
        """
        msgs = _coerce_messages(messages)
        if system_prompt and not any(m.role == "system" for m in msgs):
            msgs = [Message(role="system", content=system_prompt)] + msgs
        if not msgs:
            return ModelResponse(content="", model_name="none", role="router",
                                 error="no messages supplied")

        if prefer:
            return await self._dispatch_stream(prefer, msgs, on_token)

        collected: List[str] = errors if errors is not None else []
        for kind in self._order(self.policy):
            res = (await self._complete_cloud_stream(msgs, on_token, collected) if kind == "cloud"
                   else await self._complete_local_stream(msgs, on_token, collected))
            if res and res.content:
                return res
        return ModelResponse(content="", model_name="none", role="router",
                             error="; ".join(collected) or "no model available")

    async def _stream_provider(
        self, provider: Any, msgs: List[Message],
        on_token: Optional[Callable[[str], Awaitable[None]]],
    ) -> ModelResponse:
        """Prefer the adapter's own streamer; otherwise emit the full answer once."""
        streamer = getattr(provider, "stream", None)
        if callable(streamer):
            res = await streamer(msgs, on_token=on_token)
            if res and res.content:
                return res
            if res and res.error:
                return res
            # empty stream with no error → fall through to a normal call
        res = await provider.chat(msgs)
        if res and res.content and on_token:
            await on_token(res.content)
        return res

    async def _complete_cloud_stream(
        self, msgs: List[Message], on_token: Optional[Callable[[str], Awaitable[None]]],
        errors: List[str],
    ) -> Optional[ModelResponse]:
        for spec in self.cloud_specs(only_available=True):
            try:
                provider = self._load_provider(spec)
                if hasattr(provider, "is_available") and not await provider.is_available():
                    continue
                res = await self._stream_provider(provider, msgs, on_token)
                if res and res.content:
                    logger.info(f"[LLMRouter] streamed via {spec.id}:{res.model_name}")
                    return res
                if res and res.error:
                    errors.append(f"{spec.id}: {res.error}")
            except Exception as e:  # noqa: BLE001
                errors.append(f"{spec.id}: {e}")
        return None

    async def _complete_local_stream(
        self, msgs: List[Message], on_token: Optional[Callable[[str], Awaitable[None]]],
        errors: List[str],
    ) -> Optional[ModelResponse]:
        models = await self.local_models()
        model = self._pick_local(models)
        if not model:
            errors.append("ollama: no local models available")
            return None
        try:
            from models.ollama_manager import OllamaManager

            mgr = OllamaManager(host=self.ollama_host)
            payload = [{"role": m.role, "content": m.content} for m in msgs]
            text = await mgr.chat_stream(model_name=model, messages=payload, token_cb=on_token)
            if text:
                logger.info(f"[LLMRouter] streamed via local:{model}")
                return ModelResponse(content=text, model_name=model, role="local")
            errors.append(f"ollama:{model}: empty response")
        except Exception as e:  # noqa: BLE001
            errors.append(f"ollama: {e}")
        return None

    async def _dispatch_stream(
        self, prefer: str, msgs: List[Message],
        on_token: Optional[Callable[[str], Awaitable[None]]],
    ) -> ModelResponse:
        if prefer.startswith("local:"):
            model = prefer[len("local:"):].strip()
            try:
                from models.ollama_manager import OllamaManager

                mgr = OllamaManager(host=self.ollama_host)
                payload = [{"role": m.role, "content": m.content} for m in msgs]
                text = await mgr.chat_stream(model_name=model, messages=payload, token_cb=on_token)
                return ModelResponse(content=text, model_name=model, role="local",
                                     error=None if text else "empty local response")
            except Exception as e:  # noqa: BLE001
                return ModelResponse(content="", model_name=model, role="local", error=str(e))

        if prefer.startswith("api:"):
            rest = prefer[len("api:"):]
            provider_id, _, model = rest.partition(":")
            spec = next((s for s in CLOUD_PROVIDERS if s.id == provider_id), None)
            if spec is None:
                return ModelResponse(content="", model_name=rest, role="api",
                                     error=f"unknown provider '{provider_id}'")
            try:
                provider = self._load_provider(spec, model=model or spec.default_model)
                res = await self._stream_provider(provider, msgs, on_token)
                if res:
                    return res
                return ModelResponse(content="", model_name=model, role="api", error="empty response")
            except Exception as e:  # noqa: BLE001
                return ModelResponse(content="", model_name=model, role="api", error=str(e))

        return ModelResponse(content="", model_name=prefer, role="router",
                             error=f"unrecognised prefer target '{prefer}'")


_router_singleton: Optional[LLMRouter] = None


def get_llm_router() -> LLMRouter:
    """Process-wide router singleton."""
    global _router_singleton
    if _router_singleton is None:
        _router_singleton = LLMRouter()
    return _router_singleton
