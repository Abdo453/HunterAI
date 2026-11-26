"""Unified LLM Router — one canonical entry point for every model in HunterAI.
===============================================================================

Owner policy (see ``HUNTER_LLM_POLICY``): **cloud-first** — if any cloud
provider API key is present it is preferred, otherwise the router falls back to
the local Ollama server. Nothing is hard-wired to a single provider anymore.

Policies
--------
``cloud_first`` (default)  prefer cloud key, fall back to local Ollama
``local_first``            prefer local Ollama, fall back to cloud
``local_only``            Ollama only, never call the cloud (enforced BEFORE ``prefer``)
``cloud_only``            cloud only, never call Ollama

Catalog convention (consumed by the Web UI model picker)::

    api:<provider>:<model>     e.g. "api:gemini:gemini-2.5-flash"
    local:<ollama-model>       e.g. "local:qwen2.5-coder:14b"

Phase 6 Unification:
- Backed by ``core.llm.manifest.ModelManifest`` (unified Gemini defaults,
  hardware profiles, and per-role assignments).
- Bounded retries (``with_retry``) & non-deterministic failover (``with_failover``).
- Process-wide ``GPUScheduler`` serialization for local Ollama calls (interactive
  Copilot priority vs background scan tasks, configurable ``keep_alive``).
- Refusal-triggered reframed retry on BOTH ``_complete_cloud`` AND
  ``_complete_cloud_stream`` (preserving Phase 1 ``SecretSanitizer`` egress scrubbing).
- Persistent token & cost accounting via ``GLOBAL_COST_CONTROLLER.charge_call()``
  + ``PlatformStore.record_cost_entry()`` on EVERY completion & stream.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import importlib
import logging
import os
from typing import Any, Awaitable, Callable, Dict, List, Optional, Sequence, Tuple

from core.cost_budget import GLOBAL_COST_CONTROLLER
from core.governance.task_router import GovernedTaskRouter
from core.llm.errors import BackendError, classify_backend, is_deterministic_error
from core.llm.failover import should_failover, with_failover
from core.llm.gpu_scheduler import (
    PRIORITY_BACKGROUND,
    PRIORITY_INTERACTIVE,
    get_gpu_scheduler,
)
from core.llm.manifest import (
    DEFAULT_GEMINI_MODEL,
    GEMINI_MODELS,
    ModelManifest,
    get_model_manifest,
)
from core.llm.probe import (
    OllamaContextInfo,
    WireProbeResult,
    detect_ollama_context_window,
    detect_wire_kind,
)
from core.llm.retry import with_retry
from core.llm.stream_filter import ThinkingStreamFilter, strip_thinking_tags
from core.secret_sanitizer import SecretSanitizer
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


# Ordered by *owner preference*: NVIDIA first, then Gemini, DeepSeek, Claude, OpenAI,
# Groq, OpenRouter, Taskade. Availability is decided purely by the env key.
CLOUD_PROVIDERS: Tuple[ProviderSpec, ...] = (
    ProviderSpec(
        "nvidia",
        "NVIDIA_API_KEY",
        "models.api.nvidia_provider:NVIDIAProvider",
        "nvidia/nemotron-3-ultra-550b-a55b",
        "NVIDIA NIM",
        5,
        (
            "nvidia/nemotron-3-ultra-550b-a55b",
            "nvidia/nemotron-3-super-120b-a12b",
        ),
    ),
    ProviderSpec(
        "gemini",
        "GEMINI_API_KEY",
        "models.api.gemini_provider:GeminiProvider",
        DEFAULT_GEMINI_MODEL,
        "Google Gemini",
        10,
        GEMINI_MODELS,
    ),
    ProviderSpec(
        "deepseek",
        "DEEPSEEK_API_KEY",
        "models.api.deepseek_provider:DeepSeekProvider",
        "deepseek-chat",
        "DeepSeek",
        20,
        ("deepseek-chat", "deepseek-reasoner"),
    ),
    ProviderSpec(
        "anthropic",
        "ANTHROPIC_API_KEY",
        "models.api.anthropic_provider:AnthropicProvider",
        "claude-3-5-sonnet-20241022",
        "Anthropic Claude",
        30,
        ("claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022"),
    ),
    ProviderSpec(
        "openai",
        "OPENAI_API_KEY",
        "models.api.openai_provider:OpenAIProvider",
        "gpt-4o",
        "OpenAI",
        40,
        ("gpt-4o", "gpt-4o-mini", "o3-mini"),
    ),
    ProviderSpec(
        "groq",
        "GROQ_API_KEY",
        "models.api.groq_provider:GroqProvider",
        "llama-3.3-70b-versatile",
        "Groq",
        50,
        ("llama-3.3-70b-versatile",),
    ),
    ProviderSpec(
        "openrouter",
        "OPENROUTER_API_KEY",
        "models.api.openrouter_provider:OpenRouterProvider",
        "anthropic/claude-3.5-sonnet",
        "OpenRouter",
        60,
        ("anthropic/claude-3.5-sonnet", "google/gemini-2.5-flash"),
    ),
    ProviderSpec(
        "taskade",
        "TASKADE_API_KEY",
        "models.api.taskade_provider:TaskadeProvider",
        "taskade-ai",
        "Taskade",
        70,
        ("taskade-ai",),
    ),
)

# Local models that make good general-purpose fallbacks, in preference order.
_LOCAL_PREFERENCE = ("qwen", "llama", "mistral", "whiterabbit", "xploiter")


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


def _estimate_tokens_from_messages(msgs: Sequence[Message]) -> int:
    total_chars = sum(len(m.content or "") for m in msgs)
    return max(1, total_chars // 4) if total_chars > 0 else 0


def _estimate_tokens_from_text(text: str) -> int:
    return max(1, len(text) // 4) if text else 0


class LLMRouter:
    """Canonical cloud-first / policy-governed LLM router with GPU scheduling & cost ledger."""

    def __init__(
        self,
        ollama_host: Optional[str] = None,
        policy: Optional[str] = None,
        manifest: Optional[ModelManifest] = None,
    ):
        from models.ollama_manager import normalize_ollama_host

        self.manifest = manifest or get_model_manifest()
        self.ollama_host = normalize_ollama_host(
            ollama_host or os.getenv("OLLAMA_HOST") or self.manifest.default_host
        )
        self._policy = (policy or os.getenv(POLICY_ENV, DEFAULT_POLICY)).strip().lower()
        self._ctx_cache: Dict[str, int] = {}

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

    # ── catalog & probing ────────────────────────────────────────────────────
    def cloud_specs(self, only_available: bool = True) -> List[ProviderSpec]:
        specs = sorted(CLOUD_PROVIDERS, key=lambda s: s.priority)
        if only_available:
            specs = [s for s in specs if os.getenv(s.env_key)]
        return specs

    @staticmethod
    def default_model_for(spec: ProviderSpec) -> str:
        override = os.getenv(f"{spec.id.upper()}_MODEL", "").strip()
        if override and (not spec.models or override in spec.models):
            return override
        manifest_default = get_model_manifest().get_default_model(spec.id)
        if manifest_default and (not spec.models or manifest_default in spec.models):
            return manifest_default
        return spec.default_model

    def _load_provider(self, spec: ProviderSpec, model: Optional[str] = None):
        module_name, _, cls_name = spec.target.partition(":")
        module = importlib.import_module(module_name)
        cls = getattr(module, cls_name)
        return cls(model=model or self.default_model_for(spec))

    async def probe_local_wire(self, base_url: Optional[str] = None) -> WireProbeResult:
        """SSRF-gated wire detection (native Ollama vs OpenAI-compatible)."""
        return await detect_wire_kind(base_url or self.ollama_host)

    async def probe_local_context(self, model_name: str, base_url: Optional[str] = None) -> Optional[OllamaContextInfo]:
        """SSRF-gated Ollama ``/api/show`` context window detection."""
        info = await detect_ollama_context_window(base_url or self.ollama_host, model_name)
        if info is not None:
            self._ctx_cache[model_name] = info.num_ctx
        return info

    def resolve_role_target(self, role: str) -> Tuple[str, Dict[str, Any]]:
        """Resolve role config (local model, cloud model, temperature, context window)."""
        profile = self.manifest.resolve_hardware_profile()
        cfg = self.manifest.get_role_config(role, profile=profile)
        return cfg.local_model, {
            "role": cfg.role,
            "local_model": cfg.local_model,
            "cloud_provider": cfg.cloud_provider,
            "cloud_model": cfg.cloud_model,
            "temperature": cfg.temperature,
            "max_tokens": cfg.max_tokens,
            "context_window": cfg.context_window,
            "priority": PRIORITY_INTERACTIVE if cfg.priority == "interactive" else PRIORITY_BACKGROUND,
        }

    def _resolve_num_ctx(self, model_name: str, explicit_num_ctx: Optional[int] = None) -> int:
        if explicit_num_ctx and explicit_num_ctx > 0:
            return int(explicit_num_ctx)
        if model_name in self._ctx_cache:
            return self._ctx_cache[model_name]
        return self.manifest.context_window_for(model_name, default=8192)

    def _resolve_keep_alive(self, explicit_keep_alive: Optional[int] = None) -> int:
        if explicit_keep_alive is not None:
            return max(0, int(explicit_keep_alive))
        env_val = os.getenv("HUNTER_OLLAMA_KEEP_ALIVE_SEC")
        if env_val is not None and env_val.strip():
            try:
                return max(0, int(env_val.strip()))
            except ValueError:
                pass
        return get_gpu_scheduler().default_keep_alive

    async def local_models(self) -> List[str]:
        try:
            from models.ollama_manager import OllamaManager

            mgr = OllamaManager(host=self.ollama_host)
            return list(await mgr.list_available() or [])
        except Exception as e:  # noqa: BLE001 - probe failures are non-fatal
            logger.debug("[LLMRouter] local model probe failed: %s", e)
            return []

    def _pick_local(self, models: List[str], *, preferred_role: Optional[str] = None) -> Optional[str]:
        if not models:
            return None
        if preferred_role:
            role_model, _ = self.resolve_role_target(preferred_role)
            role_base = role_model.split(":")[0].lower()
            for m in models:
                if m.lower() == role_model.lower() or role_base in m.lower():
                    return m
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
        cloud = []
        for s in self.cloud_specs(only_available=True):
            default_model = self.default_model_for(s)
            models = list(s.models or (default_model,))
            if default_model not in models:
                models.insert(0, default_model)
            cloud.append({
                "provider": s.id,
                "label": s.label,
                "default_model": default_model,
                "models": models,
            })
        return {
            "policy": self.policy,
            "ollama_host": self.ollama_host,
            "cloud_available": bool(cloud),
            "local_available": bool(local),
            "local": {"available": bool(local), "models": local},
            "cloud": cloud,
            "choices": self._choices(local, cloud),
            "roles": {k: v.model_dump() for k, v in self.manifest.roles.items()},
        }

    # ── governance & scrubbing ───────────────────────────────────────────────
    def _effective_policy(self, task_kind: Optional[str] = None, redacted: bool = False) -> str:
        if self.policy == "local_only":
            return "local_only"
        if GovernedTaskRouter.is_local_only_task(task_kind, redacted=redacted):
            return "local_only"
        return self.policy

    @staticmethod
    def _scrub_for_cloud(msgs: List[Message]) -> List[Message]:
        """Scrub secrets before cloud LLM egress without mutating caller messages."""
        return [
            Message(role=m.role, content=SecretSanitizer.sanitize_text(m.content))
            for m in msgs
        ]

    # ── cost accounting + PlatformStore persistence ──────────────────────────
    async def _record_usage_and_cost(
        self,
        *,
        provider: str,
        model: str,
        msgs: Sequence[Message],
        response: ModelResponse,
        run_id: str = "",
        engagement_id: str = "",
        task_id: str = "",
        role: str = "",
        streamed: bool = False,
    ) -> None:
        if not response or not response.content:
            return
        in_tokens = _estimate_tokens_from_messages(msgs)
        out_tokens = _estimate_tokens_from_text(response.content)
        if getattr(response, "tokens_used", 0) and int(response.tokens_used) > 0:
            reported_total = int(response.tokens_used)
            if reported_total > in_tokens:
                out_tokens = reported_total - in_tokens
            else:
                out_tokens = max(1, reported_total // 2)
                in_tokens = max(1, reported_total - out_tokens)
        else:
            response.tokens_used = in_tokens + out_tokens

        eff_role = (role or getattr(response, "role", "") or "general").strip()
        charged = GLOBAL_COST_CONTROLLER.charge_call(
            model=model,
            input_tokens=in_tokens,
            output_tokens=out_tokens,
            run_id=run_id,
            provider=provider,
            role=eff_role,
        )
        cost_usd = float(charged) if charged is not None else 0.0

        try:
            from core.platform_store import get_platform_store

            store = get_platform_store()
            await asyncio.to_thread(
                store.record_cost_entry,
                provider=provider,
                model=model,
                input_tokens=in_tokens,
                output_tokens=out_tokens,
                cost_usd=cost_usd,
                run_id=run_id or None,
                task_id=task_id or None,
                engagement_id=engagement_id or None,
                metadata={"role": eff_role, "streamed": streamed},
            )
        except Exception as exc:  # noqa: BLE001 - telemetry write must not crash inference
            logger.debug("[LLMRouter] cost_ledger persistence skipped: %s", exc)

    # ── refusal reframe helper ───────────────────────────────────────────────
    async def _retry_provider_on_refusal(
        self,
        provider: Any,
        msgs: List[Message],
        res: ModelResponse,
        provider_label: str,
        errors: Optional[List[str]] = None,
        *,
        on_token: Optional[Callable[[str], Awaitable[None]]] = None,
        use_stream: bool = False,
    ) -> Optional[ModelResponse]:
        """When a model returns a refusal, reframe and retry the same model once."""
        from core.ai_bridge.defensive_prompt_framer import DefensivePromptFramer
        from core.ai_bridge.refusal_detector import RefusalDetector

        check = RefusalDetector.check_response(res.content)
        if not check.is_refusal:
            return res
        logger.warning(
            "[LLMRouter] %s refused request ('%s'); retrying same model with reframed phrasing.",
            provider_label,
            check.matched_signature,
        )
        reframed_msgs = self._scrub_for_cloud(
            _coerce_messages(
                DefensivePromptFramer.reframe_messages_on_refusal(
                    msgs, refusal_signature=check.matched_signature
                )
            )
        )
        if use_stream:
            retry_res = await self._stream_provider(provider, reframed_msgs, on_token)
        else:
            retry_res = await provider.chat(reframed_msgs)
        if retry_res and retry_res.content:
            retry_check = RefusalDetector.check_response(retry_res.content)
            if not retry_check.is_refusal:
                return retry_res
            if errors is not None:
                errors.append(f"{provider_label}: refused after reframe ({retry_check.matched_signature})")
            return None
        if retry_res and retry_res.error and errors is not None:
            errors.append(f"{provider_label}: {retry_res.error}")
        return None

    # ── completion ───────────────────────────────────────────────────────────
    async def complete(
        self,
        messages: Sequence[Any],
        prefer: Optional[str] = None,
        system_prompt: str = "",
        errors: Optional[List[str]] = None,
        task_kind: Optional[str] = None,
        redacted: bool = False,
        *,
        role: Optional[str] = None,
        priority: int = PRIORITY_BACKGROUND,
        run_id: str = "",
        engagement_id: str = "",
        task_id: str = "",
        keep_alive: Optional[int] = None,
        num_ctx: Optional[int] = None,
        strip_thinking: bool = False,
    ) -> ModelResponse:
        """Generate a completion following configured policy, task governance, and cost tracking.

        ``prefer`` (optional) forces a specific target, ALWAYS subject to ``policy`` and
        ``GovernedTaskRouter.LOCAL_ONLY_TASK_KINDS`` (Phase 1 ``local_only`` lock runs
        BEFORE ``prefer``):
          * ``"api:<provider>:<model>"`` — one cloud provider call (blocked when ``local_only``)
          * ``"local:<ollama-model>"``   — one local Ollama call (blocked when ``cloud_only``)
        """
        msgs = _coerce_messages(messages)
        if system_prompt and not any(m.role == "system" for m in msgs):
            msgs = [Message(role="system", content=system_prompt)] + msgs
        if not msgs:
            return ModelResponse(content="", model_name="none", role="router", error="no messages supplied")

        effective_policy = self._effective_policy(task_kind=task_kind, redacted=redacted)

        if prefer:
            res = await self._dispatch(
                prefer,
                msgs,
                effective_policy=effective_policy,
                priority=priority,
                keep_alive=keep_alive,
                num_ctx=num_ctx,
                role=role or "",
                run_id=run_id,
                engagement_id=engagement_id,
                task_id=task_id,
            )
            if strip_thinking and res and res.content:
                res.content = strip_thinking_tags(res.content)
            return res

        collected: List[str] = errors if errors is not None else []
        order = self._order(effective_policy)

        async def _call_tier(tier_kind: str) -> ModelResponse:
            if tier_kind == "cloud":
                r = await self._complete_cloud(
                    msgs,
                    collected,
                    role=role or "",
                    run_id=run_id,
                    engagement_id=engagement_id,
                    task_id=task_id,
                )
            else:
                r = await self._complete_local(
                    msgs,
                    collected,
                    role=role,
                    priority=priority,
                    keep_alive=keep_alive,
                    num_ctx=num_ctx,
                    run_id=run_id,
                    engagement_id=engagement_id,
                    task_id=task_id,
                )
            if r and r.content:
                return r
            raise BackendError(
                tier_kind,
                "backend-down",
                503,
                "; ".join(collected) or f"{tier_kind} tier unavailable",
            )

        res: Optional[ModelResponse] = None
        if len(order) == 2:
            try:
                res = await with_failover(
                    lambda: _call_tier(order[0]),
                    lambda: _call_tier(order[1]),
                )
            except BackendError:
                res = None
        else:
            try:
                res = await _call_tier(order[0])
            except BackendError:
                res = None

        if res and res.content:
            if strip_thinking:
                res.content = strip_thinking_tags(res.content)
            return res
        return ModelResponse(
            content="",
            model_name="none",
            role="router",
            error="; ".join(collected) or "no model available",
        )

    async def _complete_cloud(
        self,
        msgs: List[Message],
        errors: List[str],
        *,
        role: str = "",
        run_id: str = "",
        engagement_id: str = "",
        task_id: str = "",
    ) -> Optional[ModelResponse]:
        scrubbed_msgs = self._scrub_for_cloud(msgs)
        for spec in self.cloud_specs(only_available=True):
            try:
                provider = self._load_provider(spec)
                if hasattr(provider, "is_available") and not await provider.is_available():
                    continue
                res = await with_retry(
                    lambda p=provider: p.chat(scrubbed_msgs),
                    retries=1,
                    base_delay_s=0.2,
                    max_delay_s=1.0,
                )
                if res and res.content:
                    checked = await self._retry_provider_on_refusal(
                        provider, scrubbed_msgs, res, spec.id, errors
                    )
                    if checked and checked.content:
                        model_used = checked.model_name or self.default_model_for(spec)
                        await self._record_usage_and_cost(
                            provider=spec.id,
                            model=model_used,
                            msgs=scrubbed_msgs,
                            response=checked,
                            run_id=run_id,
                            engagement_id=engagement_id,
                            task_id=task_id,
                            role=role or "cloud",
                            streamed=False,
                        )
                        logger.info("[LLMRouter] answered via %s:%s", spec.id, model_used)
                        return checked
                    continue
                if res and res.error:
                    errors.append(f"{spec.id}: {res.error}")
            except Exception as e:  # noqa: BLE001
                errors.append(f"{spec.id}: {e}")
        return None

    async def _complete_local(
        self,
        msgs: List[Message],
        errors: List[str],
        *,
        role: Optional[str] = None,
        priority: int = PRIORITY_BACKGROUND,
        keep_alive: Optional[int] = None,
        num_ctx: Optional[int] = None,
        run_id: str = "",
        engagement_id: str = "",
        task_id: str = "",
    ) -> Optional[ModelResponse]:
        models = await self.local_models()
        model = self._pick_local(models, preferred_role=role)
        if not model:
            errors.append("ollama: no local models available")
            return None
        try:
            from models.ollama_manager import OllamaManager

            mgr = OllamaManager(host=self.ollama_host)
            payload = [{"role": m.role, "content": m.content} for m in msgs]
            eff_keep_alive = self._resolve_keep_alive(keep_alive)
            eff_num_ctx = self._resolve_num_ctx(model, num_ctx)
            scheduler = get_gpu_scheduler()
            async with scheduler.acquire(
                model,
                priority=priority,
                keep_alive=eff_keep_alive,
                ollama_manager=mgr,
            ):
                text = await mgr.chat(
                    model_name=model,
                    messages=payload,
                    keep_alive=eff_keep_alive,
                    num_ctx=eff_num_ctx,
                )
            if text:
                res = ModelResponse(content=text, model_name=model, role="local")
                await self._record_usage_and_cost(
                    provider="ollama",
                    model=model,
                    msgs=msgs,
                    response=res,
                    run_id=run_id,
                    engagement_id=engagement_id,
                    task_id=task_id,
                    role=role or "local",
                    streamed=False,
                )
                logger.info("[LLMRouter] answered via local:%s", model)
                return res
            errors.append(f"ollama:{model}: empty response")
        except Exception as e:  # noqa: BLE001
            errors.append(f"ollama: {e}")
        return None

    async def _dispatch(
        self,
        prefer: str,
        msgs: List[Message],
        *,
        effective_policy: Optional[str] = None,
        priority: int = PRIORITY_BACKGROUND,
        keep_alive: Optional[int] = None,
        num_ctx: Optional[int] = None,
        role: str = "",
        run_id: str = "",
        engagement_id: str = "",
        task_id: str = "",
    ) -> ModelResponse:
        policy = effective_policy or self.policy

        if prefer.startswith("local:"):
            if policy == "cloud_only":
                return ModelResponse(
                    content="",
                    model_name=prefer,
                    role="router",
                    error="policy violation: local model blocked under cloud_only policy",
                )
            model = prefer[len("local:"):].strip()
            try:
                from models.ollama_manager import OllamaManager

                mgr = OllamaManager(host=self.ollama_host)
                payload = [{"role": m.role, "content": m.content} for m in msgs]
                eff_keep_alive = self._resolve_keep_alive(keep_alive)
                eff_num_ctx = self._resolve_num_ctx(model, num_ctx)
                scheduler = get_gpu_scheduler()
                async with scheduler.acquire(
                    model,
                    priority=priority,
                    keep_alive=eff_keep_alive,
                    ollama_manager=mgr,
                ):
                    text = await mgr.chat(
                        model_name=model,
                        messages=payload,
                        keep_alive=eff_keep_alive,
                        num_ctx=eff_num_ctx,
                    )
                res = ModelResponse(
                    content=text,
                    model_name=model,
                    role="local",
                    error=None if text else "empty local response",
                )
                if text:
                    await self._record_usage_and_cost(
                        provider="ollama",
                        model=model,
                        msgs=msgs,
                        response=res,
                        run_id=run_id,
                        engagement_id=engagement_id,
                        task_id=task_id,
                        role=role or "local",
                        streamed=False,
                    )
                return res
            except Exception as e:  # noqa: BLE001
                return ModelResponse(content="", model_name=model, role="local", error=str(e))

        if prefer.startswith("api:"):
            if policy == "local_only":
                logger.warning("[LLMRouter] Blocked cloud dispatch '%s' under local_only policy", prefer)
                return ModelResponse(
                    content="",
                    model_name=prefer,
                    role="router",
                    error="policy violation: cloud provider blocked under local_only policy",
                )
            rest = prefer[len("api:"):]
            provider_id, _, model = rest.partition(":")
            spec = next((s for s in CLOUD_PROVIDERS if s.id == provider_id), None)
            if spec is None:
                return ModelResponse(
                    content="",
                    model_name=rest,
                    role="api",
                    error=f"unknown provider '{provider_id}'",
                )
            eff_model = model or self.default_model_for(spec)
            try:
                scrubbed_msgs = self._scrub_for_cloud(msgs)
                provider = self._load_provider(spec, model=eff_model)
                res = await provider.chat(scrubbed_msgs)
                if res and res.content:
                    checked = await self._retry_provider_on_refusal(
                        provider, scrubbed_msgs, res, f"{spec.id}:{eff_model}"
                    )
                    final_res = checked or res
                    await self._record_usage_and_cost(
                        provider=spec.id,
                        model=final_res.model_name or eff_model,
                        msgs=scrubbed_msgs,
                        response=final_res,
                        run_id=run_id,
                        engagement_id=engagement_id,
                        task_id=task_id,
                        role=role or "api",
                        streamed=False,
                    )
                    return final_res
                if res:
                    return res
                return ModelResponse(content="", model_name=eff_model, role="api", error="empty response")
            except Exception as e:  # noqa: BLE001
                return ModelResponse(content="", model_name=eff_model, role="api", error=str(e))

        return ModelResponse(
            content="",
            model_name=prefer,
            role="router",
            error=f"unrecognised prefer target '{prefer}'",
        )

    # ── streaming completion ─────────────────────────────────────────────────
    async def complete_stream(
        self,
        messages: Sequence[Any],
        prefer: Optional[str] = None,
        system_prompt: str = "",
        on_token: Optional[Callable[[str], Awaitable[None]]] = None,
        errors: Optional[List[str]] = None,
        task_kind: Optional[str] = None,
        redacted: bool = False,
        *,
        role: Optional[str] = None,
        priority: int = PRIORITY_BACKGROUND,
        run_id: str = "",
        engagement_id: str = "",
        task_id: str = "",
        keep_alive: Optional[int] = None,
        num_ctx: Optional[int] = None,
        strip_thinking: bool = False,
    ) -> ModelResponse:
        """Like :meth:`complete` but forwards token deltas to ``on_token``.

        Enforces Phase 1 ``local_only`` lock BEFORE ``prefer``, applies
        ``_retry_provider_on_refusal`` on cloud streams, serializes local Ollama
        streams through ``GPUScheduler``, and persists token/cost telemetry on
        every completed stream.
        """
        msgs = _coerce_messages(messages)
        if system_prompt and not any(m.role == "system" for m in msgs):
            msgs = [Message(role="system", content=system_prompt)] + msgs
        if not msgs:
            return ModelResponse(content="", model_name="none", role="router", error="no messages supplied")

        effective_policy = self._effective_policy(task_kind=task_kind, redacted=redacted)

        stream_filter = ThinkingStreamFilter() if strip_thinking else None
        effective_on_token = on_token
        if stream_filter is not None and on_token is not None:
            async def _filtered_cb(delta: str) -> None:
                clean = stream_filter.push(delta)
                if clean:
                    await on_token(clean)

            effective_on_token = _filtered_cb

        async def _finalize_filter(res: ModelResponse) -> ModelResponse:
            if stream_filter is not None:
                tail = stream_filter.flush()
                if tail and on_token is not None:
                    await on_token(tail)
                if res and res.content:
                    res.content = strip_thinking_tags(res.content)
            return res

        if prefer:
            res = await self._dispatch_stream(
                prefer,
                msgs,
                effective_on_token,
                effective_policy=effective_policy,
                priority=priority,
                keep_alive=keep_alive,
                num_ctx=num_ctx,
                role=role or "",
                run_id=run_id,
                engagement_id=engagement_id,
                task_id=task_id,
            )
            return await _finalize_filter(res)

        collected: List[str] = errors if errors is not None else []
        for kind in self._order(effective_policy):
            if kind == "cloud":
                res = await self._complete_cloud_stream(
                    msgs,
                    effective_on_token,
                    collected,
                    role=role or "",
                    run_id=run_id,
                    engagement_id=engagement_id,
                    task_id=task_id,
                )
            else:
                res = await self._complete_local_stream(
                    msgs,
                    effective_on_token,
                    collected,
                    role=role,
                    priority=priority,
                    keep_alive=keep_alive,
                    num_ctx=num_ctx,
                    run_id=run_id,
                    engagement_id=engagement_id,
                    task_id=task_id,
                )
            if res and res.content:
                return await _finalize_filter(res)
        return ModelResponse(
            content="",
            model_name="none",
            role="router",
            error="; ".join(collected) or "no model available",
        )

    async def _stream_provider(
        self,
        provider: Any,
        msgs: List[Message],
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
        res = await provider.chat(msgs)
        if res and res.content and on_token:
            await on_token(res.content)
        return res

    async def _complete_cloud_stream(
        self,
        msgs: List[Message],
        on_token: Optional[Callable[[str], Awaitable[None]]],
        errors: List[str],
        *,
        role: str = "",
        run_id: str = "",
        engagement_id: str = "",
        task_id: str = "",
    ) -> Optional[ModelResponse]:
        scrubbed_msgs = self._scrub_for_cloud(msgs)
        for spec in self.cloud_specs(only_available=True):
            try:
                provider = self._load_provider(spec)
                if hasattr(provider, "is_available") and not await provider.is_available():
                    continue
                res = await self._stream_provider(provider, scrubbed_msgs, on_token)
                if res and res.content:
                    checked = await self._retry_provider_on_refusal(
                        provider,
                        scrubbed_msgs,
                        res,
                        spec.id,
                        errors,
                        on_token=on_token,
                        use_stream=True,
                    )
                    if checked and checked.content:
                        model_used = checked.model_name or self.default_model_for(spec)
                        await self._record_usage_and_cost(
                            provider=spec.id,
                            model=model_used,
                            msgs=scrubbed_msgs,
                            response=checked,
                            run_id=run_id,
                            engagement_id=engagement_id,
                            task_id=task_id,
                            role=role or "cloud",
                            streamed=True,
                        )
                        logger.info("[LLMRouter] streamed via %s:%s", spec.id, model_used)
                        return checked
                    continue
                if res and res.error:
                    errors.append(f"{spec.id}: {res.error}")
            except Exception as e:  # noqa: BLE001
                errors.append(f"{spec.id}: {e}")
        return None

    async def _complete_local_stream(
        self,
        msgs: List[Message],
        on_token: Optional[Callable[[str], Awaitable[None]]],
        errors: List[str],
        *,
        role: Optional[str] = None,
        priority: int = PRIORITY_BACKGROUND,
        keep_alive: Optional[int] = None,
        num_ctx: Optional[int] = None,
        run_id: str = "",
        engagement_id: str = "",
        task_id: str = "",
    ) -> Optional[ModelResponse]:
        models = await self.local_models()
        model = self._pick_local(models, preferred_role=role)
        if not model:
            errors.append("ollama: no local models available")
            return None
        try:
            from models.ollama_manager import OllamaManager

            mgr = OllamaManager(host=self.ollama_host)
            payload = [{"role": m.role, "content": m.content} for m in msgs]
            eff_keep_alive = self._resolve_keep_alive(keep_alive)
            eff_num_ctx = self._resolve_num_ctx(model, num_ctx)
            scheduler = get_gpu_scheduler()
            async with scheduler.acquire(
                model,
                priority=priority,
                keep_alive=eff_keep_alive,
                ollama_manager=mgr,
            ):
                text = await mgr.chat_stream(
                    model_name=model,
                    messages=payload,
                    keep_alive=eff_keep_alive,
                    num_ctx=eff_num_ctx,
                    token_cb=on_token,
                )
            if text:
                res = ModelResponse(content=text, model_name=model, role="local")
                await self._record_usage_and_cost(
                    provider="ollama",
                    model=model,
                    msgs=msgs,
                    response=res,
                    run_id=run_id,
                    engagement_id=engagement_id,
                    task_id=task_id,
                    role=role or "local",
                    streamed=True,
                )
                logger.info("[LLMRouter] streamed via local:%s", model)
                return res
            errors.append(f"ollama:{model}: empty response")
        except Exception as e:  # noqa: BLE001
            errors.append(f"ollama: {e}")
        return None

    async def _dispatch_stream(
        self,
        prefer: str,
        msgs: List[Message],
        on_token: Optional[Callable[[str], Awaitable[None]]],
        *,
        effective_policy: Optional[str] = None,
        priority: int = PRIORITY_BACKGROUND,
        keep_alive: Optional[int] = None,
        num_ctx: Optional[int] = None,
        role: str = "",
        run_id: str = "",
        engagement_id: str = "",
        task_id: str = "",
    ) -> ModelResponse:
        policy = effective_policy or self.policy

        if prefer.startswith("local:"):
            if policy == "cloud_only":
                return ModelResponse(
                    content="",
                    model_name=prefer,
                    role="router",
                    error="policy violation: local model blocked under cloud_only policy",
                )
            model = prefer[len("local:"):].strip()
            try:
                from models.ollama_manager import OllamaManager

                mgr = OllamaManager(host=self.ollama_host)
                payload = [{"role": m.role, "content": m.content} for m in msgs]
                eff_keep_alive = self._resolve_keep_alive(keep_alive)
                eff_num_ctx = self._resolve_num_ctx(model, num_ctx)
                scheduler = get_gpu_scheduler()
                async with scheduler.acquire(
                    model,
                    priority=priority,
                    keep_alive=eff_keep_alive,
                    ollama_manager=mgr,
                ):
                    text = await mgr.chat_stream(
                        model_name=model,
                        messages=payload,
                        keep_alive=eff_keep_alive,
                        num_ctx=eff_num_ctx,
                        token_cb=on_token,
                    )
                res = ModelResponse(
                    content=text,
                    model_name=model,
                    role="local",
                    error=None if text else "empty local response",
                )
                if text:
                    await self._record_usage_and_cost(
                        provider="ollama",
                        model=model,
                        msgs=msgs,
                        response=res,
                        run_id=run_id,
                        engagement_id=engagement_id,
                        task_id=task_id,
                        role=role or "local",
                        streamed=True,
                    )
                return res
            except Exception as e:  # noqa: BLE001
                return ModelResponse(content="", model_name=model, role="local", error=str(e))

        if prefer.startswith("api:"):
            if policy == "local_only":
                logger.warning("[LLMRouter] Blocked cloud stream dispatch '%s' under local_only policy", prefer)
                return ModelResponse(
                    content="",
                    model_name=prefer,
                    role="router",
                    error="policy violation: cloud provider blocked under local_only policy",
                )
            rest = prefer[len("api:"):]
            provider_id, _, model = rest.partition(":")
            spec = next((s for s in CLOUD_PROVIDERS if s.id == provider_id), None)
            if spec is None:
                return ModelResponse(
                    content="",
                    model_name=rest,
                    role="api",
                    error=f"unknown provider '{provider_id}'",
                )
            eff_model = model or self.default_model_for(spec)
            try:
                scrubbed_msgs = self._scrub_for_cloud(msgs)
                provider = self._load_provider(spec, model=eff_model)
                res = await self._stream_provider(provider, scrubbed_msgs, on_token)
                if res and res.content:
                    checked = await self._retry_provider_on_refusal(
                        provider,
                        scrubbed_msgs,
                        res,
                        f"{spec.id}:{eff_model}",
                        on_token=on_token,
                        use_stream=True,
                    )
                    final_res = checked or res
                    await self._record_usage_and_cost(
                        provider=spec.id,
                        model=final_res.model_name or eff_model,
                        msgs=scrubbed_msgs,
                        response=final_res,
                        run_id=run_id,
                        engagement_id=engagement_id,
                        task_id=task_id,
                        role=role or "api",
                        streamed=True,
                    )
                    return final_res
                if res:
                    return res
                return ModelResponse(content="", model_name=eff_model, role="api", error="empty response")
            except Exception as e:  # noqa: BLE001
                return ModelResponse(content="", model_name=eff_model, role="api", error=str(e))

        return ModelResponse(
            content="",
            model_name=prefer,
            role="router",
            error=f"unrecognised prefer target '{prefer}'",
        )


_router_singleton: Optional[LLMRouter] = None


def get_llm_router() -> LLMRouter:
    """Process-wide router singleton."""
    global _router_singleton
    if _router_singleton is None:
        _router_singleton = LLMRouter()
    return _router_singleton
