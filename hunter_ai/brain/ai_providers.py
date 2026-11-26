"""HunterAI AI Providers — Thin Forwarding Shim to ``core.llm_router``.

Preserves ``list_providers``, ``choose_provider``, ``active_provider``, ``ask_ai``,
and ``AIProvider`` while delegating all cloud and local LLM inference through the
canonical ``core.llm_router.LLMRouter`` (eliminating placeholder cloud text and
raw ``urllib.request`` calls).
"""
from __future__ import annotations

import asyncio
import concurrent.futures
from dataclasses import dataclass
import os
from typing import Any, Dict, List, Optional

from core.llm.manifest import DEFAULT_GEMINI_MODEL, get_model_manifest
from core.llm_router import LLMRouter, get_llm_router

_PROVIDER_ALIAS_MAP: Dict[str, str] = {
    "claude": "anthropic",
    "gemini": "gemini",
    "groq": "groq",
    "deepseek": "deepseek",
    "openai": "openai",
    "openrouter": "openrouter",
    "nvidia": "nvidia",
    "taskade": "taskade",
    "ollama": "ollama",
}


@dataclass
class AIProvider:
    name: str
    cost: str
    privacy: str
    speed: str
    active: bool = False
    model: str = ""
    base_url: str = ""


_PROVIDERS: List[AIProvider] = [
    AIProvider(
        "ollama",
        "100% free · local",
        "Full",
        "Fast",
        model=os.getenv("HUNTER_AI_MODEL", "qwen2.5-coder:14b"),
        base_url=os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434"),
    ),
    AIProvider("gemini", "Free / pay-as-you-go", "Cloud", "Very fast", model=DEFAULT_GEMINI_MODEL),
    AIProvider("groq", "Free tier", "Cloud", "Very fast", model="llama-3.3-70b-versatile"),
    AIProvider("deepseek", "Very cheap", "Cloud", "Fast", model="deepseek-chat"),
    AIProvider("claude", "Paid", "Cloud", "Fast", model="claude-3-5-sonnet-20241022"),
    AIProvider("openai", "Paid", "Cloud", "Fast", model="gpt-4o"),
    AIProvider("openrouter", "Subscription / pay-as-you-go", "Cloud", "Fast", model="anthropic/claude-3.5-sonnet"),
    AIProvider("nvidia", "API key", "Cloud", "Fast", model="nvidia/nemotron-3-ultra-550b-a55b"),
]

_ACTIVE_INDEX = 0  # ollama by default


def list_providers() -> List[Dict[str, Any]]:
    """Return all providers as dicts."""
    return [
        {
            "name": p.name,
            "cost": p.cost,
            "privacy": p.privacy,
            "speed": p.speed,
            "active": i == _ACTIVE_INDEX,
            "model": p.model,
            "base_url": p.base_url,
        }
        for i, p in enumerate(_PROVIDERS)
    ]


def choose_provider(name: str, model: Optional[str] = None) -> None:
    """Set the active provider."""
    global _ACTIVE_INDEX
    for i, p in enumerate(_PROVIDERS):
        if p.name.lower() == name.lower():
            _ACTIVE_INDEX = i
            if model:
                p.model = model
            p.active = True
        else:
            p.active = False
    os.environ["HUNTER_AI_PROVIDER"] = name
    if model:
        os.environ["HUNTER_AI_MODEL"] = model


def active_provider() -> Dict[str, Any]:
    """Return the currently active provider."""
    return list_providers()[_ACTIVE_INDEX]


def _run_coro_sync(coro: Any) -> Any:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


def ask_ai(question: str, *, system_prompt: str = "", router: Optional[LLMRouter] = None) -> str:
    """Ask the active AI provider a question via the canonical ``LLMRouter``."""
    p = active_provider()
    canonical_name = _PROVIDER_ALIAS_MAP.get(p["name"].lower(), p["name"].lower())
    manifest = get_model_manifest()

    if canonical_name == "ollama":
        model = p.get("model") or os.getenv("HUNTER_AI_MODEL") or "qwen2.5-coder:14b"
        prefer = f"local:{model}"
    else:
        model = p.get("model") or manifest.get_default_model(canonical_name)
        prefer = f"api:{canonical_name}:{model}" if model else None

    active_router = router or get_llm_router()
    resp = _run_coro_sync(
        active_router.complete(
            [{"role": "user", "content": question}],
            prefer=prefer,
            system_prompt=system_prompt,
        )
    )
    if resp and resp.content:
        return resp.content
    err = getattr(resp, "error", "") or "provider unavailable"
    return f"[{p['name']} error] {err}"


__all__ = ["list_providers", "choose_provider", "active_provider", "ask_ai", "AIProvider"]
