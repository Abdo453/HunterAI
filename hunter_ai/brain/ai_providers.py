"""
HunterAI AI Providers — Multi-Provider LLM Layer
================================================
Free-first provider auto-detection: Ollama → Groq → DeepSeek → …
No subscription required. Ollama runs 100% locally.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class AIProvider:
    name: str
    cost: str
    privacy: str
    speed: str
    active: bool = False
    model: str = ""
    base_url: str = ""


# Ordered list: free-first priority
_PROVIDERS: List[AIProvider] = [
    AIProvider("ollama", "100% free · local", "Full", "Fast", base_url="http://127.0.0.1:11434"),
    AIProvider("groq", "Free tier", "Cloud", "Very fast"),
    AIProvider("deepseek", "Very cheap", "Cloud", "Fast"),
    AIProvider("claude", "Paid", "Cloud", "Fast"),
    AIProvider("openai", "Paid", "Cloud", "Fast"),
    AIProvider("grok", "Paid", "Cloud", "Fast"),
    AIProvider("openrouter", "Subscription / pay-as-you-go", "Cloud", "Fast"),
    AIProvider("orca_router", "Subscription / pay-as-you-go", "Cloud", "Fast"),
    AIProvider("sidrune_ai", "Subscription / pay-as-you-go", "Cloud", "Fast"),
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


def ask_ai(question: str) -> str:
    """Ask the active AI provider a question."""
    p = active_provider()
    # Try Ollama first if active
    if p["name"] == "ollama":
        return _ask_ollama(question)
    return f"[AI] {p['name']} would answer: {question} (provider integration pending)"


def _ask_ollama(question: str) -> str:
    """Query local Ollama."""
    import json
    import urllib.request

    host = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")
    model = os.getenv("HUNTER_AI_MODEL", "qwen2.5:14b")
    payload = {
        "model": model,
        "prompt": question,
        "stream": False,
    }
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{host}/api/generate",
            data=data,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            return result.get("response", "No response from Ollama")
    except Exception as e:
        return f"[Ollama error] {e}. Is Ollama running? Run: ollama serve"


__all__ = ["list_providers", "choose_provider", "active_provider", "ask_ai", "AIProvider"]
