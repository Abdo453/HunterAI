"""HunterAI Context Manager (Thin Delegation Shim to ``core.context.manager``).

Preserves the ``hunter_ai.context.manager.ContextManager`` API while eliminating
``json.dumps(...)[:N]`` JSON corruption by delegating to the canonical
``core.context.manager.ContextManager``.
"""
from __future__ import annotations

from typing import Any, Dict

from core.context.manager import ContextManager as CanonicalContextManager


class ContextManager(CanonicalContextManager):
    """Backwards-compatible subclass delegating to ``core.context.manager.ContextManager``."""

    @classmethod
    def estimate_tokens(cls, text_or_data: Any) -> int:
        return CanonicalContextManager.estimate_tokens(text_or_data)

    @classmethod
    def prepare_compact_task_context(
        cls,
        raw_payload: Dict[str, Any],
        max_token_budget: int = 8000,
    ) -> Dict[str, Any]:
        return CanonicalContextManager.prepare_compact_task_context(
            raw_payload,
            max_token_budget=max_token_budget,
        )


__all__ = ["ContextManager"]
