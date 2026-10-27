"""
Agent-core skills — lazy exports (PEP 562)
==========================================
"""
from __future__ import annotations

from importlib import import_module
from typing import Any, Dict

_LAZY_EXPORTS: Dict[str, str] = {
    "ReasoningLoopSkill": ".reasoning_loop",
    "ToolPlannerSkill": ".tool_planner",
    "ChainBuilderSkill": ".chain_builder",
    "SkillRegistry": ".skill_registry",
    "SKILL_REGISTRY": ".skill_registry",
    "AutonomousLoopSkill": ".autonomous_loop",
    "HuntMemorySkill": ".hunt_memory",
    "LLMBrainSkill": ".llm_brain",
}


def __getattr__(name: str) -> Any:
    module_path = _LAZY_EXPORTS.get(name)
    if module_path is None:
        raise AttributeError(f"module 'skills.agent_core' has no attribute {name!r}")
    module = import_module(module_path, __name__)
    value = getattr(module, name)
    globals()[name] = value
    return value


def __dir__() -> list:
    return sorted(set(globals()) | set(_LAZY_EXPORTS))


__all__ = sorted(_LAZY_EXPORTS)
