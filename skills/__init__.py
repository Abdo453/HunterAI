"""
Skills Package — lazy exports (PEP 562)
========================================
كل المهارات القابلة للتنفيذ عبر BaseSkill (ترث وتنفّذ execute())

**لماذا lazy؟** الاستيراد الكامن (eager) لكل حزمة مهارة كان يكسر الحزمة
``skills`` بالكامل عند فشل أي مهارة واحدة — لأن ``from skills.base_skill
import BaseSkill`` (المستخدم في core/skill_registry.py وعشرات الملفات)
يُجبر Python على تنفيذ ``skills/__init__.py`` كاملاً.

بـ lazy، importing أي submodule لا يسحب بقية المهارات، فتبقى المكتبة
قابلة للاستخدام حتى لو كانت مهارة معطوبة أو قيد التطوير.
"""
from __future__ import annotations

from importlib import import_module
from typing import Any, Dict

# اسم الرمز -> المسار النسبي للوحدة التي تُصدّره
_LAZY_EXPORTS: Dict[str, str] = {
    "ReasoningLoopSkill": ".agent_core.reasoning_loop",
    "ToolPlannerSkill": ".agent_core.tool_planner",
    "ChainBuilderSkill": ".agent_core.chain_builder",
    "SkillRegistry": ".agent_core.skill_registry",
    "SKILL_REGISTRY": ".agent_core.skill_registry",
    "AutonomousLoopSkill": ".agent_core.autonomous_loop",
    "HuntMemorySkill": ".agent_core.hunt_memory",
    "LLMBrainSkill": ".agent_core.llm_brain",
    "AttackSurfaceRankerSkill": ".analysis.attack_surface_ranker",
    "LogicFlawHunterSkill": ".analysis.logic_flaw_hunter",
    "TakeoverConfirmSkill": ".analysis.takeover_confirm",
    "SecretsHunterSkill": ".analysis.secrets_hunter",
    "CloudReconSkill": ".analysis.cloud_recon",
    "IDORTesterSkill": ".web.idor_tester",
    "SSRFHunterSkill": ".web.ssrf_hunter",
    "SQLiHunterSkill": ".web.sqli_hunter",
    "XSSHunterSkill": ".web.xss_hunter",
    "Bypass403Skill": ".web.bypass_403",
    "ParamDiscoverSkill": ".recon.param_discover",
    "TokenScanSkill": ".web3.token_scan",
    "Web3AuditSkill": ".web3.web3_audit",
}


def __getattr__(name: str) -> Any:
    """PEP 562: تحميل الرمز عند أول استخدام."""
    module_path = _LAZY_EXPORTS.get(name)
    if module_path is None:
        raise AttributeError(f"module 'skills' has no attribute {name!r}")
    module = import_module(module_path, __name__)
    value = getattr(module, name)
    globals()[name] = value          # cache — لا نعيد التحميل
    return value


def __dir__() -> list:
    return sorted(set(globals()) | set(_LAZY_EXPORTS))


__all__ = sorted(_LAZY_EXPORTS)
