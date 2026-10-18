"""
core.readiness — Unified Readiness (Phase 1)
============================================
مصدر حقيقة واحد لجاهزية البيئة قبل بدء أي مهمة:
  python -m core.readiness --strict
أو برمجيًا:
    from core.readiness import ReadinessChecker, enforce_strict, save_readiness_artifact
"""
from core.readiness.checker import (
    ComponentStatus,
    ComponentResult,
    ReadinessChecker,
    ReadinessGateError,
    ReadinessReport,
    enforce_strict,
)
from core.readiness.artifact import (
    ARTIFACT_NAME,
    load_readiness_artifact,
    save_readiness_artifact,
)
from core.readiness.gate import (
    DEFAULT_COMPONENTS,
    mission_gate_config,
    run_mission_gate,
)

__all__ = [
    "ComponentStatus",
    "ComponentResult",
    "ReadinessChecker",
    "ReadinessGateError",
    "ReadinessReport",
    "ARTIFACT_NAME",
    "DEFAULT_COMPONENTS",
    "enforce_strict",
    "mission_gate_config",
    "run_mission_gate",
    "save_readiness_artifact",
    "load_readiness_artifact",
]
