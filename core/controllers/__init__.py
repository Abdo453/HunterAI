"""
HunterAI Controllers Package
============================
Provides control planes connecting Cognitive Brain to external execution backends.
"""
from core.controllers.burp_controller import BurpController, RepeaterExperiment
from core.controllers.burp_research_controller import (
    BurpResearchController,
    ControlActionReceipt,
    ExecutionResult,
    DifferentialAnalysis,
    ScopeViolationError,
    ActionStatus,
)

__all__ = [
    "BurpController",
    "RepeaterExperiment",
    "BurpResearchController",
    "ControlActionReceipt",
    "ExecutionResult",
    "DifferentialAnalysis",
    "ScopeViolationError",
    "ActionStatus",
]
