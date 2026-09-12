"""
Browser Intelligence & Stateful Exploration Subsystem
"""
from core.browser.playwright_engine import PlaywrightEngine, BrowserInspectionResult
from core.browser.dom_diff import DOMDiffEngine, DOMDiffResult
from core.browser.state_graph import ApplicationStateGraph, AppState, StateTransition
from core.browser.action_discovery import ActionDiscovery, ActionCategory, ActionCandidate, RequestDeduplicator
from core.browser.session import StatefulBrowserSession
from core.browser.explorer import HumanLikeExplorationEngine, StopReason, ExplorationManifest, ExplorationLessons

__all__ = [
    "PlaywrightEngine",
    "BrowserInspectionResult",
    "DOMDiffEngine",
    "DOMDiffResult",
    "ApplicationStateGraph",
    "AppState",
    "StateTransition",
    "ActionDiscovery",
    "ActionCategory",
    "ActionCandidate",
    "RequestDeduplicator",
    "StatefulBrowserSession",
    "HumanLikeExplorationEngine",
    "StopReason",
    "ExplorationManifest",
    "ExplorationLessons",
]
