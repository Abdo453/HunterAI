"""
Browser Intelligence & Stateful Exploration Subsystem
=====================================================
Unified browser exploration framework featuring:
- Stateful continuous session across entire engagement
- Real-time BrowserEventBus for sensor integration
- Information-Gain InteractionPlanner and ActionDiscovery
- ApplicationStateGraph with loop detection
- Forensic ExplorationMemory and DOMDiffEngine
- Multi-dimensional CoverageEngine with CLI formatting
- 3-Sensor BrowserBrainLoop coordinator
"""
from core.browser.playwright_engine import PlaywrightEngine, BrowserInspectionResult
from core.browser.dom_diff import DOMDiffEngine, DOMDiffResult
from core.browser.state_graph import ApplicationStateGraph, AppState, StateTransition
from core.browser.action_discovery import ActionDiscovery, ActionCategory, ActionCandidate, RequestDeduplicator
from core.browser.session import StatefulBrowserSession, InterceptedRequest
from core.browser.explorer import HumanLikeExplorationEngine, StopReason, ExplorationManifest, ExplorationLessons
from core.browser.browser_event_bus import BrowserEventBus, BrowserEvent, BrowserEventType
from core.browser.exploration_memory import ExplorationMemory, ActionRecord
from core.browser.coverage_engine import CoverageEngine, ExplorationCoverageMetrics
from core.browser.state_detector import StateDetector, SemanticAppState
from core.browser.dom_analyzer import DOMAnalyzer, ExtractedForm, FormField
from core.browser.network_observer import NetworkObserver, ObservedTrafficItem
from core.browser.interaction_planner import InteractionPlanner
from core.browser.exploration_queue import ExplorationQueue, FrontierItem
from core.browser.navigator import BrowserNavigator
from core.browser.action_engine import ActionEngine
from core.browser.browser_brain_loop import BrowserBrainLoop, SensorObservationReport

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
    "InterceptedRequest",
    "HumanLikeExplorationEngine",
    "StopReason",
    "ExplorationManifest",
    "ExplorationLessons",
    "BrowserEventBus",
    "BrowserEvent",
    "BrowserEventType",
    "ExplorationMemory",
    "ActionRecord",
    "CoverageEngine",
    "ExplorationCoverageMetrics",
    "StateDetector",
    "SemanticAppState",
    "DOMAnalyzer",
    "ExtractedForm",
    "FormField",
    "NetworkObserver",
    "ObservedTrafficItem",
    "InteractionPlanner",
    "ExplorationQueue",
    "FrontierItem",
    "BrowserNavigator",
    "ActionEngine",
    "BrowserBrainLoop",
    "SensorObservationReport",
]
