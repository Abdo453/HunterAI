"""
HunterAI Sensory Triad Coordinator
==================================
Unifies the 3 Perceptual Sensors into a single Cognitive Ingestion Plane:
1. BrowserSensor: UI, DOM mutation, Form actions, Navigation
2. BurpSensor: HTTP Wire Reality, Lineage, Headers, Payloads, Status
3. CodeSensor: AST, Route decorators, Sinks, Data Models

Cross-Sensor Correlation:
Matches Browser user intent (e.g., 'Clicked Delete User') with Burp wire traffic
(DELETE /api/users/42) and Code definitions to eliminate blind spots.
"""
from __future__ import annotations

import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from core.sensors.burp_sensor import BurpSensor, BurpSessionContext, NormalizedObservation, SensorType

logger = logging.getLogger("hunter_ai.sensory_triad")


@dataclass
class CorrelatedEvent:
    """A cross-sensor event combining UI intent, HTTP wire packet, and Code context"""
    correlation_id: str = field(default_factory=lambda: f"corr_{uuid.uuid4().hex[:8]}")
    browser_action: Optional[str] = None       # e.g., "Click #btn-delete-user"
    http_method: str = "GET"
    http_url: str = ""
    http_status: int = 200
    code_route: Optional[str] = None           # e.g., "@router.delete('/users/{id}')"
    identified_vulnerability_hypothesis: Optional[str] = None
    confidence_score: float = 0.5
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SensoryTriadCoordinator:
    """
    Central Coordinator for Browser + Burp + Code Sensors.
    Bridges sensory input to the AutonomousBrain, Blackboard, and Evidence Graph.
    """

    def __init__(
        self,
        burp_sensor: Optional[BurpSensor] = None,
        browser_session: Optional[Any] = None,
        code_intel: Optional[Any] = None,
        blackboard: Optional[Any] = None,
        evidence_graph: Optional[Any] = None
    ):
        self.burp_sensor = burp_sensor or BurpSensor(blackboard=blackboard, evidence_graph=evidence_graph)
        self.browser_session = browser_session
        self.code_intel = code_intel
        self.blackboard = blackboard
        self.evidence_graph = evidence_graph

        self._correlated_events: List[CorrelatedEvent] = []
        self._pentester_flow = None
        logger.info("[SENSORY_TRIAD] Unified 3-Sensor Triad Initialized")

    @property
    def pentester_flow(self):
        if self._pentester_flow is None:
            from core.sensors.pentester_flow import PentesterFlowEngine
            self._pentester_flow = PentesterFlowEngine(burp_sensor=self.burp_sensor, sensory_triad=self)
        return self._pentester_flow

    def record_browser_action(self, action_description: str, target_selector: str, current_url: str):
        """Records an action taken in the browser (e.g. Playwright click, input)."""
        logger.info(f"[SENSORY_TRIAD] Browser action: {action_description} on {target_selector}")
        self._last_browser_action = {
            "action": action_description,
            "selector": target_selector,
            "url": current_url,
            "timestamp": time.time()
        }
        if self._pentester_flow:
            parts = action_description.split(" ", 1)
            act_type = parts[0].lower() if parts else "click"
            label = parts[1] if len(parts) > 1 else target_selector
            self._pentester_flow.record_browser_action(
                action_type=act_type,
                selector=target_selector,
                page_url=current_url,
                label=label
            )

    def correlate_with_burp(
        self,
        burp_tx: BurpSessionContext,
        browser_action: Optional[str] = None
    ) -> CorrelatedEvent:
        """
        Correlates a Burp HTTP wire transaction with recent browser activity and code context.
        Synthesizes immediate security hypotheses (e.g., BOLA/IDOR when delete action touches other ID).
        """
        action = browser_action or getattr(self, "_last_browser_action", {}).get("action")
        route_match = None
        if self.code_intel and hasattr(self.code_intel, "find_route_handler"):
            try:
                route_match = self.code_intel.find_route_handler(urlparse(burp_tx.url).path, burp_tx.method)
            except Exception:
                pass

        hypothesis = None
        confidence = 0.5

        # Heuristic 1: BOLA / IDOR Correlation
        # If UI action indicates deleting/editing and URL has numeric/UUID path segment
        parsed = urlparse(burp_tx.url)
        path_segments = [s for s in parsed.path.split("/") if s]
        has_resource_id = any(seg.isdigit() or len(seg) > 20 for seg in path_segments)

        if burp_tx.method in ("DELETE", "PUT", "PATCH") and has_resource_id:
            hypothesis = "BOLA_BROKEN_OBJECT_LEVEL_AUTHORIZATION"
            confidence = 0.85
        elif burp_tx.method == "POST" and "admin" in parsed.path.lower() and burp_tx.auth_context != "ADMIN":
            hypothesis = "PRIVILEGE_ESCALATION_UNAUTHORIZED_ADMIN_ACTION"
            confidence = 0.80

        event = CorrelatedEvent(
            browser_action=action,
            http_method=burp_tx.method,
            http_url=burp_tx.url,
            http_status=burp_tx.status_code,
            code_route=route_match,
            identified_vulnerability_hypothesis=hypothesis,
            confidence_score=confidence
        )
        self._correlated_events.append(event)

        # Emit hypothesis to evidence graph if high confidence
        if hypothesis and self.evidence_graph and hasattr(self.evidence_graph, "add_hypothesis"):
            try:
                self.evidence_graph.add_hypothesis(
                    vuln_type=hypothesis,
                    rationale=f"Cross-Sensor Triad correlation: UI ({action}) -> Wire ({burp_tx.method} {burp_tx.url})",
                    target_url=burp_tx.url,
                    source_sensor="SENSORY_TRIAD"
                )
            except Exception as e:
                logger.warning(f"[SENSORY_TRIAD] Failed to push hypothesis to evidence graph: {e}")

        return event

    def get_triad_summary(self) -> Dict[str, Any]:
        """Returns consolidated sensory metrics across Browser, Burp, and Code sensors."""
        return {
            "browser_sensor_online": self.browser_session is not None,
            "code_sensor_online": self.code_intel is not None,
            "burp_sensor_metrics": self.burp_sensor.get_sensor_status(),
            "total_correlated_events": len(self._correlated_events),
            "high_confidence_hypotheses": len([e for e in self._correlated_events if e.confidence_score >= 0.8])
        }
