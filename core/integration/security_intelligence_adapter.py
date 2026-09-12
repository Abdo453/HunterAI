"""
Security Intelligence Adapter
Decoupled Event Adapter connecting BurpAgent, EventBus, and AutonomousBrain to SecurityIntelligence.
Enforces pure event translation, lightweight traffic gating, and loop prevention.
"""
import logging
import time
from typing import Dict, Any, Optional, List, Callable, Set

from agents.burp_agent.pipeline.event_bus import BurpEvent, EventBus
from agents.security_intelligence.brain import SecurityIntelligence
from agents.security_intelligence.schemas import (
    SecurityObservation,
    ObservationType,
    IntelligenceFinding,
    SecurityDecision,
    ScopeRule
)
from agents.security_intelligence.events import SecurityEvent, SecurityEventType

log = logging.getLogger("core.integration.security_intelligence_adapter")


class SecurityIntelligenceAdapter:
    """
    محول الأحداث الأمني: الربط المنفصل بين ترافيك Burp Suite والعقل الأمني وقرارات الـ AutonomousBrain
    """

    def __init__(
        self,
        security_intelligence: Optional[SecurityIntelligence] = None,
        event_bus: Optional[EventBus] = None,
        on_decision_callback: Optional[Callable[[SecurityDecision], Any]] = None,
        on_finding_callback: Optional[Callable[[IntelligenceFinding], Any]] = None,
        max_tracked_requests: int = 5000
    ):
        self.si = security_intelligence or SecurityIntelligence()
        self.bus = event_bus or EventBus()
        self.on_decision_cb = on_decision_callback
        self.on_finding_cb = on_finding_callback

        # Loop protection & deduplication tracking
        self.max_tracked_requests = max_tracked_requests
        self._processed_request_ids: Set[str] = set()
        self._active_operation_ids: Set[str] = set()
        self._action_history_counts: Dict[str, int] = {}
        self.max_action_repeat = 3

        self._wire_event_subscriptions()

    def _wire_event_subscriptions(self):
        """تسجيل الاستماع لأحداث ترافيك Burp Suite وجسر أحداث SecurityEventBus الداخلية"""
        # Outer Burp EventBus subscriptions
        self.bus.subscribe(BurpEvent.TRAFFIC_STORED, self.handle_burp_traffic_stored)
        self.bus.subscribe(BurpEvent.INTERESTING_TRAFFIC, self.handle_burp_interesting_traffic)

        # Bridge internal SecurityEventBus -> Outer EventBus
        if hasattr(self.si, "bus") and hasattr(self.si.bus, "subscribe"):
            self.si.bus.subscribe(SecurityEventType.FINDING_CREATED, self._on_si_internal_finding)
            self.si.bus.subscribe(SecurityEventType.DECISION_CREATED, self._on_si_internal_decision)

    async def _on_si_internal_finding(self, event: SecurityEvent):
        """Bridge internally generated finding to outer Burp EventBus"""
        try:
            await self.bus.publish(BurpEvent.FINDING_CREATED, {
                "finding_id": event.data.get("finding_id"),
                "title": event.data.get("title"),
                "vulnerability_type": event.data.get("type"),
                "confidence": event.confidence,
                "source": "SecurityIntelligence.internal"
            })
        except Exception as e:
            log.debug(f"Failed to bridge internal finding event: {e}")

    async def _on_si_internal_decision(self, event: SecurityEvent):
        """Bridge internally generated decision to outer Burp EventBus"""
        try:
            await self.bus.publish(BurpEvent.DECISION_CREATED, {
                "decision_id": event.data.get("decision_id"),
                "action": event.data.get("action"),
                "priority": event.data.get("priority"),
                "target": event.target,
                "source": "SecurityIntelligence.internal"
            })
        except Exception as e:
            log.debug(f"Failed to bridge internal decision event: {e}")


    async def handle_burp_traffic_stored(self, data: Dict[str, Any]):
        """
        معالجة حدث تخزين الترافيك:
        1. تطبيق فلترة سريعة خفيفة الوزن (Lightweight Triage)
        2. منع الحلقات التكرارية (Loop Protection)
        3. تحويل الترافيك إلى SecurityObservation
        4. استدعاء SecurityIntelligence.analyze_observation()
        5. توليد القرارات والدروس ونشرها للـ AutonomousBrain
        """
        req = data.get("request")
        resp = data.get("response")
        if not req:
            return

        req_id = getattr(req, "id", None) or str(data.get("request_id", ""))
        if req_id and req_id in self._processed_request_ids:
            return  # Prevent duplicate processing

        url = getattr(req, "url", "") or data.get("url", "")
        method = getattr(req, "method", "GET") or data.get("method", "GET")
        headers = getattr(req, "headers", {}) or data.get("headers", {})
        body = getattr(req, "body", "") or data.get("body", "")

        # 1. Lightweight Filter (Reject static assets before invoking cognitive pipelines)
        if not self.si.is_traffic_interesting(url, method, headers, body):
            return

        # Track processed ID
        if req_id:
            if len(self._processed_request_ids) >= self.max_tracked_requests:
                self._processed_request_ids.clear()
            self._processed_request_ids.add(req_id)

        # 2. Translate to SecurityObservation
        status_code = getattr(resp, "status_code", 200) if resp else data.get("status", 200)
        resp_headers = getattr(resp, "headers", {}) if resp else data.get("response_headers", {})
        resp_body = getattr(resp, "body", "") if resp else data.get("response_body", "")

        parameters = getattr(req, "parameters", [])
        if parameters and hasattr(parameters[0], "name"):
            param_names = [p.name for p in parameters]
        elif isinstance(parameters, list):
            param_names = [str(p) for p in parameters]
        elif isinstance(parameters, dict):
            param_names = list(parameters.keys())
        else:
            param_names = []

        target_host = getattr(req, "host", "") or url.split("/")[2] if "://" in url else "unknown"

        observation = SecurityObservation(
            project_id="pentest_unified",
            target=target_host,
            source="burp_agent.adapter",
            obs_type=ObservationType.HTTP_REQUEST,
            data={
                "path": getattr(req, "path", url),
                "url": url,
                "method": method,
                "parameters": param_names,
                "headers": headers,
                "status": status_code,
                "response_headers": resp_headers,
                "response_body": resp_body[:2000] if resp_body else "",
                "behavior_difference": data.get("behavior_difference")
            }
        )

        # 3. Call SecurityIntelligence Core
        findings = await self.si.analyze_observation(observation)

        # 4. For each finding, formulate decision and notify
        for f in findings:
            decision = await self.si.decide(f)
            
            # Action Loop Protection
            action_key = f"{decision.target}:{decision.recommended_action}"
            current_count = self._action_history_counts.get(action_key, 0)
            if current_count >= self.max_action_repeat:
                log.warning(f"[LoopProtection] Repeated action '{action_key}' hit limit ({current_count}). Halting cyclic cascade.")
                continue
            self._action_history_counts[action_key] = current_count + 1

            # Notify finding callback
            if self.on_finding_cb:

                try:
                    await self.on_finding_cb(f)
                except Exception as e:
                    log.warning(f"Error in on_finding_cb: {e}")

            # Notify decision callback
            if self.on_decision_cb:
                try:
                    await self.on_decision_cb(decision)
                except Exception as e:
                    log.warning(f"Error in on_decision_cb: {e}")

            # Publish back onto EventBus
            await self.bus.publish(BurpEvent.FINDING_CREATED, {
                "finding_id": f.id,
                "title": f.title,
                "vulnerability_type": f.vulnerability_type,
                "confidence": f.confidence_score,
                "decision": decision.model_dump()
            })

    async def handle_burp_interesting_traffic(self, data: Dict[str, Any]):
        """معالجة الترافيك الموسوم كمثير للاهتمام بشكل خاص"""
        await self.handle_burp_traffic_stored(data)
