"""
Level 2 Analysis Pipeline: Performs fast passive heuristic triage, endpoint mapping, auth audit, and parameter classification.
"""
import logging
from typing import Dict, Any, List
from agents.burp_agent.storage.models import HTTPRequestModel, HTTPResponseModel, TriagePriority
from agents.burp_agent.pipeline.event_bus import BurpEvent, EventBus
from agents.burp_agent.storage.database import TrafficDatabase
from agents.burp_agent.core.normalizer import URLNormalizer

log = logging.getLogger("burp_agent.analysis_pipeline")


class AnalysisPipeline:
    """خط أنابيب الفرز السلبي الأولي بدون استدعاء الذكاء الاصطناعي (Level 2)"""

    HIGH_RISK_KEYWORDS = [
        "admin", "api", "auth", "token", "jwt", "user", "role", "upload",
        "payment", "secret", "password", "graphql", "id", "redirect", "file", "cmd"
    ]

    def __init__(self, db: TrafficDatabase, bus: EventBus, analyzers: List[Any]):
        self.db = db
        self.bus = bus
        self.analyzers = analyzers

    async def on_traffic_stored(self, data: Dict[str, Any]):
        """تنفيذ الفحص والفرز السلبي فور حفظ الترافيك"""
        req: HTTPRequestModel = data["request"]
        resp: HTTPResponseModel = data.get("response")

        priority = TriagePriority.NORMAL
        reasons = []

        # 1. Heuristic Keywords in Path & Query
        p_low = req.path.lower()
        for kw in self.HIGH_RISK_KEYWORDS:
            if kw in p_low:
                priority = TriagePriority.INTERESTING
                reasons.append(f"Keyword in path: {kw}")

        # 2. Check Parameters (IDOR / Role / Sensitive)
        for p in req.parameters:
            if p.is_user_controlled_id:
                priority = TriagePriority.HIGH
                reasons.append(f"User identifier param: {p.name}={p.value}")
            elif p.is_role_indicator:
                priority = TriagePriority.HIGH
                reasons.append(f"Role/privilege param: {p.name}={p.value}")

        # 3. HTTP Methods with State Changes
        if req.method in ("POST", "PUT", "DELETE", "PATCH"):
            if priority == TriagePriority.NORMAL:
                priority = TriagePriority.INTERESTING
                reasons.append(f"State-modifying HTTP method: {req.method}")

        # 4. Status Codes of Interest
        if resp:
            if resp.status_code in (401, 403):
                reasons.append(f"Auth barrier encountered: {resp.status_code}")
                priority = max(priority, TriagePriority.INTERESTING, key=lambda x: x.value)
            elif resp.status_code >= 500:
                reasons.append(f"Server error 5xx: {resp.status_code}")
                priority = TriagePriority.HIGH

        # 5. Run Passive Analyzers (Endpoints, Auth, Files, Vulns)
        for analyzer in self.analyzers:
            try:
                await analyzer.analyze(req, resp)
            except Exception as e:
                log.error(f"[AnalysisPipeline] Analyzer {analyzer.__class__.__name__} error: {e}")

        req.triage_priority = priority
        req.triage_reasons = reasons

        # 6. If Interesting or High Priority -> Queue for Level 3 AI Reasoning
        if priority in (TriagePriority.INTERESTING, TriagePriority.HIGH, TriagePriority.CRITICAL):
            log.info(f"[Triage] Flagged {priority.value}: {req.method} {req.path} -> {', '.join(reasons)}")
            await self.bus.publish(BurpEvent.INTERESTING_TRAFFIC, {
                "request": req,
                "response": resp,
                "priority": priority,
                "reasons": reasons
            })
