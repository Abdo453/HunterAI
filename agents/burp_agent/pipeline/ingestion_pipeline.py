"""
Level 1 Ingestion Pipeline: Ingests, Parses, and Stores ALL traffic unconditionally into SQLite.
"""
import logging
from typing import Dict, Any, Optional
from agents.burp_agent.core.parser import HTTPParser
from agents.burp_agent.pipeline.event_bus import BurpEvent, EventBus
from agents.burp_agent.storage.database import TrafficDatabase
from agents.burp_agent.storage.cache import TrafficCache
from agents.burp_agent.scope.scope_manager import ScopeManager

log = logging.getLogger("burp_agent.ingestion")


class IngestionPipeline:
    """خط أنابيب استقبال وحفظ الترافيك الأولي (Level 1)"""

    def __init__(self, db: TrafficDatabase, cache: TrafficCache, scope: ScopeManager, bus: EventBus):
        self.db = db
        self.cache = cache
        self.scope = scope
        self.bus = bus

    async def process_raw_traffic(self, payload: Dict[str, Any]):
        """معالجة حزمة الترافيك الخام القادمة من Burp Suite"""
        try:
            raw_req = payload.get("request", "")
            raw_resp = payload.get("response", "")
            host = payload.get("host", "")
            port = int(payload.get("port", 80))
            protocol = payload.get("protocol", "http")
            duration_ms = float(payload.get("duration_ms", 0.0))

            if not raw_req:
                return

            # 1. Parse Request
            req_model = HTTPParser.parse_raw_request(
                raw_http=raw_req,
                host=host,
                port=port,
                protocol=protocol
            )

            # 2. Check Scope
            if not self.scope.is_in_scope(req_model.url):
                return

            # 3. Deduplication Check
            if self.cache.is_duplicate_request(req_model.method, req_model.url, req_model.body):
                log.debug(f"[Ingestion] Deduplicated: {req_model.method} {req_model.url}")

            # 4. Parse Response (if available)
            resp_model = None
            if raw_resp:
                resp_model = HTTPParser.parse_raw_response(
                    raw_http=raw_resp,
                    request_id=req_model.id,
                    response_time_ms=duration_ms
                )

            # 5. Always Persist to Database (Guaranteed Storage)
            self.db.insert_request(req_model)
            if req_model.parameters:
                self.db.insert_parameters(req_model.parameters)
            if resp_model:
                self.db.insert_response(resp_model)

            log.info(f"[Ingestion] Stored {req_model.method} {req_model.url} (Status: {resp_model.status_code if resp_model else 'pending'})")

            # 6. Publish Event for Level 2 Passive Triage
            await self.bus.publish(BurpEvent.TRAFFIC_STORED, {
                "request": req_model,
                "response": resp_model
            })

        except Exception as e:
            log.error(f"[Ingestion] Failed to process traffic: {e}", exc_info=True)
