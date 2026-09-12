"""
Asynchronous Event Bus for BurpAgent Architecture
Decouples Ingestion -> Storage -> Passive Triage -> AI Reasoning -> Attack Graph.
"""
import asyncio
import logging
from enum import Enum
from typing import Dict, List, Callable, Any, Awaitable

log = logging.getLogger("burp_agent.event_bus")


class BurpEvent(str, Enum):
    TRAFFIC_RECEIVED = "TRAFFIC_RECEIVED"
    REQUEST_PARSED = "REQUEST_PARSED"
    TRAFFIC_STORED = "TRAFFIC_STORED"
    PASSIVE_ANALYSIS_DONE = "PASSIVE_ANALYSIS_DONE"
    INTERESTING_TRAFFIC = "INTERESTING_TRAFFIC"
    AI_ANALYSIS_DONE = "AI_ANALYSIS_DONE"
    FINDING_CREATED = "FINDING_CREATED"
    DECISION_CREATED = "DECISION_CREATED"
    GRAPH_UPDATED = "GRAPH_UPDATED"
    WEBSOCKET_FRAME_RECEIVED = "WEBSOCKET_FRAME_RECEIVED"


class EventBus:
    """ناقل الأحداث غير المتزامن لضمان عدم تعطل استقبال الترافيك عند انشغال الـ AI"""

    def __init__(self):
        self._subscribers: Dict[BurpEvent, List[Callable[[Any], Awaitable[None]]]] = {
            ev: [] for ev in BurpEvent
        }

    def subscribe(self, event: BurpEvent, handler: Callable[[Any], Awaitable[None]]):
        """تسجيل معالج لحدث معين"""
        self._subscribers[event].append(handler)

    async def publish(self, event: BurpEvent, data: Any):
        """إرسال حدث لجميع المشتركين بالتوازي دون حجب"""
        handlers = self._subscribers.get(event, [])
        if not handlers:
            return

        tasks = []
        for h in handlers:
            tasks.append(self._safe_invoke(h, data))
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _safe_invoke(self, handler: Callable[[Any], Awaitable[None]], data: Any):
        try:
            await handler(data)
        except Exception as e:
            log.error(f"[EventBus] Error in subscriber {handler.__name__}: {e}", exc_info=True)
