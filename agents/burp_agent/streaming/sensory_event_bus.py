"""
Sensory Event Bus for BurpAgent Architecture
Decoupled asynchronous Pub/Sub event bus broadcasting granular sensory observations:
- HTTP_REQUEST_OBSERVED
- HTTP_RESPONSE_OBSERVED
- FILE_OBSERVED
- TOKEN_OBSERVED
- RESPONSE_DIFF_AVAILABLE
"""
import asyncio
import logging
from enum import Enum
from typing import Dict, List, Callable, Any, Awaitable, Optional
from pydantic import BaseModel, Field

log = logging.getLogger("burp_agent.streaming.event_bus")


class SensoryEvent(str, Enum):
    HTTP_REQUEST_OBSERVED = "HTTP_REQUEST_OBSERVED"
    HTTP_RESPONSE_OBSERVED = "HTTP_RESPONSE_OBSERVED"
    FILE_OBSERVED = "FILE_OBSERVED"
    TOKEN_OBSERVED = "TOKEN_OBSERVED"
    COOKIE_OBSERVED = "COOKIE_OBSERVED"
    ENDPOINT_DISCOVERED = "ENDPOINT_DISCOVERED"
    PARAMETER_DISCOVERED = "PARAMETER_DISCOVERED"
    RESPONSE_DIFF_AVAILABLE = "RESPONSE_DIFF_AVAILABLE"


class SensoryMessage(BaseModel):
    event: SensoryEvent
    transaction_id: str
    timestamp: float
    summary: str
    data: Dict[str, Any] = Field(default_factory=dict)


class SensoryEventBus:
    """
    ناقل الأحداث الحسي غير المتزامن لربط مستشعرات Burp بالـ Reasoning Core والـ Specialists
    """

    def __init__(self):
        self._subscribers: Dict[SensoryEvent, List[Callable[[SensoryMessage], Awaitable[None]]]] = {
            ev: [] for ev in SensoryEvent
        }
        self._history: List[SensoryMessage] = []

    def subscribe(self, event: SensoryEvent, handler: Callable[[SensoryMessage], Awaitable[None]]):
        self._subscribers[event].append(handler)

    async def publish(self, event: SensoryEvent, message: SensoryMessage):
        self._history.append(message)
        if len(self._history) > 200:
            self._history.pop(0)

        handlers = self._subscribers.get(event, [])
        if not handlers:
            return

        tasks = [self._safe_invoke(h, message) for h in handlers]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _safe_invoke(self, handler: Callable[[SensoryMessage], Awaitable[None]], message: SensoryMessage):
        try:
            await handler(message)
        except Exception as e:
            log.error(f"[SensoryEventBus] Handler {handler.__name__} raised error: {e}", exc_info=True)

    def get_recent_events(self, limit: int = 50) -> List[SensoryMessage]:
        return self._history[-limit:]
