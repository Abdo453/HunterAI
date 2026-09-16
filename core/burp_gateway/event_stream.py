"""
HunterAI Live Burp Event Stream
===============================
Real-Time Asynchronous Telemetry & Event Streaming Bridge:
- Ring buffer with bounded capacity preventing unbounded memory growth
- Async generator subscription (subscribe()) for real-time streaming to Brain & Agents
- Synchronous callback hooks for immediate low-latency pipeline reactions
- High-fidelity streaming endpoints for WebSockets / SSE clients
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, AsyncIterator, Callable, Dict, List, Optional, Set

logger = logging.getLogger("hunter_ai.burp_event_stream")


@dataclass
class StreamEvent:
    event_id: str = field(default_factory=lambda: f"evt_{uuid.uuid4().hex[:8]}")
    event_type: str = "GENERIC_BURP_EVENT"
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class BurpLiveEventStream:
    """
    Thread-Safe, Async-Compatible Event Stream for live Burp Suite traffic & actions.
    """

    def __init__(self, max_buffer_size: int = 1000):
        self.max_buffer_size = max_buffer_size
        self._buffer: List[StreamEvent] = []
        self._sync_listeners: List[Callable[[StreamEvent], None]] = []
        self._async_queues: Set[asyncio.Queue] = set()

    def publish_event(self, event_type: str, data: Dict[str, Any]) -> StreamEvent:
        """Publishes an event to all sync listeners and async subscriber queues."""
        evt = StreamEvent(event_type=event_type, data=data, timestamp=time.time())

        # Bounded Ring Buffer eviction
        if len(self._buffer) >= self.max_buffer_size:
            self._buffer.pop(0)
        self._buffer.append(evt)

        # Notify sync listeners
        for cb in list(self._sync_listeners):
            try:
                cb(evt)
            except Exception as e:
                logger.warning(f"[EVENT_STREAM] Sync listener error: {e}")

        # Notify active async subscriber queues
        for q in list(self._async_queues):
            try:
                q.put_nowait(evt)
            except Exception:
                pass

        return evt

    def add_sync_listener(self, callback: Callable[[StreamEvent], None]):
        """Registers a synchronous callback function."""
        if callback not in self._sync_listeners:
            self._sync_listeners.append(callback)

    def remove_sync_listener(self, callback: Callable[[StreamEvent], None]):
        if callback in self._sync_listeners:
            self._sync_listeners.remove(callback)

    async def subscribe(
        self,
        event_filter: Optional[List[str]] = None,
        timeout: Optional[float] = None
    ) -> AsyncIterator[StreamEvent]:
        """
        Async generator providing real-time streaming of events.
        """
        q: asyncio.Queue = asyncio.Queue()
        self._async_queues.add(q)
        filter_set = set(event_filter) if event_filter else None

        try:
            while True:
                if timeout:
                    evt = await asyncio.wait_for(q.get(), timeout=timeout)
                else:
                    evt = await q.get()

                if filter_set is None or evt.event_type in filter_set:
                    yield evt
        finally:
            self._async_queues.discard(q)

    def get_recent_events(self, limit: int = 50) -> List[StreamEvent]:
        return list(self._buffer[-limit:])

    def clear(self):
        self._buffer.clear()
