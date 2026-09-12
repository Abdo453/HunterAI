"""
Browser Event Bus
=================
Real-time publish/subscribe event infrastructure for the stateful browser sensor.
Enables the Autonomous Brain, Attack Surface Graph, and Code Intelligence Pipeline
to observe DOM changes, network activity, and authentication state in real time.
"""
from __future__ import annotations

import asyncio
import inspect
import logging
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger("hunter_ai.browser_event_bus")


class BrowserEventType(str, Enum):
    PAGE_LOADED = "PAGE_LOADED"
    LINK_DISCOVERED = "LINK_DISCOVERED"
    FORM_DISCOVERED = "FORM_DISCOVERED"
    BUTTON_DISCOVERED = "BUTTON_DISCOVERED"
    XHR_DISCOVERED = "XHR_DISCOVERED"
    FETCH_DISCOVERED = "FETCH_DISCOVERED"
    DOM_CHANGED = "DOM_CHANGED"
    COOKIE_CHANGED = "COOKIE_CHANGED"
    STORAGE_CHANGED = "STORAGE_CHANGED"
    REDIRECT = "REDIRECT"
    AUTH_STATE_CHANGED = "AUTH_STATE_CHANGED"
    NEW_JS = "NEW_JS"
    NEW_ENDPOINT = "NEW_ENDPOINT"
    EXPLORATION_STEP = "EXPLORATION_STEP"


@dataclass
class BrowserEvent:
    event_type: BrowserEventType
    source_url: str
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=lambda: time.time())

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["event_type"] = self.event_type.value
        return d


class BrowserEventBus:
    """Async event bus for routing browser sensor events to brain subscribers"""

    def __init__(self):
        self._subscribers: Dict[BrowserEventType, List[Callable]] = {t: [] for t in BrowserEventType}
        self._global_subscribers: List[Callable] = []
        self._history: List[BrowserEvent] = []
        self._max_history: int = 1000

    def subscribe(self, event_type: BrowserEventType, handler: Callable) -> None:
        """Subscribe a callable to a specific event type"""
        if handler not in self._subscribers[event_type]:
            self._subscribers[event_type].append(handler)

    def subscribe_all(self, handler: Callable) -> None:
        """Subscribe a callable to all browser events"""
        if handler not in self._global_subscribers:
            self._global_subscribers.append(handler)

    def unsubscribe(self, handler: Callable, event_type: Optional[BrowserEventType] = None) -> None:
        """Remove a subscriber"""
        if event_type:
            if handler in self._subscribers[event_type]:
                self._subscribers[event_type].remove(handler)
        else:
            if handler in self._global_subscribers:
                self._global_subscribers.remove(handler)
            for subscribers in self._subscribers.values():
                if handler in subscribers:
                    subscribers.remove(handler)

    async def publish(self, event: BrowserEvent) -> None:
        """Publish an event asynchronously to all registered subscribers"""
        self._record_event(event)

        targets = list(self._subscribers.get(event.event_type, [])) + list(self._global_subscribers)
        for handler in targets:
            try:
                if inspect.iscoroutinefunction(handler):
                    await handler(event)
                else:
                    res = handler(event)
                    if asyncio.iscoroutine(res):
                        await res
            except Exception as e:
                logger.debug(f"Error executing event handler {handler} for {event.event_type}: {e}")

    def publish_sync(self, event: BrowserEvent) -> None:
        """Publish an event synchronously (or fire-and-forget async handlers)"""
        self._record_event(event)

        targets = list(self._subscribers.get(event.event_type, [])) + list(self._global_subscribers)
        for handler in targets:
            try:
                if inspect.iscoroutinefunction(handler):
                    try:
                        loop = asyncio.get_running_loop()
                        loop.create_task(handler(event))
                    except RuntimeError:
                        pass
                else:
                    handler(event)
            except Exception as e:
                logger.debug(f"Error in sync publish handler {handler}: {e}")

    def _record_event(self, event: BrowserEvent) -> None:
        self._history.append(event)
        if len(self._history) > self._max_history:
            self._history.pop(0)

    def get_history(self, event_type: Optional[BrowserEventType] = None, limit: int = 100) -> List[BrowserEvent]:
        """Retrieve recent event history, optionally filtered by type"""
        if event_type is None:
            return self._history[-limit:]
        return [e for e in self._history if e.event_type == event_type][-limit:]

    def count_events(self, event_type: BrowserEventType) -> int:
        """Count how many events of a given type have occurred"""
        return sum(1 for e in self._history if e.event_type == event_type)

    def clear(self) -> None:
        """Clear history and all subscribers"""
        self._history.clear()
        for subscribers in self._subscribers.values():
            subscribers.clear()
        self._global_subscribers.clear()
