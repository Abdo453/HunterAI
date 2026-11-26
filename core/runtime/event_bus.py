"""Persistent monotonic event bus with Last-Event-ID replay and live async fan-out.

Backed by ``PlatformStore.events`` (SQLite WAL monotonic ``seq`` and per-run
``run_seq``) while maintaining an in-memory ring buffer and per-subscriber
``asyncio.Queue`` fan-out across threads and event loops.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from collections import deque
from typing import Any, Callable, Deque, Dict, List, Optional

from core.platform_store import PlatformStore, get_platform_store, redact_payload

logger = logging.getLogger("hunter_ai.runtime.event_bus")


def parse_last_event_id(raw: Optional[str | int]) -> Optional[int]:
    """Parse an SSE ``Last-Event-ID`` header or ``since_seq`` query value cleanly."""
    if raw is None:
        return None
    if isinstance(raw, int):
        return max(0, raw)
    text = str(raw).strip()
    if not text:
        return None
    if text.startswith("seq_"):
        text = text[4:]
    if text.lstrip("-").isdigit():
        return max(0, int(text))
    return None


class PersistentEventBus:
    """Monotonic persistent event bus with Last-Event-ID replay and live pub/sub."""

    def __init__(
        self,
        store_provider: Optional[Callable[[], PlatformStore]] = None,
        *,
        history_size: int = 500,
    ) -> None:
        self._store_provider = store_provider or get_platform_store
        self._history: Deque[Dict[str, Any]] = deque(maxlen=history_size)
        self._subscribers: set[asyncio.Queue[Dict[str, Any]]] = set()
        self._lock = threading.Lock()
        self._mem_seq = 0

    def _get_store(self) -> PlatformStore:
        return self._store_provider()

    def push_local(self, event: Dict[str, Any]) -> None:
        """Broadcast an already-persisted or synthetic event dict to subscribers."""
        if not isinstance(event, dict):
            return
        with self._lock:
            self._history.append(event)
            subs = list(self._subscribers)
        for q in subs:
            self._deliver_to_queue(q, event)

    @staticmethod
    def _deliver_to_queue(q: asyncio.Queue[Dict[str, Any]], event: Dict[str, Any]) -> None:
        loop = getattr(q, "_loop", None)
        if loop is not None and not loop.is_closed():
            try:
                running = asyncio.get_running_loop()
            except RuntimeError:
                running = None
            if running is loop:
                try:
                    q.put_nowait(event)
                except asyncio.QueueFull:
                    logger.debug("Subscriber queue full; dropping live fan-out seq=%s", event.get("seq"))
                return
            try:
                loop.call_soon_threadsafe(PersistentEventBus._put_ignore_full, q, event)
                return
            except RuntimeError as exc:
                logger.debug("Subscriber loop unavailable during fan-out: %s", exc)
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            logger.debug("Subscriber queue full (fallback); dropping seq=%s", event.get("seq"))
        except RuntimeError as exc:
            logger.debug("Fallback queue delivery skipped: %s", exc)

    @staticmethod
    def _put_ignore_full(q: asyncio.Queue[Dict[str, Any]], event: Dict[str, Any]) -> None:
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            logger.debug("Subscriber queue full (threadsafe); dropping seq=%s", event.get("seq"))

    def publish_sync(
        self,
        event_type: str,
        payload: Optional[Dict[str, Any]] = None,
        *,
        run_id: Optional[str] = None,
        engagement_id: Optional[str] = None,
        task_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        tool_exec_id: Optional[str] = None,
        source: str = "platform",
        persist: bool = True,
    ) -> Dict[str, Any]:
        """Synchronously persist an event (assigning monotonic ``seq`` and ``run_seq``) and fan out."""
        safe_payload = redact_payload(payload or {})
        if persist:
            store = self._get_store()
            event = store.append_event(
                event_type,
                run_id=run_id,
                engagement_id=engagement_id,
                task_id=task_id,
                agent_id=agent_id,
                tool_exec_id=tool_exec_id,
                source=source,
                payload=safe_payload,
            )
            # If the store did not already invoke our listener, ensure local ring has it.
            with self._lock:
                already = bool(self._history and self._history[-1].get("seq") == event.get("seq"))
            if not already:
                self.push_local(event)
            return event

        with self._lock:
            self._mem_seq += 1
            seq = self._mem_seq
        event = {
            "seq": seq,
            "run_seq": 0,
            "created_at": time.time(),
            "ts": time.time(),
            "event_type": event_type,
            "type": event_type,
            "run_id": run_id,
            "engagement_id": engagement_id,
            "task_id": task_id,
            "agent_id": agent_id,
            "tool_exec_id": tool_exec_id,
            "source": source,
            "payload": safe_payload,
        }
        self.push_local(event)
        return event

    async def publish(
        self,
        event_type: str,
        payload: Optional[Dict[str, Any]] = None,
        *,
        run_id: Optional[str] = None,
        engagement_id: Optional[str] = None,
        task_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        tool_exec_id: Optional[str] = None,
        source: str = "platform",
        persist: bool = True,
    ) -> Dict[str, Any]:
        """Async offload of event persistence + live subscriber fan-out."""
        return await asyncio.to_thread(
            self.publish_sync,
            event_type,
            payload,
            run_id=run_id,
            engagement_id=engagement_id,
            task_id=task_id,
            agent_id=agent_id,
            tool_exec_id=tool_exec_id,
            source=source,
            persist=persist,
        )

    def publish_threadsafe(
        self,
        event_type: str,
        payload: Optional[Dict[str, Any]] = None,
        *,
        run_id: Optional[str] = None,
        engagement_id: Optional[str] = None,
        task_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        source: str = "platform",
        persist: bool = True,
    ) -> Dict[str, Any]:
        """Thread-safe sync emitter compatible with ``PlatformEventBus.publish_threadsafe``."""
        try:
            return self.publish_sync(
                event_type,
                payload,
                run_id=run_id,
                engagement_id=engagement_id,
                task_id=task_id,
                agent_id=agent_id,
                source=source,
                persist=persist,
            )
        except Exception as exc:
            logger.warning("Persistent publish failed for %s (%s); falling back to local ring", event_type, exc)
            return self.publish_sync(
                event_type,
                payload,
                run_id=run_id,
                engagement_id=engagement_id,
                task_id=task_id,
                agent_id=agent_id,
                source=source,
                persist=False,
            )

    def subscribe(self, maxsize: int = 512) -> asyncio.Queue[Dict[str, Any]]:
        """Register and return a subscriber queue bound to the active event loop."""
        q: asyncio.Queue[Dict[str, Any]] = asyncio.Queue(maxsize=maxsize)
        with self._lock:
            self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[Dict[str, Any]]) -> None:
        with self._lock:
            self._subscribers.discard(q)

    def backlog_since(
        self,
        since_seq: Optional[int | str],
        *,
        run_id: Optional[str] = None,
        since_run_seq: Optional[int] = None,
        engagement_id: Optional[str] = None,
        limit: int = 200,
    ) -> List[Dict[str, Any]]:
        """Replay historical events strictly after *since_seq* (supporting Last-Event-ID)."""
        parsed = parse_last_event_id(since_seq)
        seq_floor = 0 if parsed is None else parsed
        try:
            store = self._get_store()
            rows = store.list_events(
                since_seq=seq_floor,
                run_id=run_id,
                since_run_seq=since_run_seq,
                engagement_id=engagement_id,
                limit=limit,
            )
            if rows:
                return rows
        except Exception as exc:
            logger.warning("Failed reading persistent event backlog: %s", exc)

        with self._lock:
            items = list(self._history)
        filtered = [
            ev
            for ev in items
            if int(ev.get("seq") or 0) > seq_floor
            and (not run_id or ev.get("run_id") == run_id)
            and (since_run_seq is None or int(ev.get("run_seq") or 0) > since_run_seq)
            and (not engagement_id or ev.get("engagement_id") == engagement_id)
        ]
        return filtered[:limit]

    async def abacklog_since(
        self,
        since_seq: Optional[int | str],
        *,
        run_id: Optional[str] = None,
        since_run_seq: Optional[int] = None,
        engagement_id: Optional[str] = None,
        limit: int = 200,
    ) -> List[Dict[str, Any]]:
        """Async offload of ``backlog_since`` for SSE/WS views."""
        return await asyncio.to_thread(
            self.backlog_since,
            since_seq,
            run_id=run_id,
            since_run_seq=since_run_seq,
            engagement_id=engagement_id,
            limit=limit,
        )
