"""
HunterAI WebSocket Telemetry — بث لحظي لحالة المسح والنتائج
مقتبس من فكرة Xalgorix live WebSocket telemetry
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime

try:
    from fastapi import WebSocket, WebSocketDisconnect
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

log = logging.getLogger("hunter_ai.telemetry")


@dataclass
class TelemetryEvent:
    """حدث تبثّي للإرسال عبر WebSocket"""
    event_type: str  # scan_started, scan_completed, finding_discovered, phase_changed, error
    data: dict
    timestamp: float = 0.0

    def __post_init__(self):
        if self.timestamp == 0.0:
            import time
            self.timestamp = time.time()

    def to_json(self) -> str:
        return json.dumps({
            "event_type": self.event_type,
            "data": self.data,
            "timestamp": self.timestamp,
        }, ensure_ascii=False)


class TelemetryManager:
    """
    مدير البث اللحظي — يدير اتصالات WebSocket ويرسل الأحداث للعملاء المتصلين
    """

    def __init__(self):
        self.connections: List[Any] = []  # WebSocket connections
        self.event_history: List[TelemetryEvent] = []
        self.max_history = 500
        self._lock = asyncio.Lock() if hasattr(asyncio, 'Lock') else None

    async def connect(self, websocket: Any):
        """إضافة عميل جديد"""
        if HAS_FASTAPI:
            await websocket.accept()
        self.connections.append(websocket)
        log.debug(f"[Telemetry] Client connected. Total: {len(self.connections)}")

        # إرسال الأحداث الأخيرة للعميل الجديد
        for event in self.event_history[-20:]:
            try:
                if HAS_FASTAPI:
                    await websocket.send_text(event.to_json())
                else:
                    await websocket.send(event.to_json())
            except Exception:
                pass

    def disconnect(self, websocket: Any):
        """إزالة عميل"""
        if websocket in self.connections:
            self.connections.remove(websocket)
        log.debug(f"[Telemetry] Client disconnected. Total: {len(self.connections)}")

    async def broadcast(self, event: TelemetryEvent):
        """بث حدث لكل العملاء المتصلين"""
        self.event_history.append(event)
        if len(self.event_history) > self.max_history:
            self.event_history = self.event_history[-self.max_history:]

        message = event.to_json()
        disconnected = []

        for ws in self.connections:
            try:
                if HAS_FASTAPI:
                    await ws.send_text(message)
                else:
                    await ws.send(message)
            except Exception:
                disconnected.append(ws)

        for ws in disconnected:
            self.disconnect(ws)

    # ── أحداث مخصصة للمسح ────────────────────────────────────────────

    async def scan_started(
        self,
        session_id: str,
        target: str,
        mission: str,
    ):
        await self.broadcast(TelemetryEvent(
            event_type="scan_started",
            data={
                "session_id": session_id,
                "target": target,
                "mission": mission,
                "status": "running",
            },
        ))

    async def scan_completed(
        self,
        session_id: str,
        target: str,
        findings_count: int,
        duration: float,
    ):
        await self.broadcast(TelemetryEvent(
            event_type="scan_completed",
            data={
                "session_id": session_id,
                "target": target,
                "findings_count": findings_count,
                "duration": duration,
                "status": "completed",
            },
        ))

    async def finding_discovered(
        self,
        session_id: str,
        finding: Dict[str, Any],
    ):
        await self.broadcast(TelemetryEvent(
            event_type="finding_discovered",
            data={
                "session_id": session_id,
                "finding": finding,
            },
        ))

    async def phase_changed(
        self,
        session_id: str,
        phase_id: int,
        phase_name: str,
        status: str,
    ):
        await self.broadcast(TelemetryEvent(
            event_type="phase_changed",
            data={
                "session_id": session_id,
                "phase_id": phase_id,
                "phase_name": phase_name,
                "status": status,
            },
        ))

    async def error_occurred(
        self,
        session_id: str,
        error: str,
        component: str = "unknown",
    ):
        await self.broadcast(TelemetryEvent(
            event_type="error",
            data={
                "session_id": session_id,
                "error": error,
                "component": component,
            },
        ))

    def get_history(self, limit: int = 50) -> List[dict]:
        """إرجاع أحدث الأحداث"""
        return [e.to_json() for e in self.event_history[-limit:]]

    def clear_history(self):
        self.event_history.clear()


# مثيل افتراضي يمكن استخدامه في toute the system
telemetry = TelemetryManager()
