"""
WebSocket Frame Collector for BurpAgent
"""
import json
import logging
from typing import Optional, Dict, Any
from agents.burp_agent.storage.models import WebSocketFrameModel
from agents.burp_agent.storage.database import TrafficDatabase

log = logging.getLogger("burp_agent.websocket_collector")


class WebSocketCollector:
    """مجمع ومحلل حزم وتدفق الـ WebSockets"""

    def __init__(self, db: TrafficDatabase):
        self.db = db

    def record_frame(
        self,
        connection_id: str,
        direction: str,
        opcode: int,
        payload: str
    ) -> WebSocketFrameModel:
        """تسجيل رسالة WebSocket وفحص ما إذا كانت JSON"""
        is_json = False
        parsed_json = None
        try:
            if payload.strip().startswith(("{", "[")):
                parsed_json = json.loads(payload)
                is_json = True
        except Exception:
            pass

        frame = WebSocketFrameModel(
            connection_id=connection_id,
            direction=direction,
            opcode=opcode,
            payload=payload,
            payload_size=len(payload.encode("utf-8")),
            is_json=is_json,
            parsed_json=parsed_json
        )
        self.db.insert_websocket_frame(frame)
        return frame
