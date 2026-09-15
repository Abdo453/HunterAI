"""
HunterAI Security Flight Recorder
=================================
Blackbox flight recorder capturing every micro-decision, timestamp,
agent role, rationale, payload hash, and socket response.
Enables retroactive post-mission explanation of every single action.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class FlightEventType(str, Enum):
    SCOPE_LOADED = "SCOPE_LOADED"
    ASSET_DISCOVERED = "ASSET_DISCOVERED"
    ENDPOINT_PRIORITIZED = "ENDPOINT_PRIORITIZED"
    HYPOTHESIS_FORMED = "HYPOTHESIS_FORMED"
    ACTION_PROPOSED = "ACTION_PROPOSED"
    POLICY_DECISION = "POLICY_DECISION"
    PROBE_EXECUTED = "PROBE_EXECUTED"
    POE_VERIFIED = "POE_VERIFIED"
    COURT_VERDICT = "COURT_VERDICT"
    FINDING_COMMITTED = "FINDING_COMMITTED"
    REPLAY_FROZEN = "REPLAY_FROZEN"
    INCIDENT_ALERT = "INCIDENT_ALERT"


@dataclass
class FlightEvent:
    event_id: str = field(default_factory=lambda: f"FLT-{uuid.uuid4().hex[:8].upper()}")
    event_type: FlightEventType = FlightEventType.SCOPE_LOADED
    elapsed_sec: float = 0.0
    phase: str = "ORIENT"
    actor: str = "system"
    rationale: str = ""
    payload_checksum: Optional[str] = None
    finding_id: Optional[str] = None
    action_id: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["event_type"] = self.event_type.value
        return d


class SecurityFlightRecorder:
    """Blackbox telemetry recorder for HunterAI operational sessions"""

    _instance: Optional[SecurityFlightRecorder] = None

    def __init__(self, session_id: Optional[str] = None, output_dir: Optional[Path] = None):
        self.session_id = session_id or f"sess_{int(time.time())}"
        self.start_time = time.time()
        self.events: List[FlightEvent] = []
        self.output_dir = output_dir or (Path(__file__).resolve().parent.parent.parent / "data" / "telemetry")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.output_dir / f"flight_log_{self.session_id}.jsonl"

    @classmethod
    def get_instance(cls) -> SecurityFlightRecorder:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def record_event(
        self,
        event_type: FlightEventType,
        phase: str,
        actor: str,
        rationale: str,
        payload: Optional[str] = None,
        finding_id: Optional[str] = None,
        action_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> FlightEvent:
        """Records an event with calculated payload SHA-256 and streaming persistence"""
        now = time.time()
        elapsed = round(now - self.start_time, 3)

        checksum = None
        if payload is not None:
            checksum = hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()[:16]

        event = FlightEvent(
            event_type=event_type,
            elapsed_sec=elapsed,
            phase=phase,
            actor=actor,
            rationale=rationale,
            payload_checksum=checksum,
            finding_id=finding_id,
            action_id=action_id,
            details=details or {},
            timestamp=now
        )
        self.events.append(event)

        # Stream append to JSONL log file
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(event.to_dict()) + "\n")
        except Exception:
            pass

        return event

    def query_decision_trail(self, finding_id: Optional[str] = None, action_id: Optional[str] = None) -> List[FlightEvent]:
        """Retrieves all causal events linked to a specific finding or action"""
        matched = []
        for e in self.events:
            if finding_id and e.finding_id == finding_id:
                matched.append(e)
            elif action_id and e.action_id == action_id:
                matched.append(e)
            elif finding_id and e.details.get("linked_finding") == finding_id:
                matched.append(e)
        return matched

    def format_timeline(self, limit: int = 50) -> str:
        """Renders an ASCII chronological timeline of flight recorder decisions"""
        lines = [
            "=" * 76,
            f" 🛫 HunterAI Security Flight Log — Session {self.session_id}",
            "=" * 76,
            f" {'TIME':<8} | {'PHASE':<8} | {'ACTOR':<16} | {'EVENT':<22} | {'RATIONALE'}",
            "-" * 76
        ]
        for e in self.events[-limit:]:
            t_str = f"+{e.elapsed_sec:.1f}s"
            ev_str = e.event_type.value[:22]
            act_str = e.actor[:16]
            rat_str = (e.rationale[:35] + "...") if len(e.rationale) > 35 else e.rationale
            lines.append(f" {t_str:<8} | {e.phase:<8} | {act_str:<16} | {ev_str:<22} | {rat_str}")

        lines.append("=" * 76)
        return "\n".join(lines)

    def get_recent_events(self, limit: int = 50) -> List[FlightEvent]:
        """Returns the most recent flight recorder events up to limit"""
        return self.events[-limit:]
