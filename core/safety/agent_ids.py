"""
HunterAI Agent Intrusion Detection System (Agent IDS)
====================================================
Monitors internal AI agent behavior in real time:
- Request Velocity Spikes (> 100 req/min)
- Scope Creep Anomalies (accessing non-whitelisted domains)
- Cloud Metadata / RFC1918 Forbidden Egress (169.254.169.254, 10.0.0.0/8)
- Repetitive Action Looping (> 5 repeated failures)
Automatically triggers EmergencyKillSwitch on critical compromise.
"""
from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Deque, Dict, List, Optional, Set

from core.safety.kill_switch import EmergencyKillSwitch

logger = logging.getLogger("hunter_ai.agent_ids")


class AnomalySeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class IDSAlert:
    alert_id: str
    anomaly_type: str
    severity: AnomalySeverity
    description: str
    timestamp: float = field(default_factory=time.time)


class AgentIntrusionDetector:
    """Real-time behavioral IDS for HunterAI autonomous execution"""

    def __init__(
        self,
        authorized_domains: Optional[Set[str]] = None,
        max_req_per_min: int = 100,
        kill_switch: Optional[EmergencyKillSwitch] = None
    ):
        self.authorized_domains = authorized_domains or set()
        self.max_req_per_min = max_req_per_min
        self.kill_switch = kill_switch or EmergencyKillSwitch()
        self.request_timestamps: Deque[float] = deque()
        self.action_history: Deque[str] = deque(maxlen=20)
        self.alerts: List[IDSAlert] = []

    def monitor_action(
        self,
        agent_role: str,
        target_host: str,
        action_signature: str
    ) -> Optional[IDSAlert]:
        """Inspects an action before network dispatch. Freezes execution on critical anomalies."""
        now = time.time()

        # 1. Velocity Spike Check
        self.request_timestamps.append(now)
        # Purge timestamps older than 60 seconds
        while self.request_timestamps and (now - self.request_timestamps[0] > 60.0):
            self.request_timestamps.popleft()

        if len(self.request_timestamps) > self.max_req_per_min:
            alert = IDSAlert(
                alert_id=f"IDS-VEL-{int(now)}",
                anomaly_type="RATE_SPIKE_ANOMALY",
                severity=AnomalySeverity.CRITICAL,
                description=f"Agent '{agent_role}' exceeded maximum velocity: {len(self.request_timestamps)} requests/min."
            )
            self._handle_critical_alert(alert)
            return alert

        # 2. Forbidden Subnet Egress Check (Cloud Metadata & RFC1918)
        if any(target_host.startswith(p) for p in ["169.254.", "127.", "localhost", "0.0.0.0"]):
            alert = IDSAlert(
                alert_id=f"IDS-EGR-{int(now)}",
                anomaly_type="FORBIDDEN_SUBNET_EGRESS",
                severity=AnomalySeverity.CRITICAL,
                description=f"Agent '{agent_role}' attempted prohibited network access to internal/metadata target '{target_host}'."
            )
            self._handle_critical_alert(alert)
            return alert

        # 3. Scope Expansion Anomaly
        if self.authorized_domains and target_host not in self.authorized_domains:
            # Check subdomain matching
            is_sub = any(target_host == d or target_host.endswith("." + d) for d in self.authorized_domains)
            if not is_sub:
                alert = IDSAlert(
                    alert_id=f"IDS-SCP-{int(now)}",
                    anomaly_type="SCOPE_EXPANSION_ANOMALY",
                    severity=AnomalySeverity.CRITICAL,
                    description=f"Agent '{agent_role}' attempted action outside authorized scope on host '{target_host}'."
                )
                self._handle_critical_alert(alert)
                return alert

        # 4. Repetitive Action Looping
        self.action_history.append(action_signature)
        if self.action_history.count(action_signature) >= 5:
            alert = IDSAlert(
                alert_id=f"IDS-LOOP-{int(now)}",
                anomaly_type="ACTION_LOOP_ANOMALY",
                severity=AnomalySeverity.HIGH,
                description=f"Agent '{agent_role}' trapped in repetitive loop on action '{action_signature}'."
            )
            self.alerts.append(alert)
            return alert

        return None

    def _handle_critical_alert(self, alert: IDSAlert):
        self.alerts.append(alert)
        logger.critical(f"🚨 [AGENT IDS INTRUSION DETECTED]: {alert.description}")
        self.kill_switch.trigger(reason=f"Agent IDS Lockdown: {alert.description}")

    def get_health_status(self) -> Dict[str, Any]:
        return {
            "active_alerts_count": len(self.alerts),
            "recent_velocity_req_per_min": len(self.request_timestamps),
            "kill_switch_tripped": self.kill_switch.is_tripped,
            "alerts": [asdict(a) for a in self.alerts]
        }
