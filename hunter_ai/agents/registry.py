"""
HunterAI Agent Registry
Tracks all active agents, their capabilities, sessions, and permissions:
- WebAgent (web_analysis, http_analysis, vulnerability_analysis, javascript_analysis)
- BurpAgent (traffic_analysis, request_correlation, session_audit)
- ReconAgent (reconnaissance, asset_discovery, dns_analysis, osint_analysis)
- MobileAgent, CloudAgent, etc.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from hunter_ai.agents.capabilities import AgentCapability

logger = logging.getLogger(__name__)


@dataclass
class AgentDescriptor:
    agent_name: str
    capabilities: Set[AgentCapability]
    version: str = "1.0.0"
    is_active: bool = True
    session_count: int = 0
    created_at: float = field(default_factory=time.time)


class AgentRegistry:
    """
    سجل الوكلاء المركزي (Agent Registry):
    - يسجل كافة الـ Agents المتاحة في المنظومة وقدراتها المعيارية.
    - يسمح للـ Control Plane بمعرفة أي Agent مؤهل للتعامل مع أي مهمة أو حدث.
    """

    def __init__(self):
        self._agents: Dict[str, AgentDescriptor] = {}
        self._seed_default_agents()

    def _seed_default_agents(self):
        """تسجيل الـ Agents القياسية للنظام بشكل مسبق"""
        self.register_agent(
            "WebAgent",
            {
                AgentCapability.WEB_ANALYSIS,
                AgentCapability.HTTP_ANALYSIS,
                AgentCapability.VULNERABILITY_ANALYSIS,
                AgentCapability.JAVASCRIPT_ANALYSIS,
                AgentCapability.API_ANALYSIS
            }
        )
        self.register_agent(
            "BurpAgent",
            {
                AgentCapability.TRAFFIC_ANALYSIS,
                AgentCapability.REQUEST_CORRELATION,
                AgentCapability.SESSION_AUDIT,
                AgentCapability.HTTP_ANALYSIS
            }
        )
        self.register_agent(
            "ReconAgent",
            {
                AgentCapability.RECONNAISSANCE,
                AgentCapability.ASSET_DISCOVERY,
                AgentCapability.DNS_ANALYSIS,
                AgentCapability.OSINT_ANALYSIS
            }
        )
        self.register_agent(
            "AutonomousBrain",
            set(AgentCapability)  # AutonomousBrain has holistic coordination capability
        )

    def register_agent(self, agent_name: str, capabilities: Set[AgentCapability], version: str = "1.0.0") -> AgentDescriptor:
        desc = AgentDescriptor(agent_name=agent_name, capabilities=capabilities, version=version)
        self._agents[agent_name] = desc
        logger.info(f"[AgentRegistry] Registered agent '{agent_name}' with {len(capabilities)} capabilities.")
        return desc

    def get_agent(self, agent_name: str) -> Optional[AgentDescriptor]:
        return self._agents.get(agent_name)

    def find_capable_agents(self, capability: AgentCapability) -> List[AgentDescriptor]:
        """العثور على جميع الـ Agents التي تمتلك قدرة معينة"""
        return [ag for ag in self._agents.values() if capability in ag.capabilities and ag.is_active]

    def list_all(self) -> Dict[str, List[str]]:
        return {name: [c.value for c in ag.capabilities] for name, ag in self._agents.items()}
