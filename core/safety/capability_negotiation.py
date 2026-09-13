"""
HunterAI Agent Capability Negotiation Engine
============================================
Allows specialized agents to advertise capability tokens, operational constraints,
and risk boundaries:
- Capabilities: "HTTP_PROBE", "BROWSER_DOM", "JS_ANALYSIS", "GRAPHQL_INTROSPECT", "OPENAPI_DIFF"
- Boundaries: max_requests, allowed_methods, is_mutation_permitted

The Planner assigns tasks only to agents possessing the negotiated capability tokens.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass(frozen=True)
class AgentCapabilityDeclaration:
    agent_id: str
    role_name: str
    capabilities: Set[str]
    max_request_budget: int
    mutation_permitted: bool = False

    def can_fulfill(self, required_caps: Set[str], requires_mutation: bool) -> bool:
        if requires_mutation and not self.mutation_permitted:
            return False
        return required_caps.issubset(self.capabilities)


class CapabilityNegotiationEngine:
    """Matches tasks to appropriate specialized agents based on declared capability contracts"""

    def __init__(self):
        self._agents: Dict[str, AgentCapabilityDeclaration] = {}

    def register_agent(
        self,
        agent_id: str,
        role: str,
        capabilities: List[str],
        max_budget: int = 500,
        mutation_permitted: bool = False
    ) -> AgentCapabilityDeclaration:
        decl = AgentCapabilityDeclaration(
            agent_id=agent_id,
            role_name=role,
            capabilities=set(capabilities),
            max_request_budget=max_budget,
            mutation_permitted=mutation_permitted
        )
        self._agents[agent_id] = decl
        return decl

    def negotiate_agent_for_task(
        self,
        required_capabilities: List[str],
        requires_mutation: bool = False
    ) -> Optional[AgentCapabilityDeclaration]:
        req_set = set(required_capabilities)
        for agent in self._agents.values():
            if agent.can_fulfill(req_set, requires_mutation):
                return agent
        return None

    def list_registered(self) -> List[Dict[str, Any]]:
        return [
            {
                "agent_id": a.agent_id,
                "role": a.role_name,
                "capabilities": list(a.capabilities),
                "mutation_permitted": a.mutation_permitted
            }
            for a in self._agents.values()
        ]
