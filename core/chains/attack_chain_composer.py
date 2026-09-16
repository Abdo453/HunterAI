"""
HunterAI Attack Chain Composer & Path Search
============================================
Composes evidence-backed compound attack kill chains:
Finding A -> enables Finding B -> enables Critical Impact.
Implements shortest-path search from ANONYMOUS to RESTRICTED resources.
"""
from __future__ import annotations

import heapq
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("hunter_ai.attack_chain")


@dataclass
class ChainLink:
    stage_number: int
    source_finding_id: str
    vuln_class: str
    action_description: str
    unlocked_primitive: str  # e.g., 'internal_token', 'signed_url', 'tenant_admin_role'
    evidence_proof: str


@dataclass
class AttackChain:
    chain_id: str
    chain_title: str
    composite_severity: str  # "CRITICAL", "HIGH"
    initial_identity: str
    target_impact: str
    links: List[ChainLink] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "chain_title": self.chain_title,
            "composite_severity": self.composite_severity,
            "initial_identity": self.initial_identity,
            "target_impact": self.target_impact,
            "total_links": len(self.links),
            "links": [
                {
                    "step": l.stage_number,
                    "finding_id": l.source_finding_id,
                    "vuln_class": l.vuln_class,
                    "action": l.action_description,
                    "unlocked": l.unlocked_primitive,
                    "proof": l.evidence_proof,
                }
                for l in self.links
            ]
        }


class AttackChainComposer:
    """
    Composes and verifies multi-stage attack chains across findings.
    """

    def __init__(self):
        self.chains: List[AttackChain] = []

    def compose_chain(
        self,
        chain_title: str,
        initial_identity: str,
        target_impact: str,
        links: List[ChainLink]
    ) -> AttackChain:
        composite_severity = "CRITICAL" if len(links) >= 2 else "HIGH"
        chain = AttackChain(
            chain_id=f"CHAIN-{uuid.uuid4().hex[:6].upper()}",
            chain_title=chain_title,
            composite_severity=composite_severity,
            initial_identity=initial_identity,
            target_impact=target_impact,
            links=links
        )
        self.chains.append(chain)
        return chain

    @classmethod
    def search_shortest_attack_path(
        cls,
        graph_edges: Dict[str, List[Tuple[str, float]]],
        start_node: str,
        goal_node: str
    ) -> Tuple[float, List[str]]:
        """
        Dijkstra shortest path search over the attack graph:
        Returns (minimum_cost, [path_nodes]).
        """
        queue = [(0.0, start_node, [start_node])]
        visited = set()

        while queue:
            cost, current, path = heapq.heappop(queue)
            if current == goal_node:
                return cost, path

            if current in visited:
                continue
            visited.add(current)

            for neighbor, weight in graph_edges.get(current, []):
                if neighbor not in visited:
                    heapq.heappush(queue, (cost + weight, neighbor, path + [neighbor]))

        return float("inf"), []
