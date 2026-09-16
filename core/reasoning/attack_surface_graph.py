"""
HunterAI V27.0 - Attack Surface Graph
======================================
Unified Epistemic Surface Graph tracking all states, principals, resources,
endpoints, and transitions across 9 distinct epistemic statuses:
  - OBSERVED:           Directly witnessed on the wire or in DOM
  - INFERRED:           Logically derived from concrete evidence
  - CANDIDATE:          Untested candidate transition or hypothesis
  - TESTED:             Probed by an experiment contract
  - PARTIALLY_VERIFIED: Asymmetric, contradictory, or incomplete probe evidence
  - CONFIRMED:          Proven causal invariant breach
  - REJECTED:           Disproved by explicit negative observables or defense boundary
  - BLOCKED:            WAF or scope restriction prevented testing
  - UNKNOWN:            Unexplored state, boundary, or parameter

Crucial Invariant:
  PARTIALLY_VERIFIED prevents jumping prematurely to CONFIRMED or REJECTED when
  E1 succeeds but E2 diverges, or when authorization is asymmetric.
"""
from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("hunter_ai.attack_surface_graph")


class EpistemicStatus(str, Enum):
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    CANDIDATE = "CANDIDATE"
    TESTED = "TESTED"
    PARTIALLY_VERIFIED = "PARTIALLY_VERIFIED"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"


@dataclass
class SurfaceNode:
    node_id: str
    node_type: str  # 'STATE', 'ENDPOINT', 'RESOURCE', 'PRINCIPAL'
    name: str
    epistemic_status: EpistemicStatus = EpistemicStatus.UNKNOWN
    attributes: Dict[str, Any] = field(default_factory=dict)
    evidence_refs: List[str] = field(default_factory=list)
    confidence: float = 0.50
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["epistemic_status"] = self.epistemic_status.value
        return d


@dataclass
class SurfaceEdge:
    edge_id: str
    source_node_id: str
    target_node_id: str
    relation_type: str  # 'TRANSITION', 'ACCESSES', 'OWNS', 'REQUIRES', 'CANDIDATE_VIOLATION'
    epistemic_status: EpistemicStatus = EpistemicStatus.UNKNOWN
    conditions: Dict[str, Any] = field(default_factory=dict)
    evidence_refs: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["epistemic_status"] = self.epistemic_status.value
        return d


class AttackSurfaceGraph:
    """
    Central repository for the target's attack surface and epistemic state.
    Integrates application states, identity permissions, and workflow transitions.
    """

    def __init__(self, target_domain: str = "target.local"):
        self.target_domain = target_domain
        self.nodes: Dict[str, SurfaceNode] = {}
        self.edges: Dict[str, SurfaceEdge] = {}

    def add_node(self, node: SurfaceNode) -> SurfaceNode:
        self.nodes[node.node_id] = node
        return node

    def add_edge(self, edge: SurfaceEdge) -> SurfaceEdge:
        self.edges[edge.edge_id] = edge
        return edge

    def update_status(
        self,
        target_id: str,
        new_status: EpistemicStatus,
        evidence_ref: str = "",
        rationale: str = "",
        confidence: Optional[float] = None,
    ):
        """Updates the epistemic status of a node or edge with complete provenance."""
        target: Optional[Any] = self.nodes.get(target_id) or self.edges.get(target_id)
        if not target:
            logger.warning(f"[SURFACE GRAPH] Target '{target_id}' not found for status update.")
            return

        old_status = target.epistemic_status
        target.epistemic_status = new_status
        target.updated_at = time.time()
        if evidence_ref and evidence_ref not in target.evidence_refs:
            target.evidence_refs.append(evidence_ref)
        if confidence is not None and hasattr(target, "confidence"):
            target.confidence = confidence

        logger.info(
            f"[SURFACE GRAPH] {target_id} status transition: "
            f"{old_status.value} -> {new_status.value} ({rationale})"
        )

    def get_unexplored_candidates(self) -> List[SurfaceEdge]:
        """Returns all candidate or unknown transitions that warrant testing."""
        return [
            e for e in self.edges.values()
            if e.epistemic_status in (EpistemicStatus.CANDIDATE, EpistemicStatus.UNKNOWN)
        ]

    def get_partially_verified(self) -> List[SurfaceEdge]:
        """Returns all edges in PARTIALLY_VERIFIED state that require metamorphic disambiguation."""
        return [
            e for e in self.edges.values()
            if e.epistemic_status == EpistemicStatus.PARTIALLY_VERIFIED
        ]

    def export_graph(self) -> Dict[str, Any]:
        """Returns a JSON-serializable export of the attack surface graph."""
        status_counts: Dict[str, int] = {}
        for s in EpistemicStatus:
            status_counts[s.value] = sum(1 for n in self.nodes.values() if n.epistemic_status == s) + \
                                     sum(1 for e in self.edges.values() if e.epistemic_status == s)

        return {
            "target_domain": self.target_domain,
            "nodes_count": len(self.nodes),
            "edges_count": len(self.edges),
            "status_distribution": status_counts,
            "nodes": {k: v.to_dict() for k, v in self.nodes.items()},
            "edges": {k: v.to_dict() for k, v in self.edges.items()},
        }
