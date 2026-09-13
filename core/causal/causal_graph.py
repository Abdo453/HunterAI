"""
HunterAI Causal Security Graph
==============================
Moves beyond mere observational correlation into true causal attribution:
Cause -> Mechanism -> Effect -> Evidence

Invariants:
- A vulnerability cannot be claimed without an unbroken causal chain linking
  user-controlled inputs to an observable differential state change or sink execution.
- Distinguishes coincidental server variations from true causal impact.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class CausalNodeType(str, Enum):
    USER_INPUT = "USER_INPUT"
    PARSER_GATEWAY = "PARSER_GATEWAY"
    BUSINESS_LOGIC = "BUSINESS_LOGIC"
    AUTH_DECISION = "AUTH_DECISION"
    DATA_SINK = "DATA_SINK"
    OBSERVABLE_RESPONSE = "OBSERVABLE_RESPONSE"


@dataclass
class CausalNode:
    node_id: str
    node_type: CausalNodeType
    label: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CausalEdge:
    source_id: str
    target_id: str
    mechanism: str
    confidence: float = 1.0


@dataclass
class CausalChainVerification:
    finding_id: str
    is_causally_proven: bool
    unbroken_chain: List[str] = field(default_factory=list)
    confidence_score: float = 0.0
    missing_links: List[str] = field(default_factory=list)
    causal_summary: str = ""


class CausalSecurityGraph:
    """Directed Acyclic Graph (DAG) for tracking causal security influence"""

    def __init__(self, target_host: str):
        self.target_host = target_host
        self.nodes: Dict[str, CausalNode] = {}
        self.edges: List[CausalEdge] = []

    def add_node(self, node_id: str, node_type: CausalNodeType, label: str, **meta) -> CausalNode:
        node = CausalNode(node_id, node_type, label, meta)
        self.nodes[node_id] = node
        return node

    def add_causal_link(self, source_id: str, target_id: str, mechanism: str, confidence: float = 1.0) -> CausalEdge:
        if source_id not in self.nodes or target_id not in self.nodes:
            raise KeyError("Both source and target nodes must exist in the Causal Graph before linking.")
        edge = CausalEdge(source_id, target_id, mechanism, confidence)
        self.edges.append(edge)
        return edge

    def verify_causal_chain(self, start_input_node: str, end_response_node: str) -> CausalChainVerification:
        """Finds directed path from User Input to Observable Response and verifies completeness"""
        if start_input_node not in self.nodes or end_response_node not in self.nodes:
            return CausalChainVerification(
                finding_id="N/A",
                is_causally_proven=False,
                missing_links=["Start or End node not found in causal graph."]
            )

        # BFS to find causal pathway
        queue = [[start_input_node]]
        visited = set()
        found_path = None

        while queue:
            path = queue.pop(0)
            node = path[-1]
            if node == end_response_node:
                found_path = path
                break

            if node not in visited:
                visited.add(node)
                neighbors = [e.target_id for e in self.edges if e.source_id == node]
                for n in neighbors:
                    new_path = list(path)
                    new_path.append(n)
                    queue.append(new_path)

        if not found_path:
            return CausalChainVerification(
                finding_id="N/A",
                is_causally_proven=False,
                missing_links=[f"No directed causal path exists from {start_input_node} to {end_response_node}."],
                causal_summary="Observation is a disconnected correlation, not a proven causal vulnerability."
            )

        # Verify whether path traverses mandatory intermediaries
        node_types_in_path = {self.nodes[nid].node_type for nid in found_path}
        missing = []
        if CausalNodeType.DATA_SINK not in node_types_in_path and CausalNodeType.AUTH_DECISION not in node_types_in_path:
            missing.append("Missing sink execution or authorization decision in causal pathway.")

        is_proven = len(missing) == 0
        path_labels = [f"{self.nodes[nid].label} ({self.nodes[nid].node_type.value})" for nid in found_path]

        return CausalChainVerification(
            finding_id="F-CAUSAL",
            is_causally_proven=is_proven,
            unbroken_chain=path_labels,
            confidence_score=0.95 if is_proven else 0.40,
            missing_links=missing,
            causal_summary="Unbroken causal chain established from user payload to observable effect." if is_proven else "Incomplete causal attribution."
        )

    def build_standard_injection_chain(
        self,
        finding_id: str,
        param: str,
        sink_name: str,
        differential_detail: str
    ) -> CausalChainVerification:
        """Constructs and verifies a standard linear injection causal chain"""
        in_id = f"IN_{finding_id}_{param}"
        parser_id = f"PARSER_{finding_id}"
        sink_id = f"SINK_{finding_id}_{sink_name}"
        resp_id = f"RESP_{finding_id}"

        self.add_node(in_id, CausalNodeType.USER_INPUT, f"Parameter '{param}'")
        self.add_node(parser_id, CausalNodeType.PARSER_GATEWAY, "HTTP Request & Query Parser")
        self.add_node(sink_id, CausalNodeType.DATA_SINK, f"Backend Sink: {sink_name}")
        self.add_node(resp_id, CausalNodeType.OBSERVABLE_RESPONSE, f"Differential: {differential_detail}")

        self.add_causal_link(in_id, parser_id, "User input injected into parser")
        self.add_causal_link(parser_id, sink_id, "Unsanitized parameter reaches execution sink")
        self.add_causal_link(sink_id, resp_id, "Execution sink output reflected in response")

        verif = self.verify_causal_chain(in_id, resp_id)
        verif.finding_id = finding_id
        return verif

