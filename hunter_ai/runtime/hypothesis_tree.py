"""
HunterAI Runtime: Hypothesis Tree
==================================
Hierarchical hypothesis tracking system inspired by autonomous research agent architectures.
Instead of brute-forcing single attacks, the system maintains a structured tree of hypotheses,
weighing evidence for and against each hypothesis, tracking confidence, and recommending
the next best verification step.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any


class HypothesisStatus(str, Enum):
    PENDING = "PENDING"
    TESTING = "TESTING"
    CONFIRMED = "CONFIRMED"
    REFUTED = "REFUTED"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class HypothesisNode:
    """A single hypothesis node in the reasoning tree"""
    id: str
    category: str                       # e.g., "SQLi", "IDOR", "SSRF", "Auth", "Logic"
    variant: str                        # e.g., "boolean_differential", "error_based", "union_extract"
    title: str
    description: str
    target_endpoint: str
    param_name: Optional[str] = None
    confidence: float = 0.5             # 0.0 to 1.0
    status: HypothesisStatus = HypothesisStatus.PENDING
    evidence_for: List[str] = field(default_factory=list)
    evidence_against: List[str] = field(default_factory=list)
    alternative_explanations: List[str] = field(default_factory=list)
    tests_executed: List[Dict[str, Any]] = field(default_factory=list)
    next_verification_action: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    parent_id: Optional[str] = None
    child_ids: List[str] = field(default_factory=list)

    def add_evidence_for(self, item: str, confidence_boost: float = 0.15):
        self.evidence_for.append(item)
        self.confidence = round(min(0.99, self.confidence + confidence_boost), 4)
        self.updated_at = time.time()

    def add_evidence_against(self, item: str, confidence_penalty: float = 0.25):
        self.evidence_against.append(item)
        self.confidence = round(max(0.01, self.confidence - confidence_penalty), 4)
        self.updated_at = time.time()

    def record_test(self, test_name: str, payload: str, response_summary: str, result: str):
        self.tests_executed.append({
            "test_name": test_name,
            "payload": payload,
            "response_summary": response_summary,
            "result": result,
            "timestamp": time.time()
        })
        self.updated_at = time.time()

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value if isinstance(self.status, HypothesisStatus) else str(self.status)
        return d


class HypothesisTree:
    """
    Manages the full tree of hypotheses for an active target or session.
    Provides pruning, frontier selection, and token-compact summarization.
    """

    def __init__(self, root_name: str = "AttackSurface"):
        self.root_name = root_name
        self._nodes: Dict[str, HypothesisNode] = {}
        self._next_index: int = 1

    def create_hypothesis(
        self,
        category: str,
        variant: str,
        title: str,
        description: str,
        target_endpoint: str,
        param_name: Optional[str] = None,
        initial_confidence: float = 0.5,
        parent_id: Optional[str] = None,
        next_action: Optional[str] = None
    ) -> HypothesisNode:
        """Adds a new hypothesis node to the tree"""
        node_id = f"H{self._next_index}_{category[:4].upper()}_{variant[:6].lower()}"
        self._next_index += 1

        node = HypothesisNode(
            id=node_id,
            category=category,
            variant=variant,
            title=title,
            description=description,
            target_endpoint=target_endpoint,
            param_name=param_name,
            confidence=initial_confidence,
            status=HypothesisStatus.PENDING,
            parent_id=parent_id,
            next_verification_action=next_action
        )

        self._nodes[node_id] = node
        if parent_id and parent_id in self._nodes:
            self._nodes[parent_id].child_ids.append(node_id)

        return node

    def get_node(self, node_id: str) -> Optional[HypothesisNode]:
        return self._nodes.get(node_id)

    def get_all_nodes(self) -> List[HypothesisNode]:
        return list(self._nodes.values())

    def update_status(self, node_id: str, status: HypothesisStatus):
        if node_id in self._nodes:
            self._nodes[node_id].status = status
            self._nodes[node_id].updated_at = time.time()

    def get_active_frontier(self, min_confidence: float = 0.25) -> List[HypothesisNode]:
        """
        Returns active unconfirmed and unrefuted hypotheses, sorted by confidence descending.
        This forms the priority frontier for the next actions of the planner.
        """
        frontier = [
            node for node in self._nodes.values()
            if node.status in [HypothesisStatus.PENDING, HypothesisStatus.TESTING]
            and node.confidence >= min_confidence
        ]
        frontier.sort(key=lambda n: n.confidence, reverse=True)
        return frontier

    def prune_low_confidence(self, threshold: float = 0.15) -> int:
        """Marks hypotheses below threshold as REFUTED to prune the search space"""
        pruned_count = 0
        for node in self._nodes.values():
            if node.status == HypothesisStatus.PENDING and node.confidence < threshold:
                node.status = HypothesisStatus.REFUTED
                node.add_evidence_against(f"Pruned: confidence dropped below {threshold}")
                pruned_count += 1
        return pruned_count

    def to_compact_summary(self, max_items: int = 5) -> List[Dict[str, Any]]:
        """
        Generates a token-efficient JSON view tailored for the LLM working context.
        Avoids token bloat while keeping all critical decision factors visible.
        """
        frontier = self.get_active_frontier()[:max_items]
        summary = []
        for n in frontier:
            summary.append({
                "id": n.id,
                "category": n.category,
                "endpoint": n.target_endpoint,
                "param": n.param_name,
                "confidence": round(n.confidence, 2),
                "status": n.status.value,
                "evidence_for_count": len(n.evidence_for),
                "evidence_against_count": len(n.evidence_against),
                "last_evidence_for": n.evidence_for[-1] if n.evidence_for else None,
                "next_action": n.next_verification_action or "differential_probe"
            })
        return summary

    def serialize(self) -> Dict[str, Any]:
        return {
            "root_name": self.root_name,
            "next_index": self._next_index,
            "nodes": {k: v.to_dict() for k, v in self._nodes.items()}
        }

    @classmethod
    def deserialize(cls, data: Dict[str, Any]) -> HypothesisTree:
        tree = cls(root_name=data.get("root_name", "AttackSurface"))
        tree._next_index = data.get("next_index", 1)
        for k, v in data.get("nodes", {}).items():
            status_val = v.get("status", "PENDING")
            try:
                status = HypothesisStatus(status_val)
            except ValueError:
                status = HypothesisStatus.PENDING

            node = HypothesisNode(
                id=v["id"],
                category=v["category"],
                variant=v["variant"],
                title=v["title"],
                description=v["description"],
                target_endpoint=v["target_endpoint"],
                param_name=v.get("param_name"),
                confidence=v.get("confidence", 0.5),
                status=status,
                evidence_for=v.get("evidence_for", []),
                evidence_against=v.get("evidence_against", []),
                alternative_explanations=v.get("alternative_explanations", []),
                tests_executed=v.get("tests_executed", []),
                next_verification_action=v.get("next_verification_action"),
                created_at=v.get("created_at", time.time()),
                updated_at=v.get("updated_at", time.time()),
                parent_id=v.get("parent_id"),
                child_ids=v.get("child_ids", [])
            )
            tree._nodes[k] = node
        return tree
