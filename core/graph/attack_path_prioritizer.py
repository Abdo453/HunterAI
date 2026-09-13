"""
HunterAI Attack Path Prioritizer
================================
Ranks authorized exploration paths by evidence value and risk score:
Scores paths based on identity differentials, parameter sensitivity,
and resource value to prioritize high-consequence tests first.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List
from core.graph.knowledge_graph import KnowledgeGraph


@dataclass
class PrioritizedPath:
    endpoint_key: str
    path: str
    method: str
    priority_score: float  # 1.0 (lowest) to 10.0 (highest)
    rationale: str
    suggested_role: str = "anonymous"


class AttackPathPrioritizer:
    """Scores endpoints from KnowledgeGraph to guide Planner queue"""

    @classmethod
    def prioritize(cls, graph: KnowledgeGraph) -> List[PrioritizedPath]:
        ranked = []
        for key, ep in graph.endpoints.items():
            score = 2.0
            reasons = []

            # Check if linked to sensitive resources (IDOR candidate)
            matching_resources = [r for r in graph.resources.values() if r.endpoint_path == ep.path]
            if matching_resources:
                score += 4.5
                reasons.append(f"Exposes sensitive object: {[r.resource_type for r in matching_resources]}")

            # Check for high-interest parameters
            for p in ep.parameters:
                low_p = p.lower()
                if any(kw in low_p for kw in ["id", "user", "doc", "account", "order"]):
                    score += 2.0
                    reasons.append(f"Contains object identifier parameter '{p}'")
                elif any(kw in low_p for kw in ["url", "redirect", "callback", "dest"]):
                    score += 2.5
                    reasons.append(f"Contains SSRF / redirect vector parameter '{p}'")

            if ep.method in ("POST", "PUT", "DELETE"):
                score += 1.0
                reasons.append(f"State-mutating method {ep.method}")

            score = min(10.0, score)
            ranked.append(PrioritizedPath(
                endpoint_key=key,
                path=ep.path,
                method=ep.method,
                priority_score=round(score, 1),
                rationale="; ".join(reasons) or "Standard attack surface endpoint",
                suggested_role="standard_user_b" if matching_resources else "anonymous"
            ))

        ranked.sort(key=lambda x: x.priority_score, reverse=True)
        return ranked