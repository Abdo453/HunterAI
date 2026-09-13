"""
HunterAI Finding Economics Tracker
==================================
Measures the empirical operational cost of finding discoveries:
- Total HTTP requests dispatched
- Total socket / network runtime in seconds
- LLM token consumption
- Tools / Sensors invoked
Calculates discovery efficiency and eliminates high-cost/low-yield test vectors.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class FindingCostMetrics:
    finding_id: str
    target: str
    vulnerability_type: str
    requests_count: int = 0
    socket_seconds: float = 0.0
    llm_tokens: int = 0
    tools_invoked: int = 1
    replays_count: int = 1


class FindingEconomicsTracker:
    """Tracks and reports resource expenditure per security finding"""

    def __init__(self):
        self.metrics: Dict[str, FindingCostMetrics] = {}

    def record_cost(
        self,
        finding_id: str,
        target: str,
        vulnerability_type: str,
        requests: int,
        socket_sec: float,
        tokens: int = 0,
        tools: int = 1
    ) -> FindingCostMetrics:
        cost = FindingCostMetrics(
            finding_id=finding_id,
            target=target,
            vulnerability_type=vulnerability_type,
            requests_count=requests,
            socket_seconds=round(socket_sec, 2),
            llm_tokens=tokens,
            tools_invoked=tools
        )
        self.metrics[finding_id] = cost
        return cost

    def get_summary(self, finding_id: str) -> Optional[Dict[str, Any]]:
        cost = self.metrics.get(finding_id)
        return asdict(cost) if cost else None

    def get_aggregate_economics(self) -> Dict[str, Any]:
        total_reqs = sum(m.requests_count for m in self.metrics.values())
        total_time = sum(m.socket_seconds for m in self.metrics.values())
        total_tokens = sum(m.llm_tokens for m in self.metrics.values())
        count = max(1, len(self.metrics))

        return {
            "total_findings_tracked": len(self.metrics),
            "total_requests": total_reqs,
            "total_socket_seconds": round(total_time, 2),
            "total_tokens_consumed": total_tokens,
            "avg_requests_per_finding": round(total_reqs / count, 1),
            "avg_seconds_per_finding": round(total_time / count, 2)
        }
