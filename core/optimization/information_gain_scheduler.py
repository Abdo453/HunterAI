"""
HunterAI Active Information-Gain Scheduler
==========================================
Replaces blind linear scanning with mathematical Information-Gain Optimization:
Prioritizes inspection targets by maximum expected entropy reduction per request cost:

               ΔI(Endpoint)
  Score = ─────────────────────
             Cost(Endpoint)

Where:
- ΔI(Endpoint) measures uncertainty and vulnerability potential:
  • Untested surface point (baseline entropy)
  • Dynamic object identifiers in path (/users/{id}, /invoices/{uuid}) -> BOLA potential
  • Authenticated multi-tenant endpoints -> Authorization boundary
  • State-mutating methods (POST/PUT/DELETE) -> Business logic mutation
  • Unsanitized query parameters (q, search, filter, order) -> Injection potential
- Cost(Endpoint) measures probe resource expenditure:
  • Estimated requests to confirm or refute (typically 2 - 4)
  • Operational risk level
"""
from __future__ import annotations

import logging
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger("hunter_ai.optimization.info_gain_scheduler")

_OBJECT_ID_REGEX = re.compile(r"/(?:[0-9]+|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}|[a-zA-Z0-9_\-\.]{16,})(?:/|$)", re.IGNORECASE)
_INJECTION_PARAM_NAMES = {"id", "q", "query", "search", "filter", "sort", "order", "cat", "page", "dir", "cmd", "file", "url", "redirect"}


@dataclass
class ScheduledInspectionTarget:
    target_id: str
    path: str
    method: str
    asset: str
    information_gain: float
    estimated_cost: float
    efficiency_score: float                # ΔI / Cost
    priority_rank: int
    recommended_hypothesis: str
    suggested_probes: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class InformationGainScheduler:
    """Prioritizes security exploration based on mathematical information gain"""

    def __init__(self, tested_endpoints: Optional[Set[str]] = None):
        self.tested_endpoints = tested_endpoints or set()

    def score_endpoint(self, ep: Dict[str, Any]) -> Tuple[float, float, str, List[str]]:
        """
        Calculates ΔI (Information Gain) and Cost for an endpoint candidate.
        Returns: (delta_i, cost, recommended_hypothesis, suggested_probes)
        """
        path = ep.get("path") or ep.get("endpoint") or "/"
        method = (ep.get("method") or "GET").upper()
        auth_req = ep.get("auth_required", False) or ep.get("auth", False)
        params = ep.get("parameters") or ep.get("params") or []

        delta_i = 1.0  # Base uncertainty
        cost = 2.0     # Base request cost

        hypothesis = "RECON_SURFACE_AUDIT"
        probes = ["Baseline response profiling"]

        # Check if already tested
        endpoint_key = f"{method}:{path}"
        if endpoint_key in self.tested_endpoints:
            delta_i *= 0.2  # Already tested, sharply diminish information gain
            return round(delta_i, 2), cost, "REGRESSION_RETEST", ["Verify baseline invariant holds"]

        # 1. BOLA / Object ID in Path
        if _OBJECT_ID_REGEX.search(path):
            delta_i += 3.5
            hypothesis = "BOLA_OBJECT_LEVEL_AUTHORIZATION"
            probes = [
                "Swap authenticated bearer token with Tenant B context",
                "Mutate numerical/UUID identifier and observe response diff"
            ]

        # 2. Authenticated Endpoints
        if auth_req:
            delta_i += 2.5
            if hypothesis == "RECON_SURFACE_AUDIT":
                hypothesis = "BROKEN_AUTHENTICATION_OR_ACCESS_CONTROL"
                probes = ["Replay unauthenticated request to verify 401/403 barrier"]

        # 3. State-Mutating Methods
        if method in ("POST", "PUT", "DELETE", "PATCH"):
            delta_i += 2.0
            cost += 1.0  # Mutation requests carry slightly higher cost
            if "BOLA" in hypothesis:
                hypothesis = "BOLA_PRIVILEGE_MUTATION"
                probes.append("Attempt state mutation under unprivileged identity")

        # 4. Injection-Prone Parameters
        param_names = [p if isinstance(p, str) else p.get("name", "") for p in params]
        matched_injectable = [p for p in param_names if p.lower() in _INJECTION_PARAM_NAMES]
        if matched_injectable:
            delta_i += 3.0
            hypothesis = f"SQLI_PARAMETER_INJECTION (param={matched_injectable[0]})"
            probes = [
                f"Inject arithmetic nonce into parameter {matched_injectable[0]} (e.g. 41+1 vs 41+2)",
                "Evaluate reflection against database syntax error patterns"
            ]

        return round(delta_i, 2), round(cost, 2), hypothesis, probes

    def schedule_inspection(self, endpoints: List[Dict[str, Any]], asset: str = "api.target.local") -> List[ScheduledInspectionTarget]:
        """
        Calculates Information-Gain Score for all candidate endpoints and returns
        a ranked queue sorted by highest efficiency score (ΔI / Cost).
        """
        candidates: List[ScheduledInspectionTarget] = []

        for idx, ep in enumerate(endpoints):
            path = ep.get("path") or ep.get("endpoint") or "/"
            method = (ep.get("method") or "GET").upper()
            delta_i, cost, hyp, probes = self.score_endpoint(ep)
            efficiency = round(delta_i / max(cost, 0.5), 3)

            target_id = f"tgt_{idx:03d}_{method}_{path.replace('/', '_').strip('_')}"
            candidates.append(ScheduledInspectionTarget(
                target_id=target_id,
                path=path,
                method=method,
                asset=asset,
                information_gain=delta_i,
                estimated_cost=cost,
                efficiency_score=efficiency,
                priority_rank=0,  # Will be assigned after sorting
                recommended_hypothesis=hyp,
                suggested_probes=probes,
            ))

        # Sort descending by efficiency score
        candidates.sort(key=lambda x: x.efficiency_score, reverse=True)

        # Assign priority rank (1 = Highest Priority)
        for rank, c in enumerate(candidates, 1):
            c.priority_rank = rank

        return candidates
