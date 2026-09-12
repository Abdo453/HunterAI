"""
Graph-Driven Hypothesis Generator
Inspects the Causal Attack Graph topology and automatically derives deductive hypotheses
linking endpoints, parameters, and services to specific vulnerability classes.
"""
import re
import logging
from typing import List

from core.attack_graph.graph import CausalAttackGraph
from core.attack_graph.nodes import NodeType
from core.hypotheses.tracker import TrackedHypothesis, HypothesisState

log = logging.getLogger("core.hypotheses.generator")


class GraphHypothesisGenerator:
    """
    مولد الفرضيات الطوبولوجي:
    يستنتج الفرضيات الأمنية مباشرة من الرسم البياني السببي للهجوم
    """

    # Heuristic regexes
    _BOLA_ID_PATTERN = re.compile(r"/(?:users|invoices|accounts|orders|items|files|documents)/(?:\{[a-zA-Z0-9_\-]+\}|:[a-zA-Z0-9_\-]+|[0-9a-fA-F\-]{4,}|\d+)", re.I)
    _BFLA_ADMIN_PATTERN = re.compile(r"/(admin|manager|internal|dashboard|settings|super|audit)", re.I)
    _SQLI_PARAMS = {"q", "search", "filter", "query", "order", "sort", "id", "category", "limit"}
    _SSRF_PARAMS = {"url", "dest", "redirect", "target", "webhook", "callback", "feed", "fetch", "proxy"}
    _MASS_ASSIGN_PARAMS = {"role", "is_admin", "admin", "permissions", "group", "tier", "plan"}

    def __init__(self, graph: CausalAttackGraph):
        self.graph = graph

    def generate_hypotheses_from_graph(self) -> List[TrackedHypothesis]:
        """
        توليد الفرضيات استناداً إلى عقد الرسم البياني
        """
        hypotheses: List[TrackedHypothesis] = []
        endpoints = self.graph.find_nodes_by_type(NodeType.ENDPOINT)

        for ep in endpoints:
            path = ep.label
            props = ep.properties
            method = props.get("method", "GET").upper()
            params = set(props.get("parameters", []))
            auth_required = props.get("auth_required", False)

            # 1. BOLA / IDOR Pattern
            if self._BOLA_ID_PATTERN.search(path) or any(p.lower().endswith("id") or p.lower() in ["id", "user_id", "account_id", "order_id", "invoice_id"] for p in params):
                hyp = TrackedHypothesis(
                    title=f"Potential BOLA authorization bypass on {path}",
                    vuln_type="BOLA",
                    target_node_id=ep.id,
                    target_endpoint=path,
                    prior_probability=0.65 if auth_required else 0.45,
                    required_evidence_types=["BEHAVIOR_DIFF", "AUTH_ANOMALY"]
                )
                hypotheses.append(hyp)

            # 2. BFLA Pattern
            if self._BFLA_ADMIN_PATTERN.search(path):
                hyp = TrackedHypothesis(
                    title=f"Potential BFLA privilege escalation on {path}",
                    vuln_type="BFLA",
                    target_node_id=ep.id,
                    target_endpoint=path,
                    prior_probability=0.60,
                    required_evidence_types=["AUTH_ANOMALY", "BEHAVIOR_DIFF"]
                )
                hypotheses.append(hyp)

            # 3. SQLi Pattern
            if params.intersection(self._SQLI_PARAMS):
                matched = list(params.intersection(self._SQLI_PARAMS))
                hyp = TrackedHypothesis(
                    title=f"Potential SQLi on parameters {matched} at {path}",
                    vuln_type="SQLi",
                    target_node_id=ep.id,
                    target_endpoint=path,
                    prior_probability=0.55,
                    required_evidence_types=["ERROR_DISCLOSURE", "TIMING_LEAK"]
                )
                hypotheses.append(hyp)

            # 4. SSRF Pattern
            if params.intersection(self._SSRF_PARAMS):
                matched = list(params.intersection(self._SSRF_PARAMS))
                hyp = TrackedHypothesis(
                    title=f"Potential SSRF on external URL parameters {matched} at {path}",
                    vuln_type="SSRF",
                    target_node_id=ep.id,
                    target_endpoint=path,
                    prior_probability=0.60,
                    required_evidence_types=["BEHAVIOR_DIFF", "STATUS_CODE"]
                )
                hypotheses.append(hyp)

            # 5. Mass Assignment Pattern
            if method in ["POST", "PUT", "PATCH"] and (params.intersection(self._MASS_ASSIGN_PARAMS) or "/profile" in path or "/user" in path):
                hyp = TrackedHypothesis(
                    title=f"Potential Mass Assignment on {method} {path}",
                    vuln_type="Mass_Assignment",
                    target_node_id=ep.id,
                    target_endpoint=path,
                    prior_probability=0.50,
                    required_evidence_types=["BEHAVIOR_DIFF"]
                )
                hypotheses.append(hyp)

        log.info(f"[GraphHypothesisGenerator] Generated {len(hypotheses)} hypotheses from {len(endpoints)} endpoints.")
        return hypotheses
