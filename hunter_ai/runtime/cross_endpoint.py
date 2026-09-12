"""
HunterAI Runtime: Cross-Endpoint Correlator & Assumption Mapper
===============================================================
Moves beyond single-endpoint testing by analyzing the entire application graph:
1. Cross-Endpoint Correlation: Traces identifiers (IDs, tokens, hashes) created
   in one endpoint and consumed by other endpoints.
2. Developer Assumption Mapping: Identifies implicit architectural assumptions
   (e.g., trust in client inputs, predictable sequences, hidden parameters)
   and formulates surgical hypothesis tests.
"""
from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any, Set, Tuple

logger = logging.getLogger("hunter_ai.cross_endpoint")


class AssumptionKind(str, Enum):
    TRUST_IN_CLIENT_IDENTITY = "TRUST_IN_CLIENT_IDENTITY"     # Assumes client won't tamper with user/tenant ID
    NUMERIC_PREDICTABILITY = "NUMERIC_PREDICTABILITY"         # Assumes sequential integer IDs are safe
    UNENFORCED_STATE_CHAIN = "UNENFORCED_STATE_CHAIN"         # Assumes frontend always calls steps in order
    TYPE_STRICTNESS_CONFUSION = "TYPE_STRICTNESS_CONFUSION"   # Assumes param is always string/int (vulnerable to array/JSON injection)
    HIDDEN_PRIVILEGE_FLAG = "HIDDEN_PRIVILEGE_FLAG"           # Assumes admin/role parameters won't be guessed


@dataclass
class EndpointSignature:
    """The analytical profile of an observed API endpoint"""
    endpoint: str
    method: str
    input_params: Set[str] = field(default_factory=set)
    observed_output_fields: Set[str] = field(default_factory=set)
    produces_identifiers: Set[str] = field(default_factory=set)
    consumes_identifiers: Set[str] = field(default_factory=set)


@dataclass
class DataFlowLink:
    """A verified relationship connecting two distinct endpoints"""
    source_endpoint: str
    target_endpoint: str
    shared_identifier: str
    relation_type: str          # e.g., "CREATES_AND_CONSUMES", "LEAKS_AND_ACCEPTS"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DeveloperAssumption:
    """An implicit architectural assumption identified in an endpoint"""
    endpoint: str
    parameter_or_field: str
    assumption_kind: AssumptionKind
    rationale: str
    recommended_surgical_test: str
    confidence: float = 0.8

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["assumption_kind"] = self.assumption_kind.value
        return d


class CrossEndpointCorrelator:
    """
    Analyzes multi-endpoint data flows and maps developer assumptions.
    """

    def __init__(self):
        self._endpoints: Dict[str, EndpointSignature] = {}
        self._links: List[DataFlowLink] = []
        self._assumptions: List[DeveloperAssumption] = []

    def record_endpoint(
        self,
        endpoint: str,
        method: str = "GET",
        input_params: Optional[List[str]] = None,
        output_fields: Optional[List[str]] = None
    ) -> EndpointSignature:
        """Records an endpoint signature and extracts potential identifier tags"""
        in_params = set(input_params or [])
        out_fields = set(output_fields or [])

        # Detect identifiers (e.g. id, user_id, order_id, uuid, token)
        produces = {f for f in out_fields if any(tag in f.lower() for tag in ["id", "key", "token", "uuid", "num"])}
        consumes = {p for p in in_params if any(tag in p.lower() for tag in ["id", "key", "token", "uuid", "num"])}

        sig = EndpointSignature(
            endpoint=endpoint,
            method=method,
            input_params=in_params,
            observed_output_fields=out_fields,
            produces_identifiers=produces,
            consumes_identifiers=consumes
        )
        self._endpoints[endpoint] = sig
        self._update_correlations()
        self._analyze_assumptions_for_endpoint(sig)
        return sig

    def _update_correlations(self):
        """Discovers data-flow links between endpoints sharing common identifiers"""
        self._links.clear()
        for ep_src, sig_src in self._endpoints.items():
            for ep_dst, sig_dst in self._endpoints.items():
                if ep_src == ep_dst:
                    continue
                shared = sig_src.produces_identifiers.intersection(sig_dst.consumes_identifiers)
                for identifier in shared:
                    self._links.append(DataFlowLink(
                        source_endpoint=ep_src,
                        target_endpoint=ep_dst,
                        shared_identifier=identifier,
                        relation_type="CREATES_AND_CONSUMES"
                    ))

    def _analyze_assumptions_for_endpoint(self, sig: EndpointSignature):
        """Deduces potential security assumptions based on parameter signatures"""
        for param in sig.input_params:
            p_lower = param.lower()

            # 1. Sequential integer assumptions
            if p_lower in ["id", "order_id", "user_id", "account_id"]:
                self._assumptions.append(DeveloperAssumption(
                    endpoint=sig.endpoint,
                    parameter_or_field=param,
                    assumption_kind=AssumptionKind.NUMERIC_PREDICTABILITY,
                    rationale=f"Parameter '{param}' appears to be an object identifier that may follow sequential indexing.",
                    recommended_surgical_test=f"Test incremented/decremented values of '{param}' with alternative session token."
                ))

            # 2. Client-controlled identity / role assumptions
            if p_lower in ["role", "is_admin", "admin", "privilege", "tenant"]:
                self._assumptions.append(DeveloperAssumption(
                    endpoint=sig.endpoint,
                    parameter_or_field=param,
                    assumption_kind=AssumptionKind.HIDDEN_PRIVILEGE_FLAG,
                    rationale=f"Parameter '{param}' directly controls authorization context from the client side.",
                    recommended_surgical_test=f"Inject elevated role ('admin', true, 1) in '{param}' to verify server-side authorization enforcement."
                ))

            # 3. Type confusion assumptions
            if any(tag in p_lower for tag in ["filter", "query", "search", "data", "json"]):
                self._assumptions.append(DeveloperAssumption(
                    endpoint=sig.endpoint,
                    parameter_or_field=param,
                    assumption_kind=AssumptionKind.TYPE_STRICTNESS_CONFUSION,
                    rationale=f"Parameter '{param}' accepts composite or structured data.",
                    recommended_surgical_test=f"Submit '{param}' as JSON object or array to inspect parsing exceptions."
                ))

    def get_correlations(self) -> List[DataFlowLink]:
        return list(self._links)

    def get_assumptions(self) -> List[DeveloperAssumption]:
        return list(self._assumptions)

    def generate_cross_endpoint_hypotheses(self) -> List[Dict[str, Any]]:
        """
        Synthesizes high-impact hypotheses by combining cross-endpoint data links
        with developer assumption models.
        """
        hypotheses = []
        for link in self._links:
            hypotheses.append({
                "title": f"BOLA / Insecure Reference between {link.source_endpoint} and {link.target_endpoint}",
                "category": "IDOR",
                "variant": "cross_endpoint_leak",
                "source_endpoint": link.source_endpoint,
                "target_endpoint": link.target_endpoint,
                "shared_identifier": link.shared_identifier,
                "description": (
                    f"Identifier '{link.shared_identifier}' produced by '{link.source_endpoint}' "
                    f"can be fed into '{link.target_endpoint}' under a different user session "
                    f"to test if ownership validation is bypassed."
                ),
                "recommended_action": "cross_tenant_swap"
            })
        return hypotheses
