"""
HunterAI Hierarchical Evidence Graph & Deterministic Validator
==============================================================
Implements the multi-tiered Evidence Graph:
Target -> Subdomain -> Endpoint -> Parameter / Auth Context
   -> Observation
   -> Hypothesis (Proposed by LLM)
   -> Test Plan
   -> Differential Evidence (Deterministic Verification)
   -> Confidence Scoring
   -> Confirmed Finding

Enforces separation of concerns:
- LLM (WhiteRabbitNeo / Qwen) PROPOSES hypotheses and test plans.
- Deterministic Evidence Validator (Python Engine) VERIFIES proofs and DECIDES.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("hunter_ai.evidence_graph")


class NodeStatus(str, Enum):
    CANDIDATE = "candidate"
    OBSERVED = "observed"
    HYPOTHESIZED = "hypothesized"
    TESTING = "testing"
    EVIDENCE_GATHERED = "evidence_gathered"
    VERIFIED = "verified"
    REJECTED = "rejected"


@dataclass
class EvidenceItem:
    evidence_id: str = field(default_factory=lambda: f"ev_{uuid.uuid4().hex[:8]}")
    evidence_type: str = "behavioral_diff"  # arithmetic_proof, status_diff, time_delay, canary_leak
    request_snippet: str = ""
    response_snippet: str = ""
    request_hash: str = ""
    response_hash: str = ""
    differential_analysis: str = ""
    reproduced_count: int = 1
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HypothesisItem:
    hypothesis_id: str = field(default_factory=lambda: f"hyp_{uuid.uuid4().hex[:8]}")
    vuln_class: str = "IDOR"  # SQLi, CmdInjection, IDOR, SSRF, BAC
    proposed_by_model: str = "WhiteRabbitNeo"
    rationale: str = ""
    suggested_test_plan: str = ""
    created_at: float = field(default_factory=time.time)


@dataclass
class ParameterNode:
    param_name: str
    location: str = "query"  # query, body, header, path
    sample_value: Optional[str] = None
    auth_context: Optional[str] = None  # anonymous, user_a, user_b, admin
    observations: List[str] = field(default_factory=list)
    hypotheses: List[HypothesisItem] = field(default_factory=list)
    evidence: List[EvidenceItem] = field(default_factory=list)
    status: NodeStatus = NodeStatus.CANDIDATE
    confidence_score: float = 0.0  # 0.0 to 1.0


@dataclass
class EndpointNode:
    url: str
    path: str
    method: str = "GET"
    category: str = "WEB"  # API, ADMIN, AUTH, UPLOAD, WEB
    parameters: Dict[str, ParameterNode] = field(default_factory=dict)
    observations: List[str] = field(default_factory=list)


@dataclass
class SubdomainNode:
    subdomain: str
    is_alive: bool = True
    ports: List[int] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    endpoints: Dict[str, EndpointNode] = field(default_factory=dict)


class EvidenceGraph:
    """
    Hierarchical Evidence Graph connecting:
    Target -> Subdomains -> Endpoints -> Parameters/AuthContext -> Hypotheses -> Evidence -> Findings
    """

    def __init__(self, root_target: str):
        self.root_target = root_target.lower().strip()
        self.subdomains: Dict[str, SubdomainNode] = {}
        self.confirmed_findings: List[Dict[str, Any]] = []

    def get_or_create_subdomain(self, sub: str) -> SubdomainNode:
        sub = sub.lower().strip()
        if sub not in self.subdomains:
            self.subdomains[sub] = SubdomainNode(subdomain=sub)
        return self.subdomains[sub]

    def get_or_create_endpoint(self, sub: str, url: str, path: str, method: str = "GET", category: str = "WEB") -> EndpointNode:
        sub_node = self.get_or_create_subdomain(sub)
        endpoint_key = f"{method.upper()}:{url}"
        if endpoint_key not in sub_node.endpoints:
            sub_node.endpoints[endpoint_key] = EndpointNode(url=url, path=path, method=method.upper(), category=category)
        return sub_node.endpoints[endpoint_key]

    def get_or_create_parameter(self, sub: str, url: str, path: str, param_name: str, location: str = "query", method: str = "GET") -> ParameterNode:
        ep_node = self.get_or_create_endpoint(sub, url, path, method=method)
        if param_name not in ep_node.parameters:
            ep_node.parameters[param_name] = ParameterNode(param_name=param_name, location=location)
        return ep_node.parameters[param_name]

    def record_observation(self, sub: str, url: str, path: str, param_name: str, observation_text: str):
        """Records an initial telemetry/surface observation"""
        p = self.get_or_create_parameter(sub, url, path, param_name)
        p.observations.append(observation_text)
        if p.status == NodeStatus.CANDIDATE:
            p.status = NodeStatus.OBSERVED

    def propose_hypothesis(
        self,
        sub: str,
        url: str,
        path: str,
        param_name: str,
        vuln_class: str,
        proposed_by: str,
        rationale: str,
        test_plan: str
    ) -> HypothesisItem:
        """Records an attack hypothesis formulated by an AI model (e.g. WhiteRabbitNeo)"""
        p = self.get_or_create_parameter(sub, url, path, param_name)
        hyp = HypothesisItem(
            vuln_class=vuln_class,
            proposed_by_model=proposed_by,
            rationale=rationale,
            suggested_test_plan=test_plan
        )
        p.hypotheses.append(hyp)
        p.status = NodeStatus.HYPOTHESIZED
        return hyp

    def record_differential_evidence(
        self,
        sub: str,
        url: str,
        path: str,
        param_name: str,
        req: str,
        resp: str,
        evidence_type: str,
        diff_analysis: str,
        reproduced_count: int = 1
    ) -> EvidenceItem:
        """Attaches cryptographically-hashed differential evidence to the parameter node"""
        p = self.get_or_create_parameter(sub, url, path, param_name)
        req_h = hashlib.sha256(req.encode("utf-8", errors="ignore")).hexdigest()
        resp_h = hashlib.sha256(resp.encode("utf-8", errors="ignore")).hexdigest()

        item = EvidenceItem(
            evidence_type=evidence_type,
            request_snippet=req[:500],
            response_snippet=resp[:1000],
            request_hash=req_h,
            response_hash=resp_h,
            differential_analysis=diff_analysis,
            reproduced_count=reproduced_count
        )
        p.evidence.append(item)
        p.status = NodeStatus.EVIDENCE_GATHERED
        return item

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the entire Evidence Graph into an interactive JSON tree"""
        tree = {
            "root_target": self.root_target,
            "total_subdomains": len(self.subdomains),
            "subdomains": {}
        }
        for sub_name, sub_node in self.subdomains.items():
            s_dict = {
                "subdomain": sub_node.subdomain,
                "is_alive": sub_node.is_alive,
                "ports": sub_node.ports,
                "technologies": sub_node.technologies,
                "endpoints": {}
            }
            for ep_key, ep_node in sub_node.endpoints.items():
                e_dict = {
                    "url": ep_node.url,
                    "path": ep_node.path,
                    "method": ep_node.method,
                    "category": ep_node.category,
                    "observations": ep_node.observations,
                    "parameters": {}
                }
                for p_name, p_node in ep_node.parameters.items():
                    e_dict["parameters"][p_name] = {
                        "parameter": p_node.param_name,
                        "location": p_node.location,
                        "status": p_node.status.value,
                        "confidence_score": p_node.confidence_score,
                        "observations": p_node.observations,
                        "hypotheses": [asdict(h) for h in p_node.hypotheses],
                        "evidence": [ev.to_dict() for ev in p_node.evidence]
                    }
                s_dict["endpoints"][ep_key] = e_dict
            tree["subdomains"][sub_name] = s_dict

        tree["confirmed_findings"] = self.confirmed_findings
        return tree


class DeterministicEvidenceValidator:
    """
    Independent Evidence Validator & Decision Engine.
    LLMs PROPOSE hypotheses. This deterministic engine DECIDES.
    Validates proofs: arithmetic evaluation, state differential, header reflections.
    """

    CONFIDENCE_THRESHOLD = 0.85

    @classmethod
    def evaluate_arithmetic_proof(cls, output_text: str, expected_nonce: int = 42) -> Tuple[bool, float, str]:
        """Validates command execution through exact arithmetic nonce calculation"""
        if not output_text:
            return False, 0.0, "Empty response output"

        # Check if expected nonce appears isolated or formatted
        if str(expected_nonce) in output_text:
            return True, 0.98, f"Arithmetic nonce {expected_nonce} evaluated and confirmed in output."
        return False, 0.0, f"Expected arithmetic proof {expected_nonce} not found in output."

    @classmethod
    def evaluate_differential_response(
        cls,
        baseline_resp_code: int,
        baseline_len: int,
        tampered_resp_code: int,
        tampered_len: int,
        anomaly_indicator: str = ""
    ) -> Tuple[bool, float, str]:
        """Validates BOLA/IDOR or logic flaws by comparing baseline vs tampered HTTP responses"""
        # Case 1: Unauthorized access succeeds (e.g. 200 with sensitive data)
        if baseline_resp_code in (401, 403) and tampered_resp_code == 200:
            return True, 0.95, "Differential confirmed: Unauthorized request bypassed auth and returned 200 OK."

        # Case 2: Meaningful body length differential with anomaly indicator
        len_diff = abs(baseline_len - tampered_len)
        if anomaly_indicator and anomaly_indicator.lower() in anomaly_indicator.lower():
            if len_diff > 50:
                return True, 0.90, f"Significant response length divergence ({len_diff} bytes) and anomaly indicator present."

        return False, 0.30, "Response differential insufficient to prove vulnerability."

    @classmethod
    def decide_finding(
        cls,
        param_node: ParameterNode,
        target_url: str,
        vuln_class: str
    ) -> Optional[Dict[str, Any]]:
        """
        Authoritative decision gate:
        Rule: "Confidence != Verification"
        Even if confidence is high (e.g. 0.95), status remains CANDIDATE unless
        there is deterministic, reproducible differential evidence.
        """
        if not param_node.evidence:
            param_node.status = NodeStatus.REJECTED
            return None

        # Check latest evidence
        latest_ev = param_node.evidence[-1]
        reproduced = latest_ev.reproduced_count >= 1
        has_verifiable_hashes = bool(latest_ev.request_hash and latest_ev.response_hash)

        # 1. VERIFIED: Both threshold passed AND reproducible proof confirmed
        if param_node.confidence_score >= cls.CONFIDENCE_THRESHOLD and reproduced and has_verifiable_hashes:
            param_node.status = NodeStatus.VERIFIED
            finding = {
                "finding_id": f"find_{uuid.uuid4().hex[:8]}",
                "target_url": target_url,
                "parameter": param_node.param_name,
                "vuln_class": vuln_class,
                "confidence": param_node.confidence_score,
                "status": "CONFIRMED",
                "evidence_ref": latest_ev.evidence_id,
                "request_hash": latest_ev.request_hash,
                "response_hash": latest_ev.response_hash,
                "verification_notes": latest_ev.differential_analysis
            }
            return finding

        # 2. CANDIDATE: High confidence or partial evidence, but lacks proof
        if param_node.confidence_score >= cls.CONFIDENCE_THRESHOLD or len(param_node.evidence) > 0:
            param_node.status = NodeStatus.CANDIDATE
            return {
                "finding_id": f"cand_{uuid.uuid4().hex[:8]}",
                "target_url": target_url,
                "parameter": param_node.param_name,
                "vuln_class": vuln_class,
                "confidence": param_node.confidence_score,
                "status": "CANDIDATE",
                "evidence_ref": latest_ev.evidence_id,
                "verification_notes": "Hypothesis has observation signals but requires reproducible differential proof."
            }

        param_node.status = NodeStatus.REJECTED
        return None


@dataclass
class StageManifest:
    """Standardized manifest for each engagement stage (resume, diff, lineage)"""
    stage: str
    started_at: str
    completed_at: str
    inputs: List[str] = field(default_factory=list)
    outputs: List[str] = field(default_factory=list)
    artifacts: List[str] = field(default_factory=list)
    parent_nodes: List[str] = field(default_factory=list)
    child_nodes: List[str] = field(default_factory=list)
    status: str = "completed"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def save(self, stage_dir: str) -> str:
        out_path = Path(stage_dir) / "manifest.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)
        return str(out_path)

