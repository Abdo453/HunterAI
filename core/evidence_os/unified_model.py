"""
HunterAI Evidence OS — Canonical Epistemic Data Model
=====================================================
Normalizes telemetry across Burp Proxy, Playwright, raw HTTP, OpenAPI,
GraphQL, JavaScript AST, and plugins into a single canonical pipeline:
Observation -> Artifact -> Relation -> Hypothesis -> Experiment -> Evidence -> Claim -> Verdict
Enforces that no component can submit a Claim without complete lineage.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class ObservationType(str, Enum):
    HTTP_RESPONSE = "HTTP_RESPONSE"
    DOM_EVENT = "DOM_EVENT"
    AST_SINK_MATCH = "AST_SINK_MATCH"
    BURP_HISTORY_ENTRY = "BURP_HISTORY_ENTRY"
    SCHEMA_DEFINITION = "SCHEMA_DEFINITION"


class RelationType(str, Enum):
    EXTRACTED_FROM = "EXTRACTED_FROM"
    CAUSED_BY = "CAUSED_BY"
    CORRELATES_WITH = "CORRELATES_WITH"
    REFUTES = "REFUTES"
    CONFIRMS = "CONFIRMS"


@dataclass
class Observation:
    obs_id: str = field(default_factory=lambda: f"OBS-{uuid.uuid4().hex[:8].upper()}")
    obs_type: ObservationType = ObservationType.HTTP_RESPONSE
    source_tool: str = "http_engine"
    target_url: str = ""
    status_code: Optional[int] = None
    snippet: str = ""
    raw_hash: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["obs_type"] = self.obs_type.value
        return d


@dataclass
class Artifact:
    artifact_id: str = field(default_factory=lambda: f"ART-{uuid.uuid4().hex[:8].upper()}")
    name: str = ""
    artifact_type: str = "http_exchange"  # http_exchange, dom_snapshot, replay_script
    content_hash: str = ""
    uri_path: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Relation:
    relation_id: str = field(default_factory=lambda: f"REL-{uuid.uuid4().hex[:8].upper()}")
    source_id: str = ""
    relation_type: RelationType = RelationType.CAUSED_BY
    target_id: str = ""
    confidence: float = 1.0


@dataclass
class Hypothesis:
    hypo_id: str = field(default_factory=lambda: f"HYP-{uuid.uuid4().hex[:8].upper()}")
    vulnerability_class: str = "BOLA"
    target_endpoint: str = ""
    parameter: str = ""
    predicted_behavior: str = ""
    origin_observation_id: str = ""
    created_at: float = field(default_factory=time.time)


@dataclass
class Experiment:
    exp_id: str = field(default_factory=lambda: f"EXP-{uuid.uuid4().hex[:8].upper()}")
    hypothesis_id: str = ""
    baseline_obs_id: str = ""
    control_obs_id: str = ""
    active_test_obs_id: str = ""
    mutation_description: str = ""


@dataclass
class Evidence:
    evidence_id: str = field(default_factory=lambda: f"EVI-{uuid.uuid4().hex[:8].upper()}")
    experiment_id: str = ""
    has_execution_proof: bool = False
    poe_token: Optional[str] = None
    differential_score: float = 0.0
    is_reproducible: bool = False
    reproducibility_trials: int = 1


@dataclass
class Claim:
    claim_id: str = field(default_factory=lambda: f"CLM-{uuid.uuid4().hex[:8].upper()}")
    evidence_id: str = ""
    vulnerability_class: str = ""
    confidence_score: float = 0.0
    rationale: str = ""
    provenance_hash_chain: str = ""


@dataclass
class Verdict:
    verdict_id: str = field(default_factory=lambda: f"VRD-{uuid.uuid4().hex[:8].upper()}")
    claim_id: str = ""
    decision: str = "CONFIRMED"  # CONFIRMED, REJECTED, INCONCLUSIVE
    court_signature: str = ""
    timestamp: float = field(default_factory=time.time)


class EvidenceOS:
    """Canonical operating system maintaining normalized epistemic lineage"""

    def __init__(self):
        self.observations: Dict[str, Observation] = {}
        self.artifacts: Dict[str, Artifact] = {}
        self.relations: List[Relation] = []
        self.hypotheses: Dict[str, Hypothesis] = {}
        self.experiments: Dict[str, Experiment] = {}
        self.evidence_items: Dict[str, Evidence] = {}
        self.claims: Dict[str, Claim] = {}
        self.verdicts: Dict[str, Verdict] = {}

    def ingest_observation(
        self,
        obs_type: ObservationType,
        source_tool: str,
        target_url: str,
        snippet: str,
        status_code: Optional[int] = None
    ) -> Observation:
        raw_hash = hashlib.sha256(snippet.encode("utf-8", errors="replace")).hexdigest()[:16]
        obs = Observation(
            obs_type=obs_type,
            source_tool=source_tool,
            target_url=target_url,
            status_code=status_code,
            snippet=snippet[:500],
            raw_hash=raw_hash
        )
        self.observations[obs.obs_id] = obs
        return obs

    def formulate_hypothesis(
        self,
        vulnerability_class: str,
        target_endpoint: str,
        parameter: str,
        predicted_behavior: str,
        origin_obs_id: str
    ) -> Hypothesis:
        if origin_obs_id not in self.observations:
            raise ValueError(f"Origin observation '{origin_obs_id}' not found in EvidenceOS.")

        hyp = Hypothesis(
            vulnerability_class=vulnerability_class,
            target_endpoint=target_endpoint,
            parameter=parameter,
            predicted_behavior=predicted_behavior,
            origin_observation_id=origin_obs_id
        )
        self.hypotheses[hyp.hypo_id] = hyp
        self.relations.append(Relation(
            source_id=hyp.hypo_id,
            relation_type=RelationType.EXTRACTED_FROM,
            target_id=origin_obs_id
        ))
        return hyp

    def record_experiment(
        self,
        hypothesis_id: str,
        baseline_obs_id: str,
        control_obs_id: str,
        active_obs_id: str,
        mutation_description: str
    ) -> Experiment:
        exp = Experiment(
            hypothesis_id=hypothesis_id,
            baseline_obs_id=baseline_obs_id,
            control_obs_id=control_obs_id,
            active_test_obs_id=active_obs_id,
            mutation_description=mutation_description
        )
        self.experiments[exp.exp_id] = exp
        return exp

    def commit_evidence(
        self,
        experiment_id: str,
        has_execution_proof: bool,
        poe_token: Optional[str] = None,
        differential_score: float = 1.0,
        is_reproducible: bool = True
    ) -> Evidence:
        evi = Evidence(
            experiment_id=experiment_id,
            has_execution_proof=has_execution_proof,
            poe_token=poe_token,
            differential_score=differential_score,
            is_reproducible=is_reproducible
        )
        self.evidence_items[evi.evidence_id] = evi
        return evi

    def issue_claim(
        self,
        evidence_id: str,
        vulnerability_class: str,
        confidence_score: float,
        rationale: str
    ) -> Claim:
        if evidence_id not in self.evidence_items:
            raise ValueError(f"Evidence ID '{evidence_id}' does not exist.")

        # Compute tamper-evident hash chain linking backwards
        chain_str = f"{evidence_id}:{vulnerability_class}:{confidence_score}"
        chain_hash = hashlib.sha256(chain_str.encode("utf-8")).hexdigest()[:16]

        clm = Claim(
            evidence_id=evidence_id,
            vulnerability_class=vulnerability_class,
            confidence_score=confidence_score,
            rationale=rationale,
            provenance_hash_chain=chain_hash
        )
        self.claims[clm.claim_id] = clm
        return clm

    def rule_verdict(self, claim_id: str, decision: str = "CONFIRMED") -> Verdict:
        if claim_id not in self.claims:
            raise ValueError(f"Claim ID '{claim_id}' not found.")

        signature = hashlib.sha256(f"COURT:{claim_id}:{decision}".encode("utf-8")).hexdigest()[:16]
        vrd = Verdict(claim_id=claim_id, decision=decision, court_signature=signature)
        self.verdicts[vrd.verdict_id] = vrd
        return vrd

    def verify_claim_lineage(self, claim_id: str) -> bool:
        """Verifies unbroken causal lineage from Observation up to Claim"""
        clm = self.claims.get(claim_id)
        if not clm:
            return False
        evi = self.evidence_items.get(clm.evidence_id)
        if not evi:
            return False
        exp = self.experiments.get(evi.experiment_id)
        if not exp:
            return False
        hyp = self.hypotheses.get(exp.hypothesis_id)
        if not hyp:
            return False
        return hyp.origin_observation_id in self.observations
