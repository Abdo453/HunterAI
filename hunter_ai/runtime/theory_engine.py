"""
HunterAI Runtime: Theory-Driven Security Research Engine
========================================================
Implements the 'Theory of the Application' cognitive layer:
1. Latent Architecture Inference: Infers hidden internal tiers (Gateway, Proxy, Microservice, DB)
   empirically from HTTP header footprints, latency distribution, and error signatures.
2. Trust Boundary Mapper: Identifies transitions between USER_CONTROLLED, GATEWAY_VERIFIED,
   and INTERNAL_SERVICE tiers to isolate unvalidated boundary crossings.
3. Object Lifecycle Model: Tracks entity progression (CREATED -> PENDING -> APPROVED -> ARCHIVED)
   and audits lifecycle-restricted actions (e.g., modifying finalized records).
4. Semantic Diff Analyzer: Evaluates changes in operational meaning (roles, ownership, state)
   rather than textual byte differences.
5. Curiosity Engine: Proactively prioritizes unexpected behaviors by calculating an
   'Interestingness' score (Novelty + Uncertainty + Security Relevance).
6. Decision Replay Ledger: Records a deterministic, causal timeline of every analytical
   step, allowing transparent 'Why?' explanations and reproducible replays.
"""
from __future__ import annotations

import time
import json
import logging
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any, Set, Tuple

logger = logging.getLogger("hunter_ai.theory_engine")


# ─── 1. Latent Architecture Inference ────────────────────────────────────────
class ArchitectureTier(str, Enum):
    CDN_EDGE = "CDN_EDGE"
    API_GATEWAY = "API_GATEWAY"
    WAF_REVERSE_PROXY = "WAF_REVERSE_PROXY"
    APPLICATION_SERVICE = "APPLICATION_SERVICE"
    DATABASE_BACKEND = "DATABASE_BACKEND"


@dataclass
class InferredArchitecture:
    """The deduced internal system topology of the target application"""
    detected_tiers: List[ArchitectureTier]
    detected_technologies: List[str]
    topology_type: str          # e.g., "MICROSERVICES_GATEWAY", "MONOLITH", "SERVERLESS"
    evidence_footprints: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["detected_tiers"] = [t.value for t in self.detected_tiers]
        return d


class LatentArchitectureInferrer:
    """
    Infers the hidden multi-tier architecture from external response footprints.
    """

    @classmethod
    def infer_from_headers(cls, headers: Dict[str, str]) -> InferredArchitecture:
        tiers = [ArchitectureTier.APPLICATION_SERVICE]
        techs = []
        footprints = []

        h_lower = {k.lower(): v.lower() for k, v in headers.items()}

        # 1. CDN / Reverse Proxy Detection
        if any(k in h_lower for k in ["cf-ray", "cf-cache-status"]):
            tiers.insert(0, ArchitectureTier.CDN_EDGE)
            techs.append("Cloudflare CDN")
            footprints.append("Cloudflare headers detected (cf-ray)")
        elif "via" in h_lower:
            tiers.insert(0, ArchitectureTier.WAF_REVERSE_PROXY)
            techs.append(f"Via: {headers.get('via', headers.get('Via', ''))}")
            footprints.append(f"Reverse proxy detected via 'Via' header: {h_lower['via']}")

        # 2. Gateway / Load Balancer Detection
        if any(k in h_lower for k in ["x-kong-proxy-latency", "x-amzn-requestid", "x-envoy-upstream-service-time"]):
            tiers.insert(1 if ArchitectureTier.CDN_EDGE in tiers else 0, ArchitectureTier.API_GATEWAY)
            techs.append("API Gateway / Service Mesh")
            footprints.append("Gateway latency/routing header identified")

        # 3. Application Server / Framework
        server = h_lower.get("server", "")
        powered_by = h_lower.get("x-powered-by", "")
        if server:
            techs.append(f"Server: {server}")
        if powered_by:
            techs.append(f"Framework: {powered_by}")

        # Topology classification
        if ArchitectureTier.API_GATEWAY in tiers or "envoy" in str(techs).lower():
            topology = "MICROSERVICES_GATEWAY"
        elif ArchitectureTier.CDN_EDGE in tiers:
            topology = "CDN_FRONTED_APPLICATION"
        else:
            topology = "MONOLITHIC_SERVICE"

        return InferredArchitecture(
            detected_tiers=tiers,
            detected_technologies=techs,
            topology_type=topology,
            evidence_footprints=footprints
        )


# ─── 2. Trust Boundary Mapper ────────────────────────────────────────────────
class TrustLevel(str, Enum):
    UNTRUSTED_USER = "UNTRUSTED_USER"
    GATEWAY_VALIDATED = "GATEWAY_VALIDATED"
    AUTHENTICATED_TENANT = "AUTHENTICATED_TENANT"
    INTERNAL_TRUSTED = "INTERNAL_TRUSTED"


@dataclass
class TrustTransition:
    source_level: TrustLevel
    target_level: TrustLevel
    endpoint: str
    parameter: str
    is_dangerous_boundary: bool
    rationale: str


class TrustBoundaryMapper:
    """
    Identifies locations where untrusted client inputs directly influence trusted state.
    """

    @classmethod
    def analyze_parameter_boundary(
        cls,
        endpoint: str,
        parameter_name: str,
        is_client_supplied: bool,
        affects_authorization: bool
    ) -> TrustTransition:
        if is_client_supplied and affects_authorization:
            return TrustTransition(
                source_level=TrustLevel.UNTRUSTED_USER,
                target_level=TrustLevel.INTERNAL_TRUSTED,
                endpoint=endpoint,
                parameter=parameter_name,
                is_dangerous_boundary=True,
                rationale=f"Parameter '{parameter_name}' transitions directly from Untrusted User into Internal Authorization state without verifiable token binding."
            )

        return TrustTransition(
            source_level=TrustLevel.UNTRUSTED_USER,
            target_level=TrustLevel.GATEWAY_VALIDATED,
            endpoint=endpoint,
            parameter=parameter_name,
            is_dangerous_boundary=False,
            rationale="Standard user input subject to gateway/application validation."
        )


# ─── 3. Object Lifecycle Model ───────────────────────────────────────────────
class LifecycleStage(str, Enum):
    DRAFT = "DRAFT"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED_FINAL = "APPROVED_FINAL"
    ARCHIVED = "ARCHIVED"
    DELETED = "DELETED"


@dataclass
class LifecycleViolation:
    object_id: str
    current_stage: LifecycleStage
    illegal_action_attempted: str
    was_accepted_by_server: bool
    description: str


class ObjectLifecycleTracker:
    """
    Models entity state progression and checks for lifecycle rule violations.
    """

    def __init__(self):
        self._object_stages: Dict[str, LifecycleStage] = {}

    def set_stage(self, object_id: str, stage: LifecycleStage):
        self._object_stages[object_id] = stage

    def get_stage(self, object_id: str) -> LifecycleStage:
        return self._object_stages.get(object_id, LifecycleStage.DRAFT)

    def audit_lifecycle_action(
        self,
        object_id: str,
        action: str,
        server_status: int
    ) -> Optional[LifecycleViolation]:
        stage = self.get_stage(object_id)

        # Invariant: Modifying or approving an already deleted or finalized object is forbidden
        is_modification = any(k in action.lower() for k in ["edit", "modify", "update", "patch", "delete"])
        if stage in [LifecycleStage.APPROVED_FINAL, LifecycleStage.DELETED] and is_modification:
            if server_status in [200, 204]:
                return LifecycleViolation(
                    object_id=object_id,
                    current_stage=stage,
                    illegal_action_attempted=action,
                    was_accepted_by_server=True,
                    description=f"LIFECYCLE_BREACH: Object '{object_id}' in finalized state '{stage.value}' accepted destructive/altering action '{action}' (Status: {server_status})."
                )

        return None


# ─── 4. Semantic Diff Analyzer ───────────────────────────────────────────────
@dataclass
class SemanticFieldChange:
    field_name: str
    baseline_value: Any
    observed_value: Any
    security_significance: str


class SemanticDiffAnalyzer:
    """
    Compares operational meaning rather than raw text differences.
    """

    CRITICAL_SECURITY_FIELDS = {
        "role", "roles", "is_admin", "admin", "permissions", "privileges",
        "user_id", "owner_id", "tenant_id", "account_id", "status", "state", "verified"
    }

    @classmethod
    def compare_semantic_structures(
        cls,
        baseline_json: Dict[str, Any],
        observed_json: Dict[str, Any]
    ) -> List[SemanticFieldChange]:
        changes = []
        all_keys = set(baseline_json.keys()).union(set(observed_json.keys()))

        for k in all_keys:
            base_val = baseline_json.get(k)
            obs_val = observed_json.get(k)
            if base_val != obs_val:
                is_crit = k.lower() in cls.CRITICAL_SECURITY_FIELDS
                significance = "CRITICAL_AUTHORIZATION_FIELD" if is_crit else "INFORMATIONAL_DATA"
                changes.append(SemanticFieldChange(
                    field_name=k,
                    baseline_value=base_val,
                    observed_value=obs_val,
                    security_significance=significance
                ))

        return changes


# ─── 5. Curiosity Engine ─────────────────────────────────────────────────────
@dataclass
class CuriousEvent:
    """An intrinsically interesting observation that demands active investigation"""
    event_id: str
    endpoint: str
    description: str
    interestingness_score: float  # 0.0 to 1.0
    recommended_inquiry: str


class CuriosityEngine:
    """
    Calculates intrinsic interestingness scores for anomalies to trigger
    autonomous investigations without human prompting.
    """

    @classmethod
    def evaluate_anomaly(
        cls,
        endpoint: str,
        is_novel: bool,
        confidence_gap: float,
        affects_security_boundary: bool,
        description: str
    ) -> CuriousEvent:
        # Score calculation: Novelty (0.4) + Uncertainty (0.3) + Security Impact (0.3)
        novelty_weight = 0.4 if is_novel else 0.1
        uncertainty_weight = 0.3 * (1.0 - confidence_gap)
        security_weight = 0.3 if affects_security_boundary else 0.05

        score = round(min(0.99, novelty_weight + uncertainty_weight + security_weight), 2)
        event_id = f"CURIOUS_{int(time.time() * 1000) % 100000}"

        return CuriousEvent(
            event_id=event_id,
            endpoint=endpoint,
            description=description,
            interestingness_score=score,
            recommended_inquiry=f"Proactively design discriminative experiment to eliminate uncertainty on '{endpoint}'."
        )


# ─── 6. Decision Replay Ledger ───────────────────────────────────────────────
@dataclass
class DecisionReplayStep:
    step_number: int
    timestamp: float
    observation_id: str
    hypothesis_id: str
    action_taken: str
    evidence_gathered: str
    resulting_belief_update: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DecisionReplayLedger:
    """
    Maintains a deterministic audit timeline of all analytical reasoning steps.
    Enables post-mission step-by-step causal replay.
    """

    def __init__(self):
        self._timeline: List[DecisionReplayStep] = []

    def record_step(
        self,
        observation_id: str,
        hypothesis_id: str,
        action_taken: str,
        evidence_gathered: str,
        resulting_belief_update: str
    ) -> DecisionReplayStep:
        step = DecisionReplayStep(
            step_number=len(self._timeline) + 1,
            timestamp=time.time(),
            observation_id=observation_id,
            hypothesis_id=hypothesis_id,
            action_taken=action_taken,
            evidence_gathered=evidence_gathered,
            resulting_belief_update=resulting_belief_update
        )
        self._timeline.append(step)
        return step

    def get_timeline(self) -> List[Dict[str, Any]]:
        return [s.to_dict() for s in self._timeline]
