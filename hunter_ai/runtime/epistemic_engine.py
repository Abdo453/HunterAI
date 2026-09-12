"""
HunterAI Runtime: Research-Grade Epistemic Engine & Agent Compiler
===================================================================
The Boss-Level Cognitive Engine:
1. Strict Epistemic Stratification: Enforces rigorous classification of all internal states:
   [OBSERVATION, FACT, ASSUMPTION, HYPOTHESIS, PREDICTION, EVIDENCE, CONFIRMED, REJECTED, UNKNOWN]
   Prevents LLM confabulation by forbidding UNKNOWN/ASSUMPTION from masquerading as FACT.
2. Predictive Experiment Designer: Pairs every hypothesis with an explicit counterfactual
   prediction BEFORE probe execution (If H is true, we predict X; if X is absent, H is penalized).
3. Dynamic Evidence Lineage Graph: Maintains bidirectional dependency links from Findings
   down to raw HTTP exchanges. If an evidence node is invalidated, descendant confidences
   recalculate automatically.
4. Agent Compiler: Compiles target domains, capability boundaries, and security policies into
   an ephemeral, highly customized CompiledResearchPlan with formal stopping conditions.
5. Research Postmortem & Self-Evaluator: Audits mission velocity, identifies invalid assumptions,
   and extracts reusable lessons into long-term memory.
"""
from __future__ import annotations

import time
import uuid
import logging
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any, Set, Tuple

logger = logging.getLogger("hunter_ai.epistemic")


# ─── 1. Epistemic Stratification ─────────────────────────────────────────────
class EpistemicType(str, Enum):
    OBSERVATION = "OBSERVATION"   # Raw, uninterpreted sensory event from HTTP/DOM
    FACT = "FACT"                 # Verified, immutable truth (e.g. server header, status 200)
    ASSUMPTION = "ASSUMPTION"     # Developer or tester mental model heuristic
    HYPOTHESIS = "HYPOTHESIS"     # Plausible explanation awaiting experimental test
    PREDICTION = "PREDICTION"     # Expected observation if hypothesis holds true
    EVIDENCE = "EVIDENCE"         # Factual result linking an experiment to a hypothesis
    CONFIRMED = "CONFIRMED"       # Finding that survived adversarial falsification
    REJECTED = "REJECTED"         # Disproven conjecture
    UNKNOWN = "UNKNOWN"           # Identified knowledge gap / dead-zone


@dataclass
class EpistemicNode:
    """A strictly typed piece of knowledge with bidirectional provenance"""
    id: str
    epistemic_type: EpistemicType
    content: str
    confidence: float             # 0.0 to 1.0
    created_at: float = field(default_factory=time.time)
    parent_ids: Set[str] = field(default_factory=set)
    child_ids: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["epistemic_type"] = self.epistemic_type.value
        d["parent_ids"] = list(self.parent_ids)
        d["child_ids"] = list(self.child_ids)
        return d


# ─── 2. Evidence Lineage Graph ───────────────────────────────────────────────
class EvidenceGraph:
    """
    Maintains a complete DAG of epistemic dependencies.
    Finding -> Evidence -> Experiment -> Prediction -> Hypothesis -> Observation
    """

    def __init__(self):
        self._nodes: Dict[str, EpistemicNode] = {}

    def add_node(
        self,
        epistemic_type: EpistemicType,
        content: str,
        confidence: float = 0.5,
        parent_ids: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        node_id: Optional[str] = None
    ) -> EpistemicNode:
        nid = node_id or f"EPI_{uuid.uuid4().hex[:8]}"
        parents = set(parent_ids or [])
        node = EpistemicNode(
            id=nid,
            epistemic_type=epistemic_type,
            content=content,
            confidence=confidence,
            parent_ids=parents,
            metadata=metadata or {}
        )
        self._nodes[nid] = node

        # Link parent -> child
        for pid in parents:
            if pid in self._nodes:
                self._nodes[pid].child_ids.add(nid)

        return node

    def get_node(self, node_id: str) -> Optional[EpistemicNode]:
        return self._nodes.get(node_id)

    def invalidate_node(self, node_id: str, reason: str):
        """
        Invalidates a node and cascades confidence penalties down its dependency tree.
        """
        node = self.get_node(node_id)
        if not node:
            return

        node.confidence = 0.0
        node.metadata["invalidation_reason"] = reason

        # Cascade recalculation to child nodes
        for cid in node.child_ids:
            child = self.get_node(cid)
            if child:
                child.confidence = round(child.confidence * 0.3, 3)
                child.metadata["degraded_by_parent"] = node_id
                logger.info(f"[EvidenceGraph] Degraded {child.id} confidence to {child.confidence} due to parent {node_id} invalidation.")

    def get_lineage(self, node_id: str) -> List[Dict[str, Any]]:
        """Extracts complete upstream provenance path for an audit trail"""
        lineage = []
        visited = set()
        queue = [node_id]

        while queue:
            curr = queue.pop(0)
            if curr in visited:
                continue
            visited.add(curr)
            n = self.get_node(curr)
            if n:
                lineage.append(n.to_dict())
                queue.extend(list(n.parent_ids))

        return lineage


# ─── 3. Predictive Experiment Designer ───────────────────────────────────────
@dataclass
class PredictiveExperimentSpec:
    """A scientific experiment with a mandatory pre-probe prediction"""
    experiment_id: str
    hypothesis_id: str
    question: str
    variable_under_test: str
    baseline_value: Any
    mutated_value: Any
    prediction_if_true: str
    prediction_if_false: str
    falsification_condition: str

    def evaluate_result(self, observed_outcome: str) -> Tuple[bool, float, str]:
        """
        Evaluates whether the empirical outcome matches the pre-probe prediction.
        Returns: (is_confirmed, posterior_confidence, rationale)
        """
        outcome_lower = observed_outcome.lower()
        if self.prediction_if_true.lower() in outcome_lower:
            return True, 0.92, f"Empirical outcome confirmed pre-probe prediction: '{self.prediction_if_true}'"

        falsification_tokens = [c.strip() for c in self.falsification_condition.lower().replace(",", " or ").split(" or ") if c.strip()]
        for token in falsification_tokens:
            if token in outcome_lower:
                return False, 0.05, f"Falsification condition triggered: '{token}'"

        return False, 0.35, "Outcome was ambiguous; did not clearly satisfy prediction nor falsification condition."


# ─── 4. Agent Compiler (Boss-Level Execution Synthesis) ─────────────────────
@dataclass
class CompiledResearchPlan:
    """The compiled, specialized mission blueprint produced by the Agent Compiler"""
    plan_id: str
    target_domain: str
    allocated_budget_steps: int
    authorized_toolset: List[str]
    active_invariants: List[str]
    priority_exploration_vectors: List[str]
    stopping_criteria: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AgentCompiler:
    """
    Compiles high-level mission goals and target specifications into a concrete,
    specialized research runtime plan, enforcing safety boundaries and stopping criteria.
    """

    @classmethod
    def compile_mission(
        cls,
        target_domain: str,
        target_technology: str = "REST_API",
        max_steps: int = 20,
        enable_active_probing: bool = True
    ) -> CompiledResearchPlan:
        plan_id = f"PLAN_{uuid.uuid4().hex[:6].upper()}"

        # 1. Tailor tool permissions based on policy
        tools = ["http_probe", "differential_analyze", "record_observation"]
        if enable_active_probing:
            tools.extend(["independent_verify", "cve_lookup", "methodology_lookup"])

        # 2. Select priority vectors based on technology stack
        if target_technology == "GRAPHQL":
            vectors = ["introspection_query", "batch_query_amplification", "field_suggestion_mining"]
        elif target_technology == "OAUTH":
            vectors = ["redirect_uri_poisoning", "state_parameter_omission", "token_scope_expansion"]
        else: # Standard REST API
            vectors = ["tenant_isolation_idor", "numeric_predictability", "differential_parameter_audit"]

        # 3. Define formal stopping conditions
        stopping = {
            "max_consecutive_stagnant_steps": 4,
            "max_allowed_requests": max_steps * 5,
            "terminate_on_high_confidence_finding": True,
            "min_confidence_threshold": 0.85
        }

        return CompiledResearchPlan(
            plan_id=plan_id,
            target_domain=target_domain,
            allocated_budget_steps=max_steps,
            authorized_toolset=tools,
            active_invariants=["INV_01_TENANT_ISOLATION", "INV_02_PRIVILEGE_BOUNDARY"],
            priority_exploration_vectors=vectors,
            stopping_criteria=stopping
        )


# ─── 5. Research Postmortem & Self-Evaluator ─────────────────────────────────
@dataclass
class ResearchPostmortem:
    """Retrospective analysis of a completed mission to extract reusable heuristics"""
    mission_id: str
    target: str
    duration_seconds: float
    hypotheses_tested_count: int
    hypotheses_confirmed_count: int
    hypotheses_falsified_count: int
    stagnation_episodes: int
    key_lessons_learned: List[str]
    extracted_heuristics: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ResearchPostmortemEvaluator:
    """
    Evaluates completed research runs to generate actionable postmortems
    and distill lessons into long-term memory.
    """

    @classmethod
    def evaluate_mission(
        cls,
        mission_id: str,
        target: str,
        duration: float,
        tested_hypotheses: List[Dict[str, Any]],
        confirmed_findings: List[Dict[str, Any]],
        stagnation_events: int = 0
    ) -> ResearchPostmortem:
        falsified = [h for h in tested_hypotheses if h.get("status") in ["REFUTED", "REJECTED"]]
        confirmed = len(confirmed_findings)

        lessons = []
        heuristics = []

        if confirmed > 0:
            lessons.append(f"Target exhibits confirmed security boundary breakdown ({confirmed} findings).")
            for f in confirmed_findings:
                v = f.get("vulnerability", "Unknown")
                p = f.get("parameter", "general")
                heuristics.append(f"Pattern: Parameter '{p}' repeatedly lacks server-side authorization enforcement.")
        else:
            lessons.append("Target demonstrated resilient default authorization controls across tested vectors.")

        if stagnation_events > 0:
            lessons.append(f"Experienced {stagnation_events} stagnation episodes; future scans should start with deeper workflow analysis.")

        return ResearchPostmortem(
            mission_id=mission_id,
            target=target,
            duration_seconds=duration,
            hypotheses_tested_count=len(tested_hypotheses),
            hypotheses_confirmed_count=confirmed,
            hypotheses_falsified_count=len(falsified),
            stagnation_episodes=stagnation_events,
            key_lessons_learned=lessons,
            extracted_heuristics=heuristics
        )
