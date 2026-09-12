"""
HunterAI Runtime: Scientific Security Research OS (SROS)
=========================================================
Elevates HunterAI from a tool-calling agent to an autonomous scientific security researcher:
1. Application Twin & Dead-Zone Coverage Tracker
2. Active Learning Experiment Manager (Information Gain x Confidence / Cost)
3. Causal Graph & Counterfactual Reasoning
4. Next Best Action (NBA) Autonomous Decision Engine
"""
from __future__ import annotations

import time
import math
import logging
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any, Set, Tuple

from hunter_ai.runtime.world_model import ApplicationWorldModel, RoleLevel
from hunter_ai.runtime.hypothesis_tree import HypothesisTree, HypothesisNode, HypothesisStatus
from hunter_ai.runtime.invariant_engine import InvariantEngine, InvariantViolation

logger = logging.getLogger("hunter_ai.scientific_engine")


class ActionKind(str, Enum):
    PROBE_DEAD_ZONE = "PROBE_DEAD_ZONE"
    TEST_HIGH_CONFIDENCE_HYPOTHESIS = "TEST_HIGH_CONFIDENCE_HYPOTHESIS"
    DISCRIMINATE_COMPETING_HYPOTHESES = "DISCRIMINATE_COMPETING_HYPOTHESES"
    CHALLENGE_CANDIDATE_FINDING = "CHALLENGE_CANDIDATE_FINDING"
    REGRESSION_TEST = "REGRESSION_TEST"
    TERMINATE_MISSION = "TERMINATE_MISSION"


@dataclass
class ScientificExperiment:
    """A formal scientific experiment testing a hypothesis counterfactually"""
    id: str
    hypothesis_id: str
    target_endpoint: str
    param_name: Optional[str]
    probe_kind: str             # e.g., "BOOLEAN_PAIR", "CROSS_TENANT_SWAP", "STEP_OMISSION"
    baseline_request: Dict[str, Any]
    mutated_request: Dict[str, Any]
    counterfactual_check: str   # What should happen if the variable is NOT altered?
    expected_information_gain: float = 0.5
    cost: float = 1.0
    result: Optional[Dict[str, Any]] = None
    outcome_interpretation: Optional[str] = None
    executed_at: Optional[float] = None

    def calculate_utility(self, hypothesis_confidence: float) -> float:
        """Active learning utility: (InfoGain * Confidence) / Cost"""
        return (self.expected_information_gain * hypothesis_confidence) / max(0.1, self.cost)


class CoverageTracker:
    """
    Monitors coverage across endpoints, parameters, roles, and attack vectors.
    Identifies the 'Dead Zones' that have never been explored.
    """

    def __init__(self):
        self.discovered_endpoints: Set[str] = set()
        self.tested_endpoints: Set[str] = set()
        self.discovered_params: Set[str] = set()
        self.tested_params: Set[str] = set()
        self.tested_roles: Set[RoleLevel] = set()
        self.tested_vectors: Set[str] = set()

    def record_discovered_endpoint(self, endpoint: str, params: Optional[List[str]] = None):
        self.discovered_endpoints.add(endpoint)
        if params:
            for p in params:
                self.discovered_params.add(f"{endpoint}::{p}")

    def record_tested(self, endpoint: str, param: Optional[str] = None, role: Optional[RoleLevel] = None, vector: Optional[str] = None):
        self.tested_endpoints.add(endpoint)
        if param:
            self.tested_params.add(f"{endpoint}::{param}")
        if role:
            self.tested_roles.add(role)
        if vector:
            self.tested_vectors.add(vector)

    def get_dead_zones(self) -> Dict[str, List[str]]:
        """Returns untested endpoints and parameters"""
        untested_endpoints = list(self.discovered_endpoints - self.tested_endpoints)
        untested_params = list(self.discovered_params - self.tested_params)
        return {
            "untested_endpoints": untested_endpoints,
            "untested_params": untested_params
        }

    def get_metrics(self) -> Dict[str, Any]:
        ep_cov = len(self.tested_endpoints) / max(1, len(self.discovered_endpoints)) * 100
        param_cov = len(self.tested_params) / max(1, len(self.discovered_params)) * 100
        return {
            "endpoint_coverage_pct": round(ep_cov, 1),
            "param_coverage_pct": round(param_cov, 1),
            "total_discovered_endpoints": len(self.discovered_endpoints),
            "total_tested_endpoints": len(self.tested_endpoints),
            "dead_zones_count": len(self.discovered_endpoints - self.tested_endpoints)
        }


@dataclass
class CausalEdge:
    source_fact: str
    target_fact: str
    relation: str               # "CAUSES", "ENABLES", "EXPOSES"


class CausalGraph:
    """
    Distinguishes correlation from causation and maps attack chains.
    Node A (Weak Auth) --ENABLES--> Node B (Object Read) --EXPOSES--> Node C (PII Data)
    """

    def __init__(self):
        self.nodes: Set[str] = set()
        self.edges: List[CausalEdge] = []

    def add_causal_relation(self, source: str, target: str, relation: str = "ENABLES"):
        self.nodes.add(source)
        self.nodes.add(target)
        self.edges.append(CausalEdge(source_fact=source, target_fact=target, relation=relation))

    def get_chains(self) -> List[List[str]]:
        """Returns linear paths through the causal graph representing exploit chains"""
        adjacency: Dict[str, List[str]] = {n: [] for n in self.nodes}
        for e in self.edges:
            adjacency[e.source_fact].append(e.target_fact)

        chains = []
        for start_node in self.nodes:
            if not any(e.target_fact == start_node for e in self.edges): # root node
                path = [start_node]
                curr = start_node
                while adjacency[curr]:
                    curr = adjacency[curr][0]
                    path.append(curr)
                if len(path) > 1:
                    chains.append(path)
        return chains


@dataclass
class NextBestAction:
    """The computed optimal next step for the autonomous researcher"""
    action_kind: ActionKind
    target_endpoint: str
    target_param: Optional[str]
    utility_score: float
    rationale: str
    experiment: Optional[ScientificExperiment] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_kind": self.action_kind.value,
            "target_endpoint": self.target_endpoint,
            "target_param": self.target_param,
            "utility_score": round(self.utility_score, 3),
            "rationale": self.rationale,
            "experiment_id": self.experiment.id if self.experiment else None
        }


class SecurityResearchOS:
    """
    The Master Cognitive Brain orchestrating the Scientific Research Method:
    - Calculates Information Gain & Active Learning utility.
    - Resolves Dead Zones in coverage.
    - Decides the Next Best Action without brute-force guessing.
    """

    def __init__(self, target_domain: str = ""):
        self.target_domain = target_domain
        self.world_model = ApplicationWorldModel(target_domain=target_domain)
        self.coverage = CoverageTracker()
        self.causal_graph = CausalGraph()
        self.invariants = InvariantEngine()
        self._experiments: Dict[str, ScientificExperiment] = {}
        self._exp_counter = 1

    def create_experiment(
        self,
        hypothesis_id: str,
        endpoint: str,
        param_name: Optional[str],
        probe_kind: str,
        counterfactual_check: str,
        expected_info_gain: float = 0.6,
        cost: float = 1.0
    ) -> ScientificExperiment:
        exp_id = f"EXP-{self._exp_counter:03d}"
        self._exp_counter += 1

        exp = ScientificExperiment(
            id=exp_id,
            hypothesis_id=hypothesis_id,
            target_endpoint=endpoint,
            param_name=param_name,
            probe_kind=probe_kind,
            baseline_request={"url": endpoint, "method": "GET"},
            mutated_request={"url": endpoint, "method": "GET", "probe": probe_kind},
            counterfactual_check=counterfactual_check,
            expected_information_gain=expected_info_gain,
            cost=cost
        )
        self._experiments[exp_id] = exp
        return exp

    def compute_next_best_action(self, hypothesis_tree: HypothesisTree) -> NextBestAction:
        """
        Determines the mathematically optimal Next Best Action (NBA)
        by balancing Active Learning utility with Dead-Zone exploration.
        """
        frontier = hypothesis_tree.get_active_frontier(min_confidence=0.2)

        # 1. If high-confidence hypotheses exist, test the one with the highest active learning utility
        if frontier:
            best_node = frontier[0]
            exp = self.create_experiment(
                hypothesis_id=best_node.id,
                endpoint=best_node.target_endpoint,
                param_name=best_node.param_name,
                probe_kind=best_node.variant,
                counterfactual_check="Does response revert to baseline when probe variable is inverted?",
                expected_info_gain=0.8,
                cost=1.0
            )
            utility = exp.calculate_utility(best_node.confidence)
            return NextBestAction(
                action_kind=ActionKind.TEST_HIGH_CONFIDENCE_HYPOTHESIS,
                target_endpoint=best_node.target_endpoint,
                target_param=best_node.param_name,
                utility_score=utility,
                rationale=f"Highest active learning utility ({utility:.2f}) on hypothesis '{best_node.title}' to confirm or refute vulnerability.",
                experiment=exp
            )

        # 2. If no active frontier, explore Dead Zones (untested endpoints/params)
        dead_zones = self.coverage.get_dead_zones()
        if dead_zones["untested_endpoints"]:
            target_ep = dead_zones["untested_endpoints"][0]
            return NextBestAction(
                action_kind=ActionKind.PROBE_DEAD_ZONE,
                target_endpoint=target_ep,
                target_param=None,
                utility_score=0.45,
                rationale=f"Exploring untested dead-zone endpoint '{target_ep}' to seed new application surface and invariants."
            )

        # 3. Mission complete
        return NextBestAction(
            action_kind=ActionKind.TERMINATE_MISSION,
            target_endpoint="",
            target_param=None,
            utility_score=0.0,
            rationale="All attack surface covered and all active hypotheses resolved."
        )

    def to_dna_summary(self, hypothesis_tree: HypothesisTree) -> Dict[str, Any]:
        """
        Exports the complete Mission DNA specified in the architectural vision.
        """
        nba = self.compute_next_best_action(hypothesis_tree)
        return {
            "target": self.target_domain,
            "coverage_metrics": self.coverage.get_metrics(),
            "world_model": self.world_model.to_compact_summary(),
            "active_hypotheses_count": len(hypothesis_tree.get_active_frontier()),
            "causal_chains": self.causal_graph.get_chains(),
            "experiments_conducted": len(self._experiments),
            "invariant_violations": len(self.invariants.get_violations()),
            "next_best_action": nba.to_dict()
        }
