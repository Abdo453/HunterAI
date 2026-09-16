"""
HunterAI V27.0 - Autonomous Experiment Generator
=================================================
Synthesizes formal ExperimentContract objects from the Application State Machine,
Multi-Tenant Identity Matrix, and Workflow Transition Graph.

Every generated ExperimentContract mandates:
  1. Hypothesis ID (causal question being investigated)
  2. State Precondition (application state prerequisite)
  3. Mutation Plan (concrete parameter & header changes)
  4. Invariant Assertion (formal rule that should hold)
  5. Positive Success Observables (what proves the exploit)
  6. Negative Observables (CRITICAL: exact conditions that conclusively DISPROVE
     the hypothesis, such as 403 Forbidden or "Unauthorized")
  7. Risk Budget & Scope Constraints
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from core.burp_gateway.experiment_contract import ExperimentContract
from core.reasoning.identity_matrix import AccessOutcome, IdentityMatrixEngine
from core.reasoning.state_machine_engine import ApplicationStateMachineEngine
from core.reasoning.workflow_graph import CandidateTransitionType, WorkflowGraphEngine

logger = logging.getLogger("hunter_ai.experiment_generator")


class AutonomousExperimentGenerator:
    """
    Generates deterministic, hypothesis-driven security experiments from
    formal behavioral graphs (State Machine, Identity Matrix, Workflow Graph).
    """

    def __init__(
        self,
        state_engine: ApplicationStateMachineEngine,
        identity_engine: IdentityMatrixEngine,
        workflow_engine: WorkflowGraphEngine,
        allowed_scope: Optional[List[str]] = None,
    ):
        self.state_engine = state_engine
        self.identity_engine = identity_engine
        self.workflow_engine = workflow_engine
        self.allowed_scope = allowed_scope or ["target.local"]

    def is_in_scope(self, url_or_host: str) -> bool:
        """Verifies if an endpoint or host falls within the authorized experiment scope."""
        if not self.allowed_scope:
            return True
        for scope_entry in self.allowed_scope:
            if scope_entry.lower() in url_or_host.lower():
                return True
        return False

    def generate_identity_experiments(self) -> List[ExperimentContract]:
        """
        Synthesizes access-control experiments (BOLA/IDOR, Privilege Escalation, Cross-Tenant)
        from untested cells in the Multi-Tenant Identity Matrix.
        """
        candidates = self.identity_engine.generate_candidate_experiments()
        contracts: List[ExperimentContract] = []

        for cand in candidates:
            cand_id = cand["candidate_id"]
            category = cand["category"]
            actor = cand["actor"]
            target_res_id = cand["target_resource_id"]
            owner = cand["resource_owner"]

            endpoint = f"/api/resources/{target_res_id}"
            if not self.is_in_scope(endpoint) and not self.is_in_scope(self.state_engine.target_domain):
                continue

            contract_id = f"exp_id_{cand_id}_{uuid.uuid4().hex[:6]}"
            hypothesis_id = f"hyp_authz_{category.lower()}_{actor['principal_id']}_on_{target_res_id}"

            contract = ExperimentContract(
                experiment_id=contract_id,
                hypothesis_id=hypothesis_id,
                source_request_id=f"src_req_{uuid.uuid4().hex[:8]}",
                identity_context=actor["principal_id"],
                target_endpoint=endpoint,
                http_method="GET",
                mutation_plan={
                    "resource_id": target_res_id,
                    "target_owner_id": owner["principal_id"],
                    "actor_id": actor["principal_id"],
                    "actor_tenant": actor.get("tenant_id"),
                    "owner_tenant": owner.get("tenant_id"),
                    "headers": actor.get("auth_headers", {}),
                    "token": actor.get("session_token"),
                },
                expected_observation=f"Actor '{actor['principal_id']}' receives unauthorized access to '{target_res_id}' owned by '{owner['principal_id']}'.",
                success_conditions={
                    "status_code": 200,
                    "unauthorized_data_present": True,
                    "tenant_isolation_breached": actor.get("tenant_id") != owner.get("tenant_id"),
                },
                negative_observables={
                    "status_codes": [401, 403, 404],
                    "response_patterns": ["unauthorized", "forbidden", "access denied", "not found", "permission denied"],
                    "disproof_verdict": "BOUNDARY_ENFORCED",
                },
                expected_invariants=[
                    f"INV-AUTHZ-BOUNDARY: Actor '{actor['principal_id']}' MUST NOT read Resource '{target_res_id}'",
                    f"INV-TENANT-ISOLATION: Tenant '{actor.get('tenant_id')}' MUST NOT access Tenant '{owner.get('tenant_id')}'"
                ],
                state_precondition=self.state_engine.current_state_id,
                risk_tier="MEDIUM_RISK" if category == "VERTICAL_PRIVILEGE_ESCALATION" else "LOW_RISK",
                risk_budget=0.4,
                category=category,
                candidate_id=cand_id,
                scope_requirements=self.allowed_scope,
            )
            contracts.append(contract)

        logger.info(f"[EXPERIMENT GENERATOR] Synthesized {len(contracts)} Identity Matrix Experiment Contracts.")
        return contracts

    def generate_workflow_experiments(self) -> List[ExperimentContract]:
        """
        Synthesizes sequence violation experiments (Step Skipping, Premature Invocation,
        Double Execution, Tamper After Completion) from the Workflow Graph.
        """
        contracts: List[ExperimentContract] = []

        for wf_name in self.workflow_engine.workflows.keys():
            cand_transitions = self.workflow_engine.generate_candidate_transitions(wf_name)
            for cand in cand_transitions:
                endpoint = cand.mutation_recipe.get("target_endpoint", "/api/workflow")
                if not self.is_in_scope(endpoint) and not self.is_in_scope(self.state_engine.target_domain):
                    continue

                contract_id = f"exp_wf_{cand.transition_id}_{uuid.uuid4().hex[:6]}"
                hypothesis_id = f"hyp_wf_{cand.transition_type.value.lower()}_{cand.source_step_id}_to_{cand.target_step_id}"

                risk_tier = "HIGH_RISK" if cand.transition_type == CandidateTransitionType.DOUBLE_EXECUTION else "MEDIUM_RISK"
                risk_budget = 0.8 if risk_tier == "HIGH_RISK" else 0.5

                contract = ExperimentContract(
                    experiment_id=contract_id,
                    hypothesis_id=hypothesis_id,
                    source_request_id=f"src_req_{uuid.uuid4().hex[:8]}",
                    identity_context=self.state_engine.states.get(self.state_engine.current_state_id, self.state_engine.states["state_guest"]).identity_context,
                    target_endpoint=endpoint,
                    http_method=cand.mutation_recipe.get("method", "POST"),
                    mutation_plan=cand.mutation_recipe,
                    expected_observation=f"Workflow accepts invalid sequence transition ({cand.transition_type.value}): {cand.suggested_hypothesis}",
                    success_conditions={
                        "status_code_range": [200, 299],
                        "state_advanced": True,
                    },
                    negative_observables={
                        "status_codes": [400, 409, 412, 422],
                        "response_patterns": [
                            "precondition failed", "invalid state", "sequence error",
                            "already processed", "order conflict", "bad request"
                        ],
                        "disproof_verdict": "SEQUENCE_INVARIANT_ENFORCED",
                    },
                    expected_invariants=[
                        f"INV-WORKFLOW-INTEGRITY: Cannot execute '{cand.target_step_id}' without '{cand.violated_precondition}'"
                    ],
                    state_precondition=cand.source_step_id,
                    risk_tier=risk_tier,
                    risk_budget=risk_budget,
                    category=cand.transition_type.value,
                    candidate_id=cand.transition_id,
                    scope_requirements=self.allowed_scope,
                )
                contracts.append(contract)

        logger.info(f"[EXPERIMENT GENERATOR] Synthesized {len(contracts)} Workflow Experiment Contracts.")
        return contracts

    def generate_state_jump_experiments(self) -> List[ExperimentContract]:
        """
        Synthesizes illegal state jump experiments (e.g., GUEST directly to ORDER_COMPLETED,
        REVOKED session executing sensitive operations).
        """
        contracts: List[ExperimentContract] = []
        known_states = list(self.state_engine.states.keys())

        for from_s in known_states:
            for to_s in known_states:
                if from_s == to_s:
                    continue
                jump_analysis = self.state_engine.detect_illegal_state_jump(from_s, to_s, "/api/checkout/pay")
                if jump_analysis:
                    contract_id = f"exp_state_jump_{from_s}_to_{to_s}_{uuid.uuid4().hex[:6]}"
                    hypothesis_id = f"hyp_jump_{from_s}_to_{to_s}"

                    contract = ExperimentContract(
                        experiment_id=contract_id,
                        hypothesis_id=hypothesis_id,
                        source_request_id=f"src_req_{uuid.uuid4().hex[:8]}",
                        identity_context=self.state_engine.states[from_s].identity_context,
                        target_endpoint=jump_analysis["action_route"],
                        http_method="POST",
                        mutation_plan={
                            "from_state": from_s,
                            "to_state": to_s,
                            "rule_violation": jump_analysis["rule"],
                        },
                        expected_observation=f"Application allows illegal state jump from '{from_s}' to '{to_s}'.",
                        success_conditions={
                            "status_code_range": [200, 299],
                            "state_jump_permitted": True,
                        },
                        negative_observables={
                            "status_codes": [400, 401, 403, 409],
                            "response_patterns": ["unauthorized", "invalid state", "forbidden", "cart empty"],
                            "disproof_verdict": "STATE_MACHINE_GUARD_ENFORCED",
                        },
                        expected_invariants=[jump_analysis["rule"]],
                        state_precondition=from_s,
                        risk_tier="MEDIUM_RISK",
                        risk_budget=0.5,
                        category="ILLEGAL_STATE_JUMP",
                        candidate_id=f"jump_{from_s}_to_{to_s}",
                        scope_requirements=self.allowed_scope,
                    )
                    contracts.append(contract)

        logger.info(f"[EXPERIMENT GENERATOR] Synthesized {len(contracts)} State Jump Experiment Contracts.")
        return contracts

    def synthesize_all_candidate_contracts(self) -> List[ExperimentContract]:
        """
        Aggregates and deduplicates all candidate experiment contracts across
        identity, workflow, and state models.
        """
        all_contracts: List[ExperimentContract] = []
        all_contracts.extend(self.generate_identity_experiments())
        all_contracts.extend(self.generate_workflow_experiments())
        all_contracts.extend(self.generate_state_jump_experiments())

        seen: set = set()
        deduped: List[ExperimentContract] = []
        for c in all_contracts:
            key = (c.target_endpoint, c.identity_context, c.category, c.candidate_id)
            if key not in seen:
                seen.add(key)
                deduped.append(c)

        logger.info(f"[EXPERIMENT GENERATOR] Total unique synthesized contracts: {len(deduped)}")
        return deduped
