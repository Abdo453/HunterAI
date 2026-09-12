"""
HunterAI Agent Runtime: Master Agentic Scaffolding Harness
==========================================================
The core agentic runtime providing the Claude-style scaffolding:
- Multi-step tool loop with dynamic continuation
- Context Manager with sliding window token budgeting
- Persistent working memory (.agent/ directory)
- Hierarchical Hypothesis Tree
- MCP-style Tool Registry
- Skeptical Self-Critique Validator to eliminate false positives
- Seamless support for Model Council / AIModelRouter
"""
from __future__ import annotations

import time
import json
import logging
from typing import Dict, List, Optional, Any, Callable, Coroutine

from hunter_ai.runtime.hypothesis_tree import HypothesisTree, HypothesisStatus, HypothesisNode
from hunter_ai.runtime.working_memory import PersistentWorkingMemory
from hunter_ai.runtime.tool_registry import ToolRegistry, build_default_tool_registry
from hunter_ai.runtime.self_critique import SelfCritiqueValidator, CritiqueStatus
from hunter_ai.runtime.scientific_engine import SecurityResearchOS
from hunter_ai.context.compressor import ContextCompressor

logger = logging.getLogger("hunter_ai.agent_runtime")


class AgentRuntime:
    """
    Master Agentic Runtime for HunterAI.
    Coordinates the autonomous observe-think-hypothesize-test-critique loop.
    """

    def __init__(
        self,
        agent_dir: str = ".agent",
        tool_registry: Optional[ToolRegistry] = None,
        model_invoker: Optional[Callable[[Dict[str, Any]], Coroutine[Any, Any, Dict[str, Any]]]] = None,
        event_callback: Optional[Callable[[Dict[str, Any]], Coroutine[Any, Any, None]]] = None
    ):
        self.memory = PersistentWorkingMemory(agent_dir=agent_dir)
        self.tools = tool_registry or build_default_tool_registry(memory_ref=self.memory)
        self.critique = SelfCritiqueValidator()
        self.model_invoker = model_invoker
        self.event_cb = event_callback

    async def _emit_event(self, event_type: str, data: Dict[str, Any]):
        if self.event_cb:
            try:
                await self.event_cb({"event": event_type, "timestamp": time.time(), **data})
            except Exception as e:
                logger.debug(f"Event callback error: {e}")

    async def run_mission(
        self,
        target_url: str,
        initial_params: Optional[List[str]] = None,
        max_steps: int = 15
    ) -> Dict[str, Any]:
        """
        Executes a full autonomous research mission on a given target.
        """
        t0 = time.time()
        logger.info(f"[*] Starting HunterAI Agent Runtime mission on {target_url} (max_steps={max_steps})")

        # 1. Initialize or load mission state
        state = self.memory.get_state()
        prev_target = state.get("target")
        is_new_target = (prev_target != target_url)

        self.sros = SecurityResearchOS(target_domain=target_url)
        self.sros.coverage.record_discovered_endpoint(target_url, initial_params)

        state["target"] = target_url
        state["status"] = "ACTIVE"
        state["max_steps"] = max_steps
        if is_new_target:
            state["current_step"] = 0
        self.memory.update_state(**state)

        # 2. Load or seed Hypothesis Tree
        if is_new_target:
            tree = HypothesisTree()
            self._seed_initial_hypotheses(tree, target_url, initial_params)
            self.memory.save_hypotheses(tree)
        else:
            tree = self.memory.load_hypotheses()
            if not tree.get_all_nodes() or not tree.get_active_frontier():
                self._seed_initial_hypotheses(tree, target_url, initial_params)
                self.memory.save_hypotheses(tree)

        await self._emit_event("mission_started", {"target": target_url, "hypotheses_count": len(tree.get_all_nodes())})
        self.memory.append_mission_log(f"Mission started against `{target_url}`. Seeded {len(tree.get_all_nodes())} initial hypotheses.")

        # 3. Autonomous Execution Loop
        step_count = state.get("current_step", 0)
        while step_count < max_steps:
            step_count += 1
            self.memory.update_state(current_step=step_count)

            frontier = tree.get_active_frontier()
            if not frontier:
                logger.info("[AgentRuntime] No more active hypotheses in frontier. Mission complete.")
                break

            current_hypothesis = frontier[0]
            self.memory.update_state(current_focus_endpoint=current_hypothesis.target_endpoint)
            self.sros.coverage.record_tested(
                current_hypothesis.target_endpoint,
                param=current_hypothesis.param_name,
                vector=current_hypothesis.category
            )

            logger.info(f"[Step {step_count}/{max_steps}] Testing {current_hypothesis.id} ({current_hypothesis.category}) on {current_hypothesis.target_endpoint}")
            await self._emit_event("step_start", {
                "step": step_count,
                "hypothesis_id": current_hypothesis.id,
                "category": current_hypothesis.category,
                "confidence": current_hypothesis.confidence
            })

            # Execute reasoning step
            action_result = await self._execute_hypothesis_step(current_hypothesis, tree)

            # Check if candidate finding was discovered
            if action_result.get("candidate_finding"):
                await self._process_candidate_finding(action_result["candidate_finding"], current_hypothesis, tree)

            # Persist state after each step
            self.memory.save_hypotheses(tree)

            # Short-circuit if high-severity verified finding achieved objective
            findings = self.memory.get_findings()
            if any(f.get("confidence", 0) >= 0.85 for f in findings):
                logger.info("[AgentRuntime] High-confidence confirmed vulnerability achieved!")
                break

        # 4. Finalize Mission
        duration = round(time.time() - t0, 2)
        findings = self.memory.get_findings()
        self.memory.update_state(status="COMPLETED")
        self.memory.append_mission_log(f"Mission completed in {duration}s. Total verified findings: {len(findings)}.")

        return {
            "target": target_url,
            "status": "COMPLETED",
            "duration_seconds": duration,
            "steps_executed": step_count,
            "hypotheses_tested": len(tree.get_all_nodes()),
            "findings_count": len(findings),
            "findings": findings,
            "mission_dna": self.sros.to_dna_summary(tree)
        }

    def _seed_initial_hypotheses(self, tree: HypothesisTree, target_url: str, params: Optional[List[str]]):
        """Generates standard seed hypotheses based on attack surface conventions"""
        test_params = params or ["id", "category", "search", "user"]

        for p in test_params:
            # 1. SQL Injection hypothesis
            tree.create_hypothesis(
                category="SQLi",
                variant="boolean_differential",
                title=f"SQL Injection via parameter '{p}'",
                description=f"Parameter '{p}' may be concatenated into a dynamic database query.",
                target_endpoint=target_url,
                param_name=p,
                initial_confidence=0.5,
                next_action="independent_verify"
            )

            # 2. IDOR hypothesis (if parameter looks like an object identifier)
            if p.lower() in ["id", "user", "account", "order"]:
                tree.create_hypothesis(
                    category="IDOR",
                    variant="object_ownership",
                    title=f"Insecure Direct Object Reference on '{p}'",
                    description=f"Changing '{p}' may expose resources of other users without authorization checks.",
                    target_endpoint=target_url,
                    param_name=p,
                    initial_confidence=0.45,
                    next_action="http_probe"
                )

    async def _execute_hypothesis_step(self, hypothesis: HypothesisNode, tree: HypothesisTree) -> Dict[str, Any]:
        """
        Executes a targeted test corresponding to the active hypothesis.
        """
        tree.update_status(hypothesis.id, HypothesisStatus.TESTING)

        if hypothesis.category == "SQLi":
            # Execute 3-way differential verification
            tool_args = {
                "target_url": hypothesis.target_endpoint,
                "param_name": hypothesis.param_name or "id",
                "vuln_type": "sqli"
            }
            res = await self.tools.execute("independent_verify", tool_args)
            output = res.get("output", {})

            if output.get("verified", False):
                hypothesis.add_evidence_for("Differential 3-way response confirmed SQL behavior.", confidence_boost=0.35)
                hypothesis.record_test("independent_verify", "3-way boolean probe", str(output.get("reason")), "SUCCESS")
                return {
                    "candidate_finding": {
                        "type": "SQLi",
                        "endpoint": hypothesis.target_endpoint,
                        "param_name": hypothesis.param_name,
                        "claimed_evidence": {
                            "boolean_differential": True,
                            "probe_status": output.get("probe_status", 200),
                            "control_status": output.get("control_status", 200),
                            "diff_ratio": output.get("diff_ratio", 0)
                        }
                    }
                }
            else:
                hypothesis.add_evidence_against("No differential behavior between 1=1 and 1=2.", confidence_penalty=0.3)
                hypothesis.record_test("independent_verify", "3-way boolean probe", str(output.get("reason")), "NEGATIVE")
                if hypothesis.confidence < 0.2:
                    tree.update_status(hypothesis.id, HypothesisStatus.REFUTED)
                return {"result": "negative"}

        # Default fallback for other hypothesis categories
        baseline_probe = await self.tools.execute("http_probe", {"url": hypothesis.target_endpoint})
        hypothesis.record_test("http_probe", "baseline", "HTTP baseline probe recorded", "INFO")
        tree.update_status(hypothesis.id, HypothesisStatus.INCONCLUSIVE)
        return {"result": "inconclusive"}

    async def _process_candidate_finding(
        self,
        candidate: Dict[str, Any],
        hypothesis: HypothesisNode,
        tree: HypothesisTree
    ):
        """
        Passes the candidate finding through the Self-Critique Validator.
        """
        verdict = self.critique.challenge_finding(
            vuln_type=candidate["type"],
            endpoint=candidate["endpoint"],
            param_name=candidate["param_name"],
            claimed_evidence=candidate.get("claimed_evidence", {})
        )

        logger.info(f"[SelfCritique] Verdict for {candidate['type']}: {verdict.status.value} (Confidence: {verdict.confidence})")
        self.memory.record_decision(
            rationale=f"Self-critique evaluation of candidate {candidate['type']}: {verdict.reasoning}",
            action="challenge_finding",
            parameters=verdict.to_dict()
        )

        if verdict.status == CritiqueStatus.CONFIRMED:
            tree.update_status(hypothesis.id, HypothesisStatus.CONFIRMED)
            hypothesis.add_evidence_for(f"Passed adversarial self-critique: {verdict.reasoning}", confidence_boost=0.2)
            
            finding_record = {
                "vulnerability": candidate["type"],
                "endpoint": candidate["endpoint"],
                "parameter": candidate["param_name"],
                "confidence": verdict.confidence,
                "confirmed_facts": verdict.confirmed_facts,
                "refuted_explanations": verdict.refuted_explanations,
                "reasoning": verdict.reasoning,
                "timestamp": time.time()
            }
            self.memory.record_finding(finding_record)
            self.memory.append_mission_log(f"🎉 **CONFIRMED {candidate['type']}** on `{candidate['endpoint']}` (param: `{candidate['param_name']}`) — {verdict.reasoning}")
            await self._emit_event("finding_confirmed", finding_record)

        elif verdict.status == CritiqueStatus.REFUTED:
            tree.update_status(hypothesis.id, HypothesisStatus.REFUTED)
            hypothesis.add_evidence_against(f"Refuted by self-critique: {verdict.reasoning}")
            self.memory.record_failed_test(
                test_name=candidate["type"],
                payload="probe",
                endpoint=candidate["endpoint"],
                failure_reason=verdict.reasoning,
                alternative_action=verdict.recommended_test or "Prune vector"
            )

        else: # NEEDS_MORE_EVIDENCE
            hypothesis.alternative_explanations.extend(verdict.alternative_explanations)
            hypothesis.next_verification_action = verdict.recommended_test
            logger.info(f"[SelfCritique] Recommended follow-up: {verdict.recommended_test}")
