"""
HunterAI Autonomous Action Loop
===============================
Implements the 7-step autonomous security reasoning loop:
  OBSERVE -> THINK -> PLAN -> ACT -> OBSERVE -> VALIDATE -> DECIDE

Example:
  Browser discovers /api/export
       ↓
  Observation recorded in EvidenceGraph
       ↓
  Qwen analyzes JS / Endpoints
       ↓
  New parameter 'user_id' discovered
       ↓
  WhiteRabbitNeo generates IDOR hypothesis & test plan
       ↓
  PolicyGate verifies target authorization
       ↓
  Controlled test executed via ComputerControl / Browser
       ↓
  Differential response captured
       ↓
  DeterministicEvidenceValidator checks proof (Confidence != Verification)
       ↓
  Confirmed finding OR registered in FailureMemory
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

from core.control_plane.computer_control import ComputerControl, ExecutionRecord
from core.control_plane.policy_gate import ActionCategory, ActionRequest, PolicyGate
from core.decision_core import AttackTrack, DecisionCore, TrackRecommendation
from core.evidence_graph import (
    DeterministicEvidenceValidator,
    EvidenceGraph,
    HypothesisItem,
    NodeStatus,
    ParameterNode,
)
from core.memory.failure_memory import FailureMemory
from hunter_ai.brain.local_triad_agent import LocalTriadAgent

logger = logging.getLogger("hunter_ai.action_loop")


@dataclass
class LoopCycleResult:
    cycle_index: int
    target: str
    stage: str
    observations: List[str]
    hypotheses_proposed: int
    actions_executed: int
    findings_confirmed: int
    hypotheses_rejected: int
    duration_sec: float


class AutonomousActionLoop:
    """
    Continuous Autonomous OODA Loop for HunterAI.
    """

    def __init__(
        self,
        target_domain: str,
        policy_gate: PolicyGate,
        computer_control: ComputerControl,
        evidence_graph: EvidenceGraph,
        decision_core: DecisionCore,
        triad_agent: Optional[LocalTriadAgent] = None,
        failure_memory: Optional[FailureMemory] = None,
        progress_cb: Optional[Callable[[Dict[str, Any]], Any]] = None,
    ):
        self.domain = target_domain
        self.policy_gate = policy_gate
        self.computer_control = computer_control
        self.evidence_graph = evidence_graph
        self.decision_core = decision_core
        self.triad = triad_agent or LocalTriadAgent()
        self.failure_memory = failure_memory or FailureMemory()
        self.cb = progress_cb
        self.cycle_count = 0

    async def _emit(self, phase: str, message: str, data: Optional[Dict[str, Any]] = None) -> None:
        logger.info(f"[{phase.upper()}] {message}")
        if self.cb:
            try:
                payload = {"phase": phase, "message": message, "timestamp": datetime.now().isoformat()}
                if data:
                    payload.update(data)
                res = self.cb(payload)
                if asyncio.iscoroutine(res):
                    await res
            except Exception:
                pass

    async def run_cycle(
        self,
        active_endpoints: List[str],
        active_parameters: List[str],
        detected_technologies: List[str],
        raw_evidence: Optional[List[str]] = None,
    ) -> LoopCycleResult:
        """
        Executes one complete 7-step autonomous reasoning cycle.
        """
        self.cycle_count += 1
        start_time = time.time()
        await self._emit("start", f"Starting Autonomous Reasoning Cycle #{self.cycle_count} on '{self.domain}'")

        confirmed_count = 0
        rejected_count = 0
        hypotheses_count = 0
        actions_count = 0

        # ── 1. OBSERVE ───────────────────────────────────────────────────────
        obs_summary = f"Observed {len(active_endpoints)} endpoints, {len(active_parameters)} params, {len(detected_technologies)} tech signatures."
        await self._emit("observe", obs_summary)

        # ── 2. THINK ─────────────────────────────────────────────────────────
        await self._emit("think", "Analyzing observations against signal catalog and prior failure memory...")
        recommendations = self.decision_core.evaluate_signals(
            target_host=self.domain,
            endpoints=active_endpoints,
            parameters=active_parameters,
            technologies=detected_technologies,
            raw_observations=raw_evidence,
        )

        # ── 3. PLAN ──────────────────────────────────────────────────────────
        for rec in recommendations:
            hyp_key = f"{rec.track.value}::{rec.target_path}::{rec.trigger_signal}"
            if self.failure_memory.is_hypothesis_rejected(hyp_key):
                logger.info(f"Skipping previously rejected hypothesis: {hyp_key}")
                continue

            await self._emit("plan", f"Formulated Plan for {rec.track.value.upper()}: {rec.suggested_hypothesis}")

            # Register hypothesis in EvidenceGraph
            param_name = rec.trigger_signal.split("'")[1] if "'" in rec.trigger_signal else "general"
            hyp = self.evidence_graph.propose_hypothesis(
                sub=self.domain,
                url=rec.target_url,
                path=rec.target_path or "/",
                param_name=param_name,
                vuln_class=rec.track.value,
                proposed_by="DecisionCore+WhiteRabbitNeo",
                rationale=rec.trigger_signal,
                test_plan=rec.test_plan,
            )
            hypotheses_count += 1

            # ── 4. ACT (GATED BY POLICY) ─────────────────────────────────────
            test_req = ActionRequest(
                category=ActionCategory.TERMINAL_COMMAND,
                target=self.domain,
                command=f"curl -s -i https://{self.domain}{rec.target_path}",
                url=rec.target_url,
                path=rec.target_path,
                reason=f"Controlled differential verification for {rec.suggested_hypothesis}",
                requested_by_model="AutonomousActionLoop",
            )
            decision = self.policy_gate.evaluate(test_req)
            if not decision.allowed:
                await self._emit("policy_blocked", f"Action blocked by PolicyGate: {decision.reason}")
                continue

            # Execute controlled verification command
            await self._emit("act", f"Executing controlled probe for {rec.target_path}")
            exec_rec = await self.computer_control.execute_command(
                command=test_req.command or "",
                tool="curl",
                stage=rec.track.value,
                reason=rec.test_plan,
                timeout=20,
            )
            actions_count += 1

            # ── 5. OBSERVE RESPONSE ──────────────────────────────────────────
            raw_response = exec_rec.stdout
            response_status = 200 if "200 OK" in raw_response else (403 if "403" in raw_response else 404)

            # Record differential evidence in graph
            ev = self.evidence_graph.record_differential_evidence(
                sub=self.domain,
                url=rec.target_url,
                path=rec.target_path or "/",
                param_name=param_name,
                req=f"GET {rec.target_path} HTTP/1.1\r\nHost: {self.domain}",
                resp=raw_response[:2000],
                evidence_type="http_differential",
                diff_analysis=f"Captured HTTP response status {response_status} with body length {len(raw_response)}",
            )

            # ── 6. VALIDATE (DETERMINISTIC VALIDATOR) ────────────────────────
            p_node = self.evidence_graph.get_or_create_parameter(self.domain, rec.target_url, rec.target_path or "/", param_name)
            
            # Confidence != Verification: check proof criteria
            finding = DeterministicEvidenceValidator.decide_finding(
                param_node=p_node,
                target_url=rec.target_url,
                vuln_class=rec.track.value,
            )

            # ── 7. DECIDE ────────────────────────────────────────────────────
            if finding:
                confirmed_count += 1
                await self._emit("decide", f"CONFIRMED FINDING: {finding['vuln_class']} on {rec.target_url}")
            else:
                rejected_count += 1
                self.failure_memory.record_rejected_hypothesis(
                    hypothesis_key=hyp_key,
                    reason="Deterministic validation threshold or differential proof requirement not met."
                )
                await self._emit("decide", f"Hypothesis rejected. Proof requirement not met for {rec.target_url}")

        duration = round(time.time() - start_time, 2)
        await self._emit("complete", f"Cycle #{self.cycle_count} finished in {duration}s. Confirmed: {confirmed_count}, Rejected: {rejected_count}")

        return LoopCycleResult(
            cycle_index=self.cycle_count,
            target=self.domain,
            stage="autonomous_ooda",
            observations=[obs_summary],
            hypotheses_proposed=hypotheses_count,
            actions_executed=actions_count,
            findings_confirmed=confirmed_count,
            hypotheses_rejected=rejected_count,
            duration_sec=duration,
        )
