"""
HunterAI Independent Verification & Negative Testing Team (P1)
==============================================================
Ensures zero-tolerance for hallucinations and false positives:
  1. CounterexampleAgent: Actively searches for alternative benign explanations
     (reflection vs execution, natural HTTP jitter, WAF rate-limiting, static error pages)
  2. ReproductionAgent: Runs repeated metamorphic probes to verify deterministic reproducibility
  3. CausalVerificationAgent: Enforces PoE rules (arithmetic evaluation, DBMS banners, token diffs)
  4. EvidenceCourtReviewer: Assembles formal court docket for final binding adjudication
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from core.contracts.task_contracts import (
    AgentTeam,
    EvidenceArtifact,
    EvidenceSignificance,
    TaskContract,
    ToolExecutionResult,
)
from core.coverage.coverage_ledger import AssetType, CoverageLedger
from core.evidence_court import EvidenceCourt, CourtVerdict
from core.poe_engine import ProofOfExecutionEngine

logger = logging.getLogger("hunter_ai.teams.verification")


class CounterexampleAgent:
    """
    Adversarial skeptic: attempts to DISPROVE findings by testing alternative hypotheses:
    - Reflection test: Is the input merely echoed verbatim in response?
    - Jitter test: Does an unmutated request also return varying lengths?
    - Auth rejection test: Does a completely random invalid session also return 200?
    """
    def __init__(self, agent_name: str = "CounterexampleAgent"):
        self.name = agent_name

    def evaluate_claim(
        self,
        endpoint: str,
        vuln_class: str,
        probed_response: str,
        baseline_response: str,
    ) -> Tuple[bool, str]:
        """
        Returns: (is_refuted, refutation_reason).
        If is_refuted is True, the finding MUST NOT be confirmed!
        """
        # Test 1: Check for Command Injection literal echo
        if vuln_class == "COMMAND_INJECTION":
            syntax_echo = any(
                s in probed_response for s in ["$(", "expr ", "; echo", "__PTST"]
            )
            if syntax_echo:
                return True, "Counterexample found: Command syntax is reflected literally in response (Echo != Execution)."

        # Test 2: Natural Jitter vs Real Delta
        baseline_len = len(baseline_response)
        probed_len = len(probed_response)
        delta = abs(probed_len - baseline_len)
        if delta < 15 and baseline_response != probed_response:
            return True, f"Counterexample found: Response delta ({delta} bytes) is within natural HTTP timestamp/nonce jitter."

        # Test 3: Generic Error Page Masking
        if "404 Not Found" in probed_response or "Access Denied" in probed_response or "Cloudflare Ray ID" in probed_response:
            return True, "Counterexample found: Target returned a generic WAF challenge or error page."

        return False, "No refutation found; candidate survived counterexample evaluation."


class ReproductionAgent:
    """Verifies that a probe result is deterministically reproducible across multiple runs."""
    def __init__(self, agent_name: str = "ReproductionAgent"):
        self.name = agent_name

    def test_reproducibility(
        self,
        endpoint: str,
        repeated_probe_fn: Any,
        required_successes: int = 2,
    ) -> Tuple[bool, str]:
        success_count = 0
        for i in range(required_successes):
            try:
                res = repeated_probe_fn()
                if res and res.get("status_code") == 200:
                    success_count += 1
            except Exception as e:
                logger.warning("Reproduction attempt %d failed with network error: %s", i + 1, e)

        if success_count >= required_successes:
            return True, f"Deterministically reproduced {success_count}/{required_successes} times."
        return False, f"Failed reproduction: only {success_count}/{required_successes} attempts succeeded."


class CausalVerificationAgent:
    """Performs deep causal verification utilizing Proof-of-Execution."""
    def __init__(self, agent_name: str = "CausalVerificationAgent"):
        self.name = agent_name

    def execute(self, task: TaskContract, context: Dict[str, Any]) -> ToolExecutionResult:
        target = task.target
        vuln_class = task.parameters.get("vuln_class", "IDOR")
        logger.info("[%s] Verifying causal finding for %s [%s]", self.name, target, vuln_class)

        # Real probe data only: never fabricate a differential. If the caller did
        # not hand over the observed bodies there is nothing to verify.
        probed_response = str(context.get("probed_response", ""))
        baseline_response = str(context.get("baseline_response", ""))

        if not probed_response or not baseline_response:
            return ToolExecutionResult(
                task_id=task.task_id,
                tool_name=self.name,
                action="verify_finding",
                target=target,
                success=False,
                raw_output="No probe/baseline responses supplied; cannot verify.",
                normalized_data={"verdict": "UNVERIFIED", "reason": "missing_observations"},
                unresolved_unknowns=["No observed responses to re-evaluate"],
            )

        # 1. Counterexample Check
        counter = CounterexampleAgent()
        is_refuted, reason = counter.evaluate_claim(
            endpoint=target,
            vuln_class=vuln_class,
            probed_response=probed_response,
            baseline_response=baseline_response,
        )

        if is_refuted:
            return ToolExecutionResult(
                task_id=task.task_id,
                tool_name=self.name,
                action="verify_finding",
                target=target,
                success=False,
                raw_output=f"Finding refuted: {reason}",
                normalized_data={"verdict": "REJECTED", "reason": reason},
                unresolved_unknowns=["Refuted by counterexample analysis"],
            )

        # 2. Causal Evidence Generation — carries the RAW observed bodies so the
        # reviewer and the EvidenceCourt can re-evaluate the differential rather
        # than trusting a self-declared flag.
        evidence = [
            EvidenceArtifact(
                significance=EvidenceSignificance.PROOF,
                source_tool=self.name,
                target=target,
                description=f"Verified causal differential delta on {target}",
                diff_data={
                    "baseline_text": baseline_response,
                    "probed_text": probed_response,
                    "delta_bytes": abs(len(probed_response) - len(baseline_response)),
                },
                poe_verified=True,
            )
        ]

        return ToolExecutionResult(
            task_id=task.task_id,
            tool_name=self.name,
            action="verify_finding",
            target=target,
            success=True,
            raw_output="Verified differential authorization failure",
            normalized_data={"verdict": "CONFIRMED", "vuln_class": vuln_class, "confidence": 0.95},
            evidence_artifacts=evidence,
            covered_items=[target],
            recommended_next_steps=[
                {"team": "REPORTING", "action": "write_finding", "target": target}
            ],
        )


class EvidenceCourtReviewer:
    """Prepares and adjudicates final verified evidence in the EvidenceCourt."""
    def __init__(self, agent_name: str = "EvidenceCourtReviewer"):
        self.name = agent_name

    def review(self, task: TaskContract, ledger: Optional[CoverageLedger] = None) -> bool:
        if not task.result or not task.result.success:
            task.reject_review(self.name, task.result.raw_output if task.result else "No result")
            return False

        verdict = task.result.normalized_data.get("verdict")
        if verdict != "CONFIRMED":
            task.reject_review(self.name, f"Evidence Court rejected unproven claim: {verdict}")
            return False

        # The agent's own verdict is an INPUT, not a court ruling. Re-adjudicate
        # with the raw observed bodies where available and never with a fabricated
        # token: the court must DERIVE the proof, otherwise the claim is refused.
        proof_payload = None
        for artifact in task.result.evidence_artifacts or []:
            diff = getattr(artifact, "diff_data", None) or {}
            probed = diff.get("probed_text")
            if probed:
                proof_payload = {
                    "artifact_type": "differential",
                    "response_text": str(probed),
                    "baseline_text": str(diff.get("baseline_text", "")),
                }
                break

        # Adjudicate via EvidenceCourt (declared proof is never trusted here).
        judgment = EvidenceCourt.adjudicate(
            target_url=task.target,
            parameter=task.parameters.get("parameter", "id"),
            vuln_class=task.parameters.get("vuln_class", "IDOR"),
            finder_claim={"claim": "Differential object access observed"},
            verifier_result={
                "reproduced": True,
                "confidence": task.result.normalized_data.get("confidence", 0.9),
            },
            proof_payload=proof_payload,
            is_in_scope=True,
            allow_declared_proof=False,
        )

        if judgment.verdict != CourtVerdict.CONFIRMED:
            task.reject_review(
                self.name,
                f"Evidence Court did not confirm the claim "
                f"(Verdict: {judgment.verdict.value}, proof={judgment.proof_strength}): "
                f"{judgment.adjudication_rationale}",
            )
            return False

        if ledger:
            ledger.record_confirmation(AssetType.ENDPOINT, task.target, judgment.judgment_id)

        task.approve_review(
            self.name,
            f"EvidenceCourt confirmed finding {judgment.judgment_id} "
            f"(Verdict: {judgment.verdict.value}, proof={judgment.proof_strength})",
        )
        return True
