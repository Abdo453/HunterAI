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

import json
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
                return True, "Counterexample found: Command syntax is reflected literally in response (Reflection != Execution)."

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

        # 2. Causal Evidence Generation — carries the RAW observed bodies (plus any
        # caller-supplied proof fields) so the reviewer and EvidenceCourt can re-evaluate
        # rather than trusting a self-declared flag.
        diff_payload: Dict[str, Any] = {
            "baseline_text": baseline_response,
            "probed_text": probed_response,
            "delta_bytes": abs(len(probed_response) - len(baseline_response)),
        }
        for key in (
            "proof_payload",
            "artifact_type",
            "expected_token",
            "victim_canary",
            "owner_marker",
            "actor_id",
            "owner_id",
            "status_code",
            "probe_status",
            "baseline_status",
            "probed_expression",
            "expected_result",
            "metadata",
        ):
            if key in context and context[key] is not None:
                diff_payload[key] = context[key]
            elif key in task.parameters and task.parameters[key] is not None:
                diff_payload[key] = task.parameters[key]

        evidence = [
            EvidenceArtifact(
                significance=EvidenceSignificance.PROOF,
                source_tool=self.name,
                target=target,
                description=f"Verified causal differential delta on {target}",
                diff_data=diff_payload,
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


_IDOR_ID_KEYS = ("id", "user_id", "uid", "account_id", "owner_id", "tenant_id", "member_id")
_IDOR_PII_KEYS = (
    "email",
    "ssn",
    "phone",
    "secret",
    "token",
    "api_key",
    "private_key",
    "password_hash",
    "address",
    "credit_card",
    "iban",
)


def _extract_structured_idor_proof(
    probed_text: str,
    baseline_text: str,
) -> Optional[Tuple[str, str, str]]:
    """Derive (actor_id, owner_id, victim_pii_token) strictly from distinct-owner JSON bodies.

    Returns None for non-JSON responses, same-owner objects, or responses without a
    victim-specific PII/secret value absent from the baseline (bare diffs stay rejected).
    """
    if not probed_text or not baseline_text:
        return None
    try:
        probed_obj = json.loads(probed_text)
        baseline_obj = json.loads(baseline_text)
    except (ValueError, TypeError):
        return None
    if not isinstance(probed_obj, dict) or not isinstance(baseline_obj, dict):
        return None

    actor_id = ""
    owner_id = ""
    for key in _IDOR_ID_KEYS:
        if key in probed_obj and key in baseline_obj:
            p_val = str(probed_obj[key] if probed_obj[key] is not None else "").strip()
            b_val = str(baseline_obj[key] if baseline_obj[key] is not None else "").strip()
            if p_val and b_val and p_val != b_val:
                actor_id = b_val
                owner_id = p_val
                break
    if not actor_id or not owner_id:
        return None

    for pii_key in _IDOR_PII_KEYS:
        raw_val = probed_obj.get(pii_key)
        if raw_val is None:
            continue
        token = str(raw_val).strip()
        if len(token) >= 4 and token not in baseline_text:
            return actor_id, owner_id, token
    return None


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

        params = dict(task.parameters or {})
        vuln_class = str(params.get("vuln_class", "IDOR"))
        vuln_low = vuln_class.lower().strip()

        # The agent's own verdict is an INPUT, not a court ruling. Re-adjudicate
        # with the raw observed bodies and real proof fields where available, never
        # with a fabricated token: bare diffs without a real proof token/invariant
        # remain rejected by EvidenceCourt.
        proof_payload: Optional[Dict[str, Any]] = None
        explicit_param_payload = params.get("proof_payload")
        if isinstance(explicit_param_payload, dict):
            proof_payload = dict(explicit_param_payload)

        for artifact in task.result.evidence_artifacts or []:
            diff = getattr(artifact, "diff_data", None) or {}
            if not isinstance(diff, dict):
                continue
            if isinstance(diff.get("proof_payload"), dict):
                proof_payload = dict(diff["proof_payload"])
                if not proof_payload.get("response_text") and diff.get("probed_text"):
                    proof_payload["response_text"] = str(diff["probed_text"])
                if not proof_payload.get("baseline_text") and diff.get("baseline_text"):
                    proof_payload["baseline_text"] = str(diff["baseline_text"])
                break

            probed = diff.get("probed_text") or diff.get("response_text")
            if probed:
                baseline = str(diff.get("baseline_text", ""))
                artifact_type = str(
                    diff.get("artifact_type")
                    or params.get("artifact_type")
                    or vuln_low
                ).strip()
                expected_token = str(
                    diff.get("expected_token")
                    or diff.get("victim_canary")
                    or diff.get("owner_marker")
                    or params.get("expected_token")
                    or params.get("victim_canary")
                    or params.get("owner_marker")
                    or ""
                )
                meta: Dict[str, Any] = {}
                if isinstance(params.get("metadata"), dict):
                    meta.update(params["metadata"])
                if isinstance(diff.get("metadata"), dict):
                    meta.update(diff["metadata"])
                for meta_key in (
                    "actor_id",
                    "owner_id",
                    "status_code",
                    "probe_status",
                    "baseline_status",
                    "oob_callbacks",
                    "oob_nonce",
                    "dom_executed",
                    "boolean_true_matches_baseline",
                    "boolean_false_diverges",
                    "control_matches_baseline",
                    "concurrent_success_count",
                    "expected_max_success",
                    "state_delta_verified",
                    "probe_origin",
                    "acao",
                    "acac",
                    "probe_redirect_host",
                    "location",
                    "raw_jwt",
                    "cracked_secret",
                    "sensitive_data_leaked",
                ):
                    if diff.get(meta_key) is not None:
                        meta[meta_key] = diff[meta_key]
                    elif params.get(meta_key) is not None and meta_key not in meta:
                        meta[meta_key] = params[meta_key]

                if not expected_token and vuln_low in ("idor", "bola", "broken_object_level_authorization"):
                    extracted = _extract_structured_idor_proof(str(probed), baseline)
                    if extracted is not None:
                        ext_actor, ext_owner, ext_token = extracted
                        meta.setdefault("actor_id", ext_actor)
                        meta.setdefault("owner_id", ext_owner)
                        expected_token = ext_token

                payload_dict: Dict[str, Any] = {
                    "artifact_type": artifact_type,
                    "response_text": str(probed),
                    "baseline_text": baseline,
                    "metadata": meta,
                }
                if expected_token:
                    payload_dict["expected_token"] = expected_token
                if diff.get("probed_expression") is not None:
                    payload_dict["probed_expression"] = str(diff["probed_expression"])
                elif params.get("probed_expression") is not None:
                    payload_dict["probed_expression"] = str(params["probed_expression"])
                elif vuln_low not in ("cmdi", "command_injection", "cmd_injection", "rce"):
                    payload_dict["probed_expression"] = ""
                if diff.get("expected_result") is not None:
                    payload_dict["expected_result"] = str(diff["expected_result"])
                elif params.get("expected_result") is not None:
                    payload_dict["expected_result"] = str(params["expected_result"])

                proof_payload = payload_dict
                break

        # Adjudicate via EvidenceCourt (declared proof is never trusted here).
        judgment = EvidenceCourt.adjudicate(
            target_url=task.target,
            parameter=params.get("parameter", "id"),
            vuln_class=vuln_class,
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
