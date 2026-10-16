"""Evidence-integrity defaults & reviewer honesty (LEDGER-011).

Guards the "no CONFIRMED without proof" invariant across the paths that could
otherwise silently claim a verified result:

  1. ``HunterFinding`` schema defaults are non-confirmed.
  2. ``EvidenceOS.rule_verdict`` refuses CONFIRMED without a verified lineage.
  3. ``DeterministicEvidenceValidator.evaluate_differential_response`` no longer
     contains the ``x.lower() in x.lower()`` tautology (length delta alone is
     never proof).
  4. ``EvidenceCourtReviewer`` re-adjudicates via the EvidenceCourt with real,
     re-evaluable proof instead of a fabricated token, and refuses anything the
     court does not confirm.
  5. ``CausalVerificationAgent`` never fabricates probe responses.
"""
from __future__ import annotations

import pytest

from hunter_ai.pipeline.schemas import HunterFinding, FindingStatus, FindingTier
from core.evidence_os.unified_model import EvidenceOS, ObservationType
from core.evidence_graph import DeterministicEvidenceValidator
from core.contracts import (
    AgentTeam,
    TaskContract,
    TaskLifecycleStatus,
    ToolExecutionResult,
)
from core.teams.verification_team import (
    CausalVerificationAgent,
    EvidenceCourtReviewer,
)


# Long enough to clear the CounterexampleAgent jitter floor (delta >= 15 bytes).
PROBED = '{"id": 456, "name": "victim_alice", "email": "alice@corp.local"}'
BASELINE = '{"id": 123, "name": "attacker_bob"}'


# ─────────────────────────────────────────────────────────────────────────────
# 1. HunterFinding safe defaults
# ─────────────────────────────────────────────────────────────────────────────
class TestHunterFindingSafeDefaults:
    def test_default_status_is_not_confirmed(self):
        f = HunterFinding(
            finding="x", asset="a", endpoint="https://a/x", vuln_type="XSS"
        )
        assert f.status is FindingStatus.UNVERIFIED
        assert f.tier is FindingTier.NEEDS_REVIEW

    def test_explicit_promotion_still_possible(self):
        f = HunterFinding(
            finding="x",
            asset="a",
            endpoint="https://a/x",
            vuln_type="XSS",
            status=FindingStatus.CONFIRMED,
            tier=FindingTier.VERIFIED_FINDING,
        )
        assert f.status is FindingStatus.CONFIRMED
        assert f.tier is FindingTier.VERIFIED_FINDING


# ─────────────────────────────────────────────────────────────────────────────
# 2. EvidenceOS verdict gate
# ─────────────────────────────────────────────────────────────────────────────
def _full_lineage_claim(eos: EvidenceOS):
    obs = eos.ingest_observation(
        obs_type=ObservationType.HTTP_RESPONSE,
        source_tool="http_engine",
        target_url="https://api.target.local/v1/orders/42",
        snippet='{"order_id": 42, "user": "alice"}',
        status_code=200,
    )
    hyp = eos.formulate_hypothesis(
        vulnerability_class="BOLA",
        target_endpoint="/v1/orders/42",
        parameter="order_id",
        predicted_behavior="Bob token accesses Alice order object",
        origin_obs_id=obs.obs_id,
    )
    exp = eos.record_experiment(
        hypothesis_id=hyp.hypo_id,
        baseline_obs_id=obs.obs_id,
        control_obs_id=obs.obs_id,
        active_obs_id=obs.obs_id,
        mutation_description="Replay request with Bob Authorization header",
    )
    evi = eos.commit_evidence(
        experiment_id=exp.exp_id,
        has_execution_proof=True,
        poe_token="BOB_TOKEN_ACCESS_PROOF",
        differential_score=1.0,
        is_reproducible=True,
    )
    return eos.issue_claim(
        evidence_id=evi.evidence_id,
        vulnerability_class="BOLA",
        confidence_score=0.99,
        rationale="Cross-tenant access confirmed via differential execution",
    )


class TestEvidenceOSVerdictGate:
    def test_default_verdict_is_not_confirmed(self):
        eos = EvidenceOS()
        clm = _full_lineage_claim(eos)
        verdict = eos.rule_verdict(clm.claim_id)  # no decision supplied
        assert verdict.decision == "UNVERIFIED"

    def test_confirmed_allowed_with_valid_lineage(self):
        eos = EvidenceOS()
        clm = _full_lineage_claim(eos)
        verdict = eos.rule_verdict(clm.claim_id, decision="CONFIRMED")
        assert verdict.decision == "CONFIRMED"

    def test_confirmed_refused_when_lineage_broken(self):
        eos = EvidenceOS()
        clm = _full_lineage_claim(eos)
        # Sever the causal link Observation -> ... -> Claim.
        eos.evidence_items[list(eos.evidence_items.keys())[0]].experiment_id = (
            "EXP-DOES-NOT-EXIST"
        )
        with pytest.raises(ValueError):
            eos.rule_verdict(clm.claim_id, decision="CONFIRMED")


# ─────────────────────────────────────────────────────────────────────────────
# 3. Differential evaluator (tautology removed)
# ─────────────────────────────────────────────────────────────────────────────
class TestDifferentialNoTautology:
    def test_length_delta_alone_is_not_proof(self):
        ok, _conf, _reason = DeterministicEvidenceValidator.evaluate_differential_response(
            baseline_resp_code=200,
            baseline_len=100,
            tampered_resp_code=200,
            tampered_len=500,
            anomaly_indicator="victim_alice",
            tampered_body='{"id": 456}',
        )
        assert ok is False

    def test_indicator_must_actually_be_present_in_body(self):
        ok, conf, _reason = DeterministicEvidenceValidator.evaluate_differential_response(
            baseline_resp_code=200,
            baseline_len=100,
            tampered_resp_code=200,
            tampered_len=500,
            anomaly_indicator="victim_alice",
            tampered_body='{"name": "victim_alice"}',
        )
        assert ok is True
        assert conf >= 0.9

    def test_auth_bypass_status_differential_still_confirms(self):
        ok, _conf, _reason = DeterministicEvidenceValidator.evaluate_differential_response(
            baseline_resp_code=403,
            baseline_len=100,
            tampered_resp_code=200,
            tampered_len=100,
        )
        assert ok is True


# ─────────────────────────────────────────────────────────────────────────────
# 4/5. Verification team honesty
# ─────────────────────────────────────────────────────────────────────────────
def _task_in_review(result: ToolExecutionResult) -> TaskContract:
    task = TaskContract(
        title="Verify IDOR",
        team=AgentTeam.VERIFICATION,
        target="https://target.local/api/v1/users/456",
        action="verify_finding",
        parameters={"vuln_class": "IDOR", "parameter": "id"},
    )
    task.mark_running("VerifierWorker_1")
    task.submit_for_review(result)
    return task


class TestCausalVerificationAgentNoFabrication:
    def test_refuses_without_observations(self):
        agent = CausalVerificationAgent()
        task = TaskContract(
            target="https://target.local/x",
            action="verify_finding",
            parameters={},
        )
        res = agent.execute(task, context={})
        assert res.success is False
        assert res.normalized_data["verdict"] == "UNVERIFIED"

    def test_evidence_carries_raw_bodies(self):
        agent = CausalVerificationAgent()
        task = TaskContract(
            target="https://target.local/x",
            action="verify_finding",
            parameters={"vuln_class": "IDOR"},
        )
        res = agent.execute(
            task, context={"probed_response": PROBED, "baseline_response": BASELINE}
        )
        assert res.success is True
        diff = res.evidence_artifacts[0].diff_data
        assert diff["probed_text"] == PROBED
        assert diff["baseline_text"] == BASELINE


class TestEvidenceCourtReviewerHonesty:
    def test_approves_real_differential(self):
        agent = CausalVerificationAgent()
        probe_task = TaskContract(
            target="https://target.local/api/v1/users/456",
            action="verify_finding",
            parameters={"vuln_class": "IDOR", "parameter": "id"},
        )
        res = agent.execute(
            probe_task, context={"probed_response": PROBED, "baseline_response": BASELINE}
        )
        assert res.success is True

        task = _task_in_review(res)
        assert EvidenceCourtReviewer().review(task) is True
        assert task.status == TaskLifecycleStatus.DONE
        assert task.review_passed is True

    def test_rejects_claim_without_re_evaluable_proof(self):
        # Self-declared CONFIRMED with no raw bodies -> court cannot derive proof.
        res = ToolExecutionResult(
            task_id="TASK-X",
            tool_name="CausalVerificationAgent",
            action="verify_finding",
            target="https://target.local/x",
            success=True,
            normalized_data={"verdict": "CONFIRMED", "confidence": 0.99},
        )
        task = _task_in_review(res)
        assert EvidenceCourtReviewer().review(task) is False
        assert task.review_passed is False
