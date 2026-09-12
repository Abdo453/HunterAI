"""
Unit tests for HunterAI Meta-Reasoning Layer:
- Capability Graph & Privilege Creep
- Multi-Dimensional Behavioral Fingerprinting
- Four-Persona Reasoning Council (Explorer, Tester, Skeptic, Judge)
- Meta-Reasoner & Research Strategy Evolution
"""
import pytest

from hunter_ai.runtime import (
    CapabilityGraph, Capability,
    BehavioralFingerprint, DeviationReport, BehavioralFingerprinter,
    FourPersonaCouncil, PersonaVerdict, CouncilJudgment,
    MetaReasoner, StrategyState, MetaStrategyStatus
)


# ─── 1. Capability Graph Tests ───────────────────────────────────────────────
class TestCapabilityGraph:
    def test_capability_grants_and_privilege_creep(self):
        graph = CapabilityGraph()
        # Alice has own profile reading and order creation
        graph.grant_capability("user_alice", "read", "profile", scope="own")
        graph.grant_capability("user_alice", "create", "order", scope="own")

        # Authorized actions
        assert graph.has_capability("user_alice", "read", "profile", scope="own") is True
        assert graph.has_capability("user_alice", "create", "order", scope="own") is True

        # Unauthorized action: global order deletion
        creep, reason = graph.detect_privilege_creep("user_alice", "delete", "order", target_scope="global")
        assert creep is True
        assert "PRIVILEGE_CREEP" in reason

        # Admin user with global grant
        graph.grant_capability("admin", "delete", "order", scope="global")
        creep, _ = graph.detect_privilege_creep("admin", "delete", "order", target_scope="global")
        assert creep is False


# ─── 2. Behavioral Fingerprinting Tests ──────────────────────────────────────
class TestBehavioralFingerprinter:
    def test_structural_hash_and_deviation_detection(self):
        baseline_headers = {"Content-Type": "application/json", "Server": "nginx"}
        baseline_body = '{"user_id": 101, "name": "Alice", "role": "user"}'

        baseline_fp = BehavioralFingerprinter.create_fingerprint(
            endpoint="/api/user",
            status_code=200,
            headers=baseline_headers,
            body=baseline_body
        )

        # 1. Volatile data change with identical structure -> No semantic deviation
        same_struct_body = '{"user_id": 999, "name": "RandomNameXYZ", "role": "user"}'
        same_struct_fp = BehavioralFingerprinter.create_fingerprint(
            endpoint="/api/user",
            status_code=200,
            headers=baseline_headers,
            body=same_struct_body
        )
        report1 = BehavioralFingerprinter.compare(baseline_fp, same_struct_fp)
        assert report1.has_semantic_deviation is False

        # 2. Structural skeleton change (new admin fields or new cookie) -> Semantic deviation!
        deviant_headers = {"Content-Type": "application/json", "Set-Cookie": "admin_session=xyz"}
        deviant_body = '{"user_id": 101, "name": "Alice", "role": "user", "secret_key": "sec123"}'
        deviant_fp = BehavioralFingerprinter.create_fingerprint(
            endpoint="/api/user",
            status_code=200,
            headers=deviant_headers,
            body=deviant_body
        )
        report2 = BehavioralFingerprinter.compare(baseline_fp, deviant_fp)
        assert report2.has_semantic_deviation is True
        assert report2.structural_changed is True
        assert len(report2.new_cookies) > 0


# ─── 3. Four-Persona Council Tests ───────────────────────────────────────────
class TestFourPersonaCouncil:
    def test_council_approval_when_evidence_solid(self):
        deviation = DeviationReport(
            has_semantic_deviation=True,
            status_changed=True,
            structural_changed=True,
            new_cookies=set(),
            redirect_diverged=False,
            summary="Status shifted 403 -> 200 with object data"
        )

        # Falsification proofs passed + high reproducibility
        judgment = FourPersonaCouncil.evaluate_candidate(
            vulnerability_type="IDOR",
            observed_deviation=deviation,
            has_falsification_proof=True,
            reproducibility_rate=0.95
        )

        assert judgment.verdict == PersonaVerdict.APPROVED
        assert judgment.confidence >= 0.85
        assert "proven beyond reasonable doubt" in judgment.judge_ruling

    def test_council_challenge_when_unfalsified(self):
        deviation = DeviationReport(
            has_semantic_deviation=True,
            status_changed=False,
            structural_changed=True,
            new_cookies=set(),
            redirect_diverged=False,
            summary="Structural change without status change"
        )

        # Missing falsification proof (could be public data or reflection)
        judgment = FourPersonaCouncil.evaluate_candidate(
            vulnerability_type="IDOR",
            observed_deviation=deviation,
            has_falsification_proof=False,
            reproducibility_rate=0.9
        )

        assert judgment.verdict == PersonaVerdict.CHALLENGED
        assert "Challenged by Skeptic" in judgment.judge_ruling


# ─── 4. Meta-Reasoner & Strategy Evolution Tests ─────────────────────────────
class TestMetaReasoner:
    def test_stagnation_detection_and_strategy_pivot(self):
        reasoner = MetaReasoner(stagnation_threshold=3)
        assert reasoner.current_strategy == StrategyState.SURFACE_PROBING

        # Step 1: No yield -> stagnant counter = 1
        s1 = reasoner.evaluate_velocity(step_yielded_signals=False)
        assert s1.is_stagnant is False
        assert s1.consecutive_stagnant_steps == 1

        # Step 2: Yielded signal -> resets counter
        s2 = reasoner.evaluate_velocity(step_yielded_signals=True)
        assert s2.consecutive_stagnant_steps == 0

        # Steps 3, 4, 5: Consecutive failures reach threshold (3)
        reasoner.evaluate_velocity(step_yielded_signals=False)
        reasoner.evaluate_velocity(step_yielded_signals=False)
        s5 = reasoner.evaluate_velocity(step_yielded_signals=False)

        # Must trigger STAGNATION and pivot strategy to DEEP_PARAM_PROBING
        assert s5.is_stagnant is True
        assert s5.recommended_pivot == StrategyState.DEEP_PARAM_PROBING
        assert reasoner.current_strategy == StrategyState.DEEP_PARAM_PROBING
