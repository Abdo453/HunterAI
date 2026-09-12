"""
Unit tests for HunterAI Unified Cognitive Core:
- Noise & Deception Model
- Bayesian Hypothesis Competition
- Automatic Invariant Discovery
- Falsification & Anti-Confirmation Engine
- Deterministic Reproducibility Verifier
"""
import pytest

from hunter_ai.runtime import (
    NoiseModel, NoiseProfile,
    BayesianHypothesisCompetition, CompetingExplanation,
    AutomaticInvariantDiscovery, DiscoveredRule,
    FalsificationEngine, ReproducibilityVerifier,
    MetamorphicEngine, RootCauseClusteringEngine, MemoryDecayManager
)


# ─── 1. Noise & Deception Model Tests ────────────────────────────────────────
class TestNoiseModel:
    def test_noise_calibration_and_significance(self):
        model = NoiseModel()
        # Calibrate baseline with slightly fluctuating responses (1000, 1005, 1008 bytes)
        samples = [
            {"text": "A" * 1000, "status_code": 200},
            {"text": "A" * 1005, "status_code": 200},
            {"text": "A" * 1008, "status_code": 200}
        ]
        profile = model.calibrate("/api/search", samples)
        assert profile.sample_count == 3

        # Small fluctuation (1004 bytes) should be recognized as background noise
        sig, reason = profile.is_signal_significant(1004, 200)
        assert sig is False
        assert "noise floor" in reason

        # Large shift (1500 bytes) should be recognized as significant signal
        sig, reason = profile.is_signal_significant(1500, 200)
        assert sig is True
        assert "exceeds noise threshold" in reason

        # Status code change should immediately trigger signal
        sig, reason = profile.is_signal_significant(1000, 500)
        assert sig is True
        assert "Status code 500 differs" in reason


# ─── 2. Bayesian Hypothesis Competition Tests ────────────────────────────────
class TestBayesianHypothesisCompetition:
    def test_bayesian_probability_updates(self):
        competition = BayesianHypothesisCompetition("Endpoint returned HTTP 500 on single quote")
        competition.add_explanation("H1_SQLI", "SQLi", "RDBMS syntax error triggered", prior=0.5)
        competition.add_explanation("H2_VALIDATION", "Logic", "Framework input filter rejected character", prior=0.3)
        competition.add_explanation("H3_OUTAGE", "Infra", "Transient server glitch", prior=0.2)

        # Initially H1 is leading with 0.5
        leading = competition.get_leading_explanation()
        assert leading.explanation_id == "H1_SQLI"

        # Apply strong evidence favoring H1 (e.g. double quote closes string, query returns 200 OK)
        competition.apply_evidence("H1_SQLI", likelihood_multiplier=5.0, evidence_text="Double single quote reverted response to 200 OK")

        leading = competition.get_leading_explanation()
        assert leading.explanation_id == "H1_SQLI"
        assert leading.posterior_probability > 0.8
        assert "Double single quote" in leading.evidence_points[0]


# ─── 3. Automatic Invariant Discovery Tests ──────────────────────────────────
class TestAutomaticInvariantDiscovery:
    def test_ownership_invariant_inference(self):
        discovery = AutomaticInvariantDiscovery()

        # Observation: User B (non-owner) gets 403 on document owned by User A
        rule = discovery.observe_access_differential(
            resource_type="document",
            resource_id="doc_123",
            owner_id="user_alice",
            actor_id="user_bob",
            status_code=403
        )

        assert rule is not None
        assert "OWNERSHIP_DOCUMENT" in rule.rule_id or "AUTO-INV" in rule.rule_id
        assert rule.resource_type == "document"
        assert rule.confidence >= 0.8

        # Reinforcing observation strengthens confidence
        updated_rule = discovery.observe_access_differential(
            resource_type="document",
            resource_id="doc_456",
            owner_id="user_alice",
            actor_id="user_bob",
            status_code=403
        )
        assert updated_rule.supporting_observations == 2
        assert updated_rule.confidence > 0.85


# ─── 4. Falsification Engine Tests ───────────────────────────────────────────
class TestFalsificationEngine:
    def test_public_resource_falsification(self):
        # Scenario 1: Unauthenticated request accesses the object -> Falsified!
        survived, reason = FalsificationEngine.test_public_resource_falsification(
            unauthenticated_response_status=200,
            unauthenticated_response_body='{"id": "obj_999", "title": "Public Catalog Item"}',
            target_object_id="obj_999"
        )
        assert survived is False
        assert "FALSIFIED" in reason

        # Scenario 2: Unauthenticated request gets 401 Unauthorized -> Survives!
        survived, reason = FalsificationEngine.test_public_resource_falsification(
            unauthenticated_response_status=401,
            unauthenticated_response_body='{"error": "Authentication required"}',
            target_object_id="obj_999"
        )
        assert survived is True
        assert "SURVIVED" in reason

    def test_control_negative_falsification(self):
        # Negative control gives same response as probe -> Falsified (input reflection / noise)
        survived, reason = FalsificationEngine.test_control_negative_falsification(
            probe_status=200,
            control_status=200,
            probe_len=1000,
            control_len=1005
        )
        assert survived is False
        assert "FALSIFIED" in reason

        # Negative control diverges significantly -> Survives
        survived, reason = FalsificationEngine.test_control_negative_falsification(
            probe_status=200,
            control_status=404,
            probe_len=1500,
            control_len=300
        )
        assert survived is True
        assert "SURVIVED" in reason


# ─── 5. Reproducibility Verifier Tests ───────────────────────────────────────
class TestReproducibilityVerifier:
    def test_reproducibility_rate(self):
        # 4 out of 5 trials succeed -> Reproducible
        reproducible, rate = ReproducibilityVerifier.verify_reproducibility([True, True, True, True, False])
        assert reproducible is True
        assert rate == 0.8

        # Only 1 out of 5 trials succeeds -> Flaky/Non-reproducible
        reproducible, rate = ReproducibilityVerifier.verify_reproducibility([True, False, False, False, False])
        assert reproducible is False
        assert rate == 0.2


# ─── 6. Metamorphic Testing Engine Tests ─────────────────────────────────────
class TestMetamorphicEngine:
    def test_generate_variants(self):
        variants = MetamorphicEngine.generate_metamorphic_variants("test value")
        assert variants["identity"] == "test value"
        assert "url_encoded" in variants
        assert variants["uppercase"] == "TEST VALUE"

    def test_metamorphic_invariance(self):
        # Consistent behavior -> Invariance maintained
        ok, reason = MetamorphicEngine.evaluate_metamorphic_invariance(
            baseline_status=200, baseline_body="Search results for test",
            variant_status=200, variant_body="Search results for TEST"
        )
        assert ok is True
        assert "INVARIANCE_MAINTAINED" in reason

        # Divergent behavior (e.g. status code changes on encoded payload) -> Divergence
        ok, reason = MetamorphicEngine.evaluate_metamorphic_invariance(
            baseline_status=200, baseline_body="Normal results",
            variant_status=500, variant_body="Server internal error"
        )
        assert ok is False
        assert "METAMORPHIC_DIVERGENCE" in reason


# ─── 7. Root-Cause Clustering Engine Tests ───────────────────────────────────
class TestRootCauseClusteringEngine:
    def test_root_cause_clustering(self):
        raw_findings = [
            {"vulnerability": "IDOR", "parameter": "user_id", "endpoint": "/api/users/profile"},
            {"vulnerability": "IDOR", "parameter": "user_id", "endpoint": "/api/users/settings"},
            {"vulnerability": "IDOR", "parameter": "user_id", "endpoint": "/api/users/orders"},
            {"vulnerability": "SQLi", "parameter": "category", "endpoint": "/api/products"},
        ]

        clusters = RootCauseClusteringEngine.cluster_findings(raw_findings)
        # Should cluster the 3 IDORs on user_id into 1 root cause, and SQLi as a 2nd root cause
        assert len(clusters) == 2

        idor_cluster = next(c for c in clusters if c.defect_class == "IDOR")
        assert len(idor_cluster.affected_endpoints) == 3
        assert "user_id" in idor_cluster.affected_parameters


# ─── 8. Epistemic Memory Decay Manager Tests ─────────────────────────────────
class TestMemoryDecayManager:
    def test_ephemeral_decay(self):
        manager = MemoryDecayManager(default_ttl=10.0)

        manager.set_ephemeral("temp_probe", {"status": 200}, ttl=0.1)
        manager.set_permanent("arch_rule", "Strict RBAC")

        # Immediately accessible
        assert manager.get_ephemeral("temp_probe") is not None
        assert manager.get_permanent("arch_rule") == "Strict RBAC"

        # After simulated delay exceeding TTL
        import time
        time.sleep(0.15)

        # Expired observation should return None
        assert manager.get_ephemeral("temp_probe") is None
        # Permanent rule must still exist
        assert manager.get_permanent("arch_rule") == "Strict RBAC"
