"""
Automated Test Suite for Enhanced Security Intelligence & Education Layer
Tests ContextEngine, ContradictionEngine, DecisionEngine, ProvenanceTracker,
ResearchCache, LearningProfile, and full Cognitive Pipeline.
"""
import pytest
import asyncio
import os
import shutil
from pathlib import Path

from agents.security_intelligence.schemas import (
    SecurityObservation,
    ObservationType,
    EvidenceType,
    EvidenceItem,
    SecurityHypothesis,
    ScopeRule,
    ExplanationLevel,
    ConfidenceLevel,
    ActionPriority
)
from agents.security_intelligence.brain import SecurityIntelligence
from agents.security_intelligence.confidence_engine import ConfidenceEngine
from agents.security_intelligence.scope_guard import ScopeGuard
from agents.security_intelligence.critic import CriticEngine
from agents.security_intelligence.contradiction_engine import ContradictionEngine
from agents.security_intelligence.provenance import ProvenanceTracker
from agents.security_intelligence.context_engine import ContextEngine
from agents.security_intelligence.decision_engine import SecurityDecisionEngine
from agents.security_intelligence.research_cache import ResearchCache
from agents.security_intelligence.learning_profile import LearningProfile
from agents.security_intelligence.memory_manager import MemoryManager


@pytest.fixture
def clean_memory_env(tmp_path):
    """Fixture to provide isolated storage files for testing"""
    proj_mem = str(tmp_path / "proj.json")
    targ_mem = str(tmp_path / "targ.json")
    fp_mem = str(tmp_path / "fp.json")
    learn_mem = str(tmp_path / "learn.json")
    
    return MemoryManager(
        project_storage=proj_mem,
        target_storage=targ_mem,
        fp_storage=fp_mem,
        learning_storage=learn_mem
    )


def test_confidence_engine_tiers():
    assert ConfidenceEngine.score_to_level(0.10) == ConfidenceLevel.UNKNOWN
    assert ConfidenceEngine.score_to_level(0.30) == ConfidenceLevel.WEAK
    assert ConfidenceEngine.score_to_level(0.50) == ConfidenceLevel.POSSIBLE
    assert ConfidenceEngine.score_to_level(0.70) == ConfidenceLevel.STRONG
    assert ConfidenceEngine.score_to_level(0.88) == ConfidenceLevel.HIGH
    assert ConfidenceEngine.score_to_level(0.98) == ConfidenceLevel.CONFIRMED


def test_scope_guard_boundaries():
    rule = ScopeRule(
        target="example.com",
        allowed_domains=["example.com", "api.example.com"],
        excluded_paths=["/logout", "/delete_account"],
        allow_active_tests=False
    )
    guard = ScopeGuard(rule)

    # 1. In-scope passive check
    res = guard.check_target("https://api.example.com/api/users", action="passive_analysis")
    assert res.is_in_scope is True
    assert res.is_action_permitted is True

    # 2. Excluded path check
    res_exc = guard.check_target("https://api.example.com/delete_account", action="passive_analysis")
    assert res_exc.is_in_scope is False
    assert res_exc.is_action_permitted is False

    # 3. Out-of-scope domain
    res_out = guard.check_target("https://evil.com/login", action="passive_analysis")
    assert res_out.is_in_scope is False

    # 4. Education / Theory should always be allowed
    res_edu = guard.check_target("https://evil.com/login", action="education")
    assert res_edu.is_in_scope is True
    assert res_edu.is_action_permitted is True


def test_provenance_tracking():
    prov = ProvenanceTracker.create_record(
        source_component="BurpAgent.Parser",
        model_name="qwen2.5:7b",
        evidence_ids=["EVD-1234"],
        confidence=0.92,
        notes="Parsed JSON response headers"
    )
    assert prov.source_component == "BurpAgent.Parser"
    assert prov.model_name == "qwen2.5:7b"
    assert "EVD-1234" in prov.evidence_ids
    assert prov.confidence == 0.92


def test_context_engine_enrichment(clean_memory_env):
    ctx_engine = ContextEngine(clean_memory_env)
    clean_memory_env.project.record_technology("FastAPI")
    clean_memory_env.project.record_technology("PostgreSQL")

    obs = SecurityObservation(
        project_id="test_proj",
        target="api.test.local",
        source="burp_agent",
        obs_type=ObservationType.HTTP_REQUEST,
        data={
            "path": "/api/v1/admin/users",
            "method": "POST",
            "parameters": ["role", "email"],
            "headers": {"authorization": "Bearer eyJhbGciOi..."}
        }
    )

    ctx = ctx_engine.build_context(obs)
    assert ctx.is_authenticated is True
    assert ctx.auth_type == "jwt"
    assert ctx.is_state_changing is True
    assert "FastAPI" in ctx.known_technologies
    assert "role" in ctx.parameters_observed


def test_contradiction_engine_detects_defenses():
    contra_engine = ContradictionEngine()
    hyp = SecurityHypothesis(
        title="Potential BOLA",
        vulnerability_type="BOLA",
        target_endpoint="/api/user/10"
    )

    # Evidence showing server returned 403 Forbidden
    ev_forbidden = [
        EvidenceItem(
            type=EvidenceType.STATUS_CODE,
            source="burp",
            data={"status": 403, "body": "Access Denied: You do not own this object."},
            description="HTTP 403 Forbidden"
        )
    ]

    res = contra_engine.find_contradictions(hyp, ev_forbidden)
    assert res.has_contradiction is True
    assert res.penalty_score >= 0.50
    assert "HTTP 403" in res.explanation


def test_decision_engine_prioritization():
    dec_engine = SecurityDecisionEngine()
    brain = SecurityIntelligence()

    # Create mock high-confidence finding
    finding_high = brain.analyst.analyze_observation(
        SecurityObservation(
            project_id="p1",
            target="target.local",
            obs_type=ObservationType.HTTP_REQUEST,
            data={
                "path": "/api/orders/55",
                "method": "GET",
                "parameters": ["id"],
                "status": 200,
                "behavior_difference": "User 2 accessed User 1 orders with 200 OK"
            }
        )
    )[0]

    dec = dec_engine.evaluate_finding_decision(finding_high)
    assert dec.action_priority in [ActionPriority.IMMEDIATE, ActionPriority.HIGH]
    assert dec.target == "target.local"
    assert len(dec.rationale) > 0


def test_research_cache_hit_and_miss(tmp_path):
    cache_path = str(tmp_path / "cache.json")
    cache = ResearchCache(cache_file=cache_path, ttl_seconds=60)
    
    brain = SecurityIntelligence()
    brain.research_cache = cache
    brain.researcher.cache = cache

    # 1. First lookup (Miss -> Fetch)
    report1 = asyncio.run(brain.research("CWE-639"))
    assert report1.cached is False

    # 2. Second lookup (Hit -> Cached)
    report2 = asyncio.run(brain.research("CWE-639"))
    assert report2.cached is True
    assert report2.topic == report1.topic


def test_learning_profile_adaptive_level(tmp_path):
    prof_path = str(tmp_path / "profile.json")
    profile = LearningProfile(storage_file=prof_path)

    # Initially, default is technical
    assert profile.get_optimal_explanation_level("BOLA") == ExplanationLevel.TECHNICAL

    # Simulate failing twice on BOLA
    brain = SecurityIntelligence()
    quiz = brain.quiz.generate_quiz_for_topic("bola")
    eval_wrong = brain.quiz.evaluate_answer(quiz, user_choice_idx=2)
    
    profile.record_evaluation(eval_wrong, "BOLA")
    profile.record_evaluation(eval_wrong, "BOLA")

    # Should adapt to SIMPLE
    assert profile.get_optimal_explanation_level("BOLA") == ExplanationLevel.SIMPLE



@pytest.mark.asyncio
async def test_end_to_end_security_intelligence_pipeline():
    brain = SecurityIntelligence()
    scope = ScopeRule(
        target="app.testlab.local",
        allowed_domains=["app.testlab.local"]
    )
    brain.set_scope(scope)

    # 1. Observation of an interesting endpoint with behavioral difference
    obs = SecurityObservation(
        project_id="pentest_01",
        target="app.testlab.local",
        source="burp_agent",
        obs_type=ObservationType.HTTP_REQUEST,
        data={
            "path": "/api/v2/users/9912",
            "method": "GET",
            "parameters": ["user_id"],
            "status": 200,
            "headers": {"authorization": "Bearer token_for_user_100"},
            "behavior_difference": "User 100 received 200 OK with User 9912 personal data"
        }
    )

    # 2. Run analysis
    findings = await brain.analyze(obs)
    assert len(findings) > 0
    f = findings[0]
    assert f.vulnerability_type == "BOLA"
    assert f.confidence_score >= 0.60
    assert len(f.evidence) > 0
    assert f.provenance is not None

    # 3. Make security decision
    decision = await brain.decide(f)
    assert decision.target == "app.testlab.local"
    assert decision.action_priority in [ActionPriority.IMMEDIATE, ActionPriority.HIGH]

    # 4. Create a lesson from this finding
    lesson = await brain.teach_from_finding(f)
    assert lesson.topic == f.title
    assert lesson.vuln_class == "BOLA"
    assert ExplanationLevel.PENTESTER.value in lesson.explanations

    # 5. Correlate attack chains
    chains = await brain.correlate_attack_chains("app.testlab.local", findings)
    assert len(chains["attack_chains"]) > 0
    assert "Direct Object Identifier" in chains["attack_chains"][0]["chain_name"]
