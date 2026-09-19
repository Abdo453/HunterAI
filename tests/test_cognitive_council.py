"""
Unit Tests for HunterAI Cognitive Council V2
============================================
Covers:
- Council Models, Enums & Schemas
- CouncilState Working Memory & Context Slicing
- DisagreementDetector & Consensus Adjudication
- CognitiveCouncil Parallel Peer Review & Debate Loop
"""
import pytest
from unittest.mock import AsyncMock, patch

from hunter_ai.brain.cognitive_council import (
    CognitiveCouncil,
    CouncilState,
    CouncilHypothesis,
    CouncilRole,
    ModelVote,
    VoteVerdict,
    HypothesisStatus,
    DisagreementDetector,
    create_cognitive_council,
)


def test_council_models_and_schemas():
    vote = ModelVote(
        model_name="qwen2.5-coder:14b",
        role=CouncilRole.CODE_AUDITOR,
        verdict=VoteVerdict.CONFIRM_VULN,
        confidence=0.88,
        rationale="Parameter flows directly into SQL query without parameterization.",
        counter_arguments=[],
        proposed_probe="id=1' OR '1'='1'",
    )
    assert vote.role == CouncilRole.CODE_AUDITOR
    assert vote.verdict == VoteVerdict.CONFIRM_VULN
    d = vote.to_dict()
    assert d["confidence"] == 0.88
    assert d["proposed_probe"] == "id=1' OR '1'='1'"

    hypo = CouncilHypothesis(
        claim_id="test_claim_01",
        vuln_type="SQLi",
        endpoint="https://example.com/api/items",
        parameter="id",
        initial_observation="Numeric parameter observed in REST API",
    )
    hypo.votes["code_auditor"] = vote
    assert hypo.status == HypothesisStatus.HYPOTHESIS
    hd = hypo.to_dict()
    assert hd["claim_id"] == "test_claim_01"
    assert "code_auditor" in hd["votes"]


def test_council_state_working_memory():
    state = CouncilState(target_domain="bancoplata.mx")
    state.update_recon(
        subdomains=["api.bancoplata.mx", "auth.bancoplata.mx"],
        live_assets=[{"url": "https://api.bancoplata.mx", "status_code": 200}],
        technologies=["Next.js", "GraphQL", "Spring Boot"]
    )
    state.update_surface(
        endpoints=[{"url": "https://api.bancoplata.mx/graphql", "category": "API"}],
        parameters=[{"parameter": "query", "context": {"risk_level": "HIGH"}}],
        secrets=[{"secret_type": "jwt_token", "file_url": "https://api.bancoplata.mx/app.js"}]
    )

    assert len(state.subdomains) == 2
    assert "graphql" in state.detected_technologies

    # Test context slicing
    slice_offensive = state.get_context_slice_for_role(CouncilRole.OFFENSIVE_STRATEGIST)
    assert "technologies" in slice_offensive
    assert len(slice_offensive["high_risk_params"]) == 1

    slice_code = state.get_context_slice_for_role(CouncilRole.CODE_AUDITOR)
    assert len(slice_code["js_secrets"]) == 1

    slice_critic = state.get_context_slice_for_role(CouncilRole.CRITIC_JUDGE)
    assert slice_critic["subdomains_count"] == 2
    assert "verification_mandate" in slice_critic


def test_disagreement_detector():
    # 1. Unanimous Confirmation
    votes_confirm = {
        "m1": ModelVote("m1", CouncilRole.OFFENSIVE_STRATEGIST, VoteVerdict.CONFIRM_VULN, 0.9, "RCE probable"),
        "m2": ModelVote("m2", CouncilRole.CODE_AUDITOR, VoteVerdict.CONFIRM_VULN, 0.85, "Command concat in source"),
        "m3": ModelVote("m3", CouncilRole.CRITIC_JUDGE, VoteVerdict.CONFIRM_VULN, 0.80, "Differential proof validated"),
    }
    score, conflict, reason = DisagreementDetector.evaluate_consensus(votes_confirm)
    assert not conflict
    assert score >= 0.8
    assert "Unanimous" in reason

    # 2. Conflict / Disagreement (One confirms, one rejects)
    votes_conflict = {
        "m1": ModelVote("m1", CouncilRole.OFFENSIVE_STRATEGIST, VoteVerdict.CONFIRM_VULN, 0.85, "Potential IDOR"),
        "m2": ModelVote("m2", CouncilRole.CODE_AUDITOR, VoteVerdict.NEEDS_MORE_EVIDENCE, 0.70, "Endpoint requires auth"),
        "m3": ModelVote("m3", CouncilRole.CRITIC_JUDGE, VoteVerdict.SKEPTICAL_REJECT, 0.80, "Identical 200 response on non-existent IDs (Soft-404)"),
    }
    score, conflict, reason = DisagreementDetector.evaluate_consensus(votes_conflict)
    assert conflict
    assert "Disagreement Detected" in reason

    # 3. Unanimous Rejection
    votes_reject = {
        "m1": ModelVote("m1", CouncilRole.OFFENSIVE_STRATEGIST, VoteVerdict.SKEPTICAL_REJECT, 0.9, "Public asset"),
        "m2": ModelVote("m2", CouncilRole.CRITIC_JUDGE, VoteVerdict.SKEPTICAL_REJECT, 0.9, "Zero security impact"),
    }
    score, conflict, reason = DisagreementDetector.evaluate_consensus(votes_reject)
    assert not conflict
    assert "Rejected" in reason


@pytest.mark.asyncio
async def test_cognitive_council_debate_flow():
    council = create_cognitive_council(target_domain="bancoplata.mx")
    council.state.update_recon(
        subdomains=["api.bancoplata.mx"],
        technologies=["GraphQL"]
    )

    # In offline / test environment, council falls back gracefully to heuristic votes
    hypo = await council.debate_hypothesis(
        vuln_type="SQLi",
        endpoint="https://api.bancoplata.mx/v1/search",
        parameter="query",
        initial_observation="Parameter query in search endpoint",
        evidence_snippet="SELECT * FROM items WHERE query = 'test'"
    )

    assert hypo.claim_id.startswith("claim_")
    assert hypo.vuln_type == "SQLi"
    assert len(hypo.votes) == 3
    assert hypo.status in (HypothesisStatus.CONFIRMED, HypothesisStatus.ACTIVE_PROBING, HypothesisStatus.UNPROVEN)
    assert len(hypo.debate_transcript) >= 1
    assert hypo.claim_id in council.state.hypotheses


@pytest.mark.asyncio
async def test_cognitive_council_with_mocked_llm_responses():
    council = CognitiveCouncil(target_domain="secure.bank.com")

    # Mock Ollama queries for each model
    async def mock_query(role, sys, usr, temperature=0.2, timeout=15):
        if role == CouncilRole.OFFENSIVE_STRATEGIST:
            return '{"verdict": "CONFIRM_VULN", "confidence": 0.92, "rationale": "Direct SQL concatenation detected", "proposed_probe": "id=1\'"}'
        elif role == CouncilRole.CODE_AUDITOR:
            return '{"verdict": "CONFIRM_VULN", "confidence": 0.88, "rationale": "Unsanitized input in db.execute", "proposed_probe": "id=1 OR 1=1"}'
        else:
            return '{"verdict": "NEEDS_MORE_EVIDENCE", "confidence": 0.75, "rationale": "Check for WAF error reflection", "counter_arguments": ["Could be generic 500 error"]}'

    with patch.object(council, "_query_model", side_effect=mock_query):
        hypo = await council.debate_hypothesis(
            vuln_type="SQLi",
            endpoint="https://secure.bank.com/account",
            parameter="id",
            initial_observation="Unsanitized account ID",
            evidence_snippet="Error: syntax error at or near '1\''"
        )

        assert hypo.votes["offensive_strategist"].verdict == VoteVerdict.CONFIRM_VULN
        assert hypo.votes["code_auditor"].verdict == VoteVerdict.CONFIRM_VULN
        assert hypo.votes["critic_judge"].verdict == VoteVerdict.NEEDS_MORE_EVIDENCE
        assert hypo.consensus_score >= 0.6
        assert len(hypo.debate_transcript) == 1
