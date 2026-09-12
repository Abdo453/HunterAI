"""
Tests for Decision Bridge, Learning Profile Progression, and Property Aliases
"""
import asyncio
import pytest
from agents.security_intelligence.brain import SecurityIntelligence
from agents.security_intelligence.schemas import (
    SecurityObservation, ObservationType, ScopeRule, QuizEvaluation,
    IntelligenceFinding, ConfidenceLevel, SeverityLevel, ActionPriority
)
from agents.burp_agent.pipeline.event_bus import EventBus, BurpEvent
from core.integration.security_intelligence_adapter import SecurityIntelligenceAdapter
from agents.security_intelligence.events import SecurityEvent, SecurityEventType
from agents.security_intelligence.learning_profile import LearningProfile


# ============================================================================
# Decision Bridge Test
# ============================================================================
class TestDecisionBridge:
    """Verify that internal DECISION_CREATED events are bridged to outer EventBus"""

    @pytest.mark.asyncio
    async def test_decision_bridged_to_outer_bus(self):
        si = SecurityIntelligence()
        bus = EventBus()
        adapter = SecurityIntelligenceAdapter(
            security_intelligence=si,
            event_bus=bus
        )

        bridged_decisions = []

        async def capture_decision(data):
            bridged_decisions.append(data)

        bus.subscribe(BurpEvent.DECISION_CREATED, capture_decision)

        # Manually publish an internal decision event
        await si.bus.publish(SecurityEvent(
            event_type=SecurityEventType.DECISION_CREATED,
            target="api.target.local",
            source="SecurityDecisionEngine",
            data={
                "decision_id": "DEC-test-001",
                "action": "verify_bola_cross_user",
                "priority": "immediate"
            }
        ))

        # Allow event propagation
        await asyncio.sleep(0.1)

        assert len(bridged_decisions) > 0, "Decision should be bridged to outer EventBus"
        assert bridged_decisions[0]["decision_id"] == "DEC-test-001"
        assert bridged_decisions[0]["action"] == "verify_bola_cross_user"
        assert bridged_decisions[0]["source"] == "SecurityIntelligence.internal"

    @pytest.mark.asyncio
    async def test_finding_still_bridged(self):
        """Ensure findings bridge still works after decision bridge fix"""
        si = SecurityIntelligence()
        bus = EventBus()
        adapter = SecurityIntelligenceAdapter(
            security_intelligence=si,
            event_bus=bus
        )

        bridged_findings = []

        async def capture_finding(data):
            bridged_findings.append(data)

        bus.subscribe(BurpEvent.FINDING_CREATED, capture_finding)

        await si.bus.publish(SecurityEvent(
            event_type=SecurityEventType.FINDING_CREATED,
            target="api.target.local",
            source="VulnerabilityAnalyst",
            data={
                "finding_id": "FND-test-002",
                "title": "Test BOLA",
                "type": "BOLA"
            },
            confidence=0.85
        ))

        await asyncio.sleep(0.1)

        assert len(bridged_findings) > 0
        assert bridged_findings[0]["finding_id"] == "FND-test-002"


# ============================================================================
# Learning Profile Upward Progression Test
# ============================================================================
class TestLearningProfileProgression:
    """Test upward adaptation: SIMPLE → TECHNICAL → PENTESTER → RESEARCHER"""

    def test_upward_progression_through_correct_answers(self):
        lp = LearningProfile(storage_file=None)

        # Start fresh — default mastery is 0.5 → TECHNICAL
        from agents.security_intelligence.schemas import ExplanationLevel
        assert lp.get_optimal_explanation_level("bola") == ExplanationLevel.TECHNICAL

        # Record 2 correct answers → mastery goes 0.5 → 0.7 → 0.9
        for _ in range(2):
            lp.record_evaluation(
                QuizEvaluation(
                    quiz_id="QZ-test",
                    is_correct=True,
                    understanding_score=0.9,
                    feedback_ar="أحسنت",
                    next_recommendation="تابع"
                ),
                concept="bola"
            )

        # 0.9 → should be PENTESTER (0.70 <= score < 0.90)
        level = lp.get_optimal_explanation_level("bola")
        assert level in [ExplanationLevel.PENTESTER, ExplanationLevel.RESEARCHER], \
            f"After 2 correct answers, level should be PENTESTER or RESEARCHER, got {level}"

    def test_researcher_level_at_high_mastery(self):
        lp = LearningProfile(storage_file=None)

        # Record 3 correct answers → mastery 0.5 → 0.7 → 0.9 → 1.0 (capped)
        for _ in range(3):
            lp.record_evaluation(
                QuizEvaluation(
                    quiz_id="QZ-test",
                    is_correct=True,
                    understanding_score=1.0,
                    feedback_ar="ممتاز",
                    next_recommendation="أنت خبير"
                ),
                concept="sqli"
            )

        from agents.security_intelligence.schemas import ExplanationLevel
        level = lp.get_optimal_explanation_level("sqli")
        assert level == ExplanationLevel.RESEARCHER

    def test_concept_isolation(self):
        """Mastery on BOLA should NOT affect SQLi level"""
        lp = LearningProfile(storage_file=None)

        # Boost BOLA to researcher level
        for _ in range(3):
            lp.record_evaluation(
                QuizEvaluation(
                    quiz_id="QZ-bola",
                    is_correct=True,
                    understanding_score=1.0,
                    feedback_ar="ممتاز",
                    next_recommendation="أنت خبير"
                ),
                concept="bola"
            )

        from agents.security_intelligence.schemas import ExplanationLevel
        assert lp.get_optimal_explanation_level("bola") == ExplanationLevel.RESEARCHER
        assert lp.get_optimal_explanation_level("sqli") == ExplanationLevel.TECHNICAL  # unchanged default


# ============================================================================
# Property Aliases on SecurityIntelligence Facade
# ============================================================================
class TestFacadePropertyAliases:
    """Verify both short and long property names work on SecurityIntelligence"""

    def test_context_engine_alias(self):
        si = SecurityIntelligence()
        assert si.context_engine is si.context

    def test_contradiction_engine_alias(self):
        si = SecurityIntelligence()
        assert si.contradiction_engine is si.contradiction

    def test_decision_engine_alias(self):
        si = SecurityIntelligence()
        assert si.decision_engine is si.decision

    def test_security_teacher_alias(self):
        si = SecurityIntelligence()
        assert si.security_teacher is si.teacher

    def test_evidence_collector_alias(self):
        si = SecurityIntelligence()
        assert si.evidence_collector is si.evidence_analyzer

    def test_get_profile_method(self):
        si = SecurityIntelligence()
        profile = si.learning_profile.get_profile()
        assert profile.user_id == "default_student"
