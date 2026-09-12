"""
Security Intelligence & Education Brain (Unified Layer Facade)
Standardized Unified API for Context, Reasoning, Hypothesis, Contradiction, Critic, Confidence, Decision, Research, and Education.
"""
import logging
from typing import Dict, List, Any, Optional, Union, Tuple

from agents.security_intelligence.schemas import (
    SecurityObservation,
    SecurityHypothesis,
    EvidenceItem,
    IntelligenceFinding,
    SecurityLesson,
    QuizQuestion,
    QuizEvaluation,
    ResearchReport,
    ScopeRule,
    ScopeCheckResult,
    ScopeDecision,
    SecurityContext,
    SecurityDecision,
    ObservationType,
    FindingStatus
)
from agents.security_intelligence.events import SecurityEventBus, SecurityEvent, SecurityEventType
from agents.security_intelligence.scope_guard import ScopeGuard
from agents.security_intelligence.finding_validator import FindingValidator
from agents.security_intelligence.memory_manager import MemoryManager
from agents.security_intelligence.knowledge_engine import KnowledgeEngine
from agents.security_intelligence.context_engine import ContextEngine
from agents.security_intelligence.evidence_analyzer import EvidenceAnalyzer
from agents.security_intelligence.hypothesis_engine import HypothesisEngine
from agents.security_intelligence.critic import CriticEngine
from agents.security_intelligence.contradiction_engine import ContradictionEngine
from agents.security_intelligence.confidence_engine import ConfidenceEngine
from agents.security_intelligence.decision_engine import SecurityDecisionEngine
from agents.security_intelligence.vulnerability_analyst import VulnerabilityAnalyst
from agents.security_intelligence.reasoning_engine import ReasoningEngine
from agents.security_intelligence.research_cache import ResearchCache
from agents.security_intelligence.researcher import ResearcherEngine
from agents.security_intelligence.explanation_engine import ExplanationEngine
from agents.security_intelligence.curriculum_engine import CurriculumEngine
from agents.security_intelligence.quiz_engine import QuizEngine
from agents.security_intelligence.learning_profile import LearningProfile
from agents.security_intelligence.teacher import TeacherAgent
from agents.security_intelligence.model_router import IntelligenceModelRouter
from agents.security_intelligence.tool_registry import ToolRegistry

log = logging.getLogger("security_intelligence.brain")


class SecurityIntelligence:
    """
    الواجهة المركزية الموحدة لطبقة الاستدلال الأمني والمعرفي في PentestAI-Unified
    """

    def __init__(self, scope_rule: Optional[ScopeRule] = None):
        # 1. Foundation & Governance
        self.scope_guard = ScopeGuard(scope_rule)
        self.bus = SecurityEventBus()
        self.tools = ToolRegistry()
        self.model_router = IntelligenceModelRouter()

        # 2. Knowledge & Memory Layer
        self.kb = KnowledgeEngine()
        self.memory = MemoryManager()
        self.learning_profile = LearningProfile()
        self.research_cache = ResearchCache()

        # 3. Context & Analytical Core
        self.context = ContextEngine(self.memory)
        self.evidence_analyzer = EvidenceAnalyzer()
        self.confidence_engine = ConfidenceEngine()
        self.hypothesis_engine = HypothesisEngine(self.kb)
        self.critic = CriticEngine(self.memory.false_positive)
        self.contradiction = ContradictionEngine()
        self.decision = SecurityDecisionEngine()

        self.analyst = VulnerabilityAnalyst(
            hypothesis_engine=self.hypothesis_engine,
            evidence_analyzer=self.evidence_analyzer,
            critic_engine=self.critic,
            contradiction_engine=self.contradiction,
            context_engine=self.context,
            knowledge_engine=self.kb,
            memory_manager=self.memory
        )
        self.reasoning = ReasoningEngine(self.memory)

        # 4. Research & Educational Suite
        self.researcher = ResearcherEngine(self.kb, cache=self.research_cache)
        self.explanation = ExplanationEngine(self.kb)
        self.quiz = QuizEngine(self.kb)
        self.curriculum = CurriculumEngine(self.memory.learning)
        self.teacher = TeacherAgent(
            explanation_engine=self.explanation,
            quiz_engine=self.quiz,
            curriculum_engine=self.curriculum,
            knowledge_engine=self.kb,
            learning_memory=self.memory.learning,
            learning_profile=self.learning_profile
        )

        # 5. Finding Validation & Lifecycle Engine (Shannon & Dark-Moon inspired)
        self.validator = FindingValidator()

    # ------------------------------------------------------------------
    # Property aliases (consistent API for callers using _engine suffix)
    # ------------------------------------------------------------------
    @property
    def context_engine(self) -> ContextEngine:
        return self.context

    @property
    def contradiction_engine(self) -> ContradictionEngine:
        return self.contradiction

    @property
    def decision_engine(self) -> SecurityDecisionEngine:
        return self.decision

    @property
    def security_teacher(self) -> TeacherAgent:
        return self.teacher

    @property
    def evidence_collector(self) -> EvidenceAnalyzer:
        return self.evidence_analyzer

    @property
    def finding_validator(self) -> FindingValidator:
        return self.validator

    def validate_finding_transition(
        self,
        finding: IntelligenceFinding,
        target_status: FindingStatus,
        new_evidence: Optional[List[EvidenceItem]] = None,
        poc_steps: Optional[List[str]] = None,
        reproduction_curl: Optional[str] = None,
        impact_description: Optional[str] = None
    ) -> Tuple[bool, str]:
        """التحقق من أهلية انتقال الثغرة إلى حالة أخرى"""
        return self.validator.can_transition(
            finding, target_status, new_evidence, poc_steps, reproduction_curl, impact_description
        )

    def transition_finding(
        self,
        finding: IntelligenceFinding,
        target_status: FindingStatus,
        actor: str = "SecurityIntelligence",
        rationale: str = "",
        new_evidence: Optional[List[EvidenceItem]] = None,
        poc_steps: Optional[List[str]] = None,
        reproduction_curl: Optional[str] = None,
        impact_description: Optional[str] = None
    ) -> Tuple[bool, str, IntelligenceFinding]:
        """تنفيذ انتقال حالة الثغرة وتحديث سجل التحولات"""
        return self.validator.transition_finding(
            finding, target_status, actor, rationale, new_evidence, poc_steps, reproduction_curl, impact_description
        )

    def set_scope(self, rule: ScopeRule):
        """تحديث سياسة النطاق والتصاريح"""
        self.scope_guard.set_scope(rule)

    def evaluate_scope(self, target: str, action: str = "passive_analysis") -> ScopeDecision:
        """فحص النطاق متعدد المستويات وإرجاع ScopeDecision"""
        return self.scope_guard.evaluate_scope_decision(target, action)

    def is_traffic_interesting(self, url: str, method: str = "GET", headers: Optional[Dict] = None, body: Any = None) -> bool:
        """فلترة أولية خفيفة للترافيك لتحديد ما إذا كان يستحق المعالجة المعرفية"""
        return self.tools.is_interesting_traffic(url, method, headers or {}, body)

    async def get_context(self, observation_or_target: Union[SecurityObservation, str], project_id: str = "default_project") -> SecurityContext:
        """استخراج السياق الأمني الشامل"""
        if isinstance(observation_or_target, SecurityObservation):
            return self.context.build_context(observation_or_target)
        else:
            # Fallback observation for target string
            dummy_obs = SecurityObservation(
                target=observation_or_target,
                project_id=project_id,
                obs_type=ObservationType.ENDPOINT,
                data={"path": "/", "method": "GET"}
            )
            return self.context.build_context(dummy_obs)

    async def analyze_observation(
        self,
        observation: SecurityObservation,
        extra_evidence: Optional[List[EvidenceItem]] = None
    ) -> List[IntelligenceFinding]:
        """
        التحليل الأمني الشامل:
        Observation -> Scope Check -> Context -> Hypotheses -> Evidence -> Critic & Contradictions -> Confidence -> Findings
        """
        target = observation.target
        scope_dec = self.scope_guard.evaluate_scope_decision(target, action="passive_analysis")
        if not scope_dec.allowed:
            log.warning(f"Analysis skipped for target {target}: {scope_dec.reason}")
            await self.bus.publish(SecurityEvent(
                event_type=SecurityEventType.SCOPE_VIOLATION,
                target=target,
                source="SecurityIntelligence.analyze",
                data={"reason": scope_dec.reason, "mode": scope_dec.mode.value}
            ))
            return []

        # Execute Enhanced Vulnerability Analyst pipeline
        findings = self.analyst.analyze_observation(observation, extra_evidence=extra_evidence)

        # Publish Events
        for f in findings:
            await self.bus.publish(SecurityEvent(
                event_type=SecurityEventType.FINDING_CREATED,
                project_id=f.project_id,
                target=f.target,
                source="VulnerabilityAnalyst",
                data={"finding_id": f.id, "title": f.title, "type": f.vulnerability_type},
                confidence=f.confidence_score,
                operation_id=observation.operation_id,
                correlation_id=observation.correlation_id
            ))

        return findings

    # Alias for analyze_observation for flexible calling
    async def analyze(
        self,
        observation: SecurityObservation,
        extra_evidence: Optional[List[EvidenceItem]] = None
    ) -> List[IntelligenceFinding]:
        return await self.analyze_observation(observation, extra_evidence=extra_evidence)

    async def decide(self, finding: IntelligenceFinding, context: Optional[SecurityContext] = None) -> SecurityDecision:
        """تقديم توجيه وقرار أمني مبرر حول الخطوة التالية بناءً على النتيجة"""
        decision = self.decision.evaluate_finding_decision(finding)
        await self.bus.publish(SecurityEvent(
            event_type=SecurityEventType.DECISION_CREATED,
            project_id=finding.project_id,
            target=finding.target,
            source="SecurityDecisionEngine",
            data={"decision_id": decision.id, "action": decision.recommended_action, "priority": decision.action_priority.value}
        ))
        return decision

    async def generate_hypotheses(self, observation: SecurityObservation) -> List[SecurityHypothesis]:
        """توليد الفرضيات الأمنية المسبقة لملاحظة معينة"""
        return self.hypothesis_engine.generate_hypotheses(observation)

    async def evaluate_evidence(self, items: List[EvidenceItem]) -> Dict[str, Any]:
        """تقييم سلسلة الأدلة وحساب الوزن التراكمي"""
        return self.evidence_analyzer.evaluate_evidence_chain(items)

    async def research(self, topic_or_cve: str) -> ResearchReport:
        """البحث الأمني المتعمق والتحقق من مصادر CVE وقواعد البيانات مع التخزين المؤقت"""
        report = await self.researcher.research_topic_or_cve(topic_or_cve)
        await self.bus.publish(SecurityEvent(
            event_type=SecurityEventType.RESEARCH_COMPLETED,
            target=topic_or_cve,
            source="ResearcherEngine",
            data={"topic": report.topic, "summary": report.summary, "cached": report.cached}
        ))
        return report

    async def research_topic(self, topic_or_cve: str) -> ResearchReport:
        """Alias for research"""
        return await self.research(topic_or_cve)

    async def explain(
        self,
        subject: str,
        finding: Optional[IntelligenceFinding] = None,
        language: str = "ar"
    ) -> Dict[str, str]:
        """توليد شرح شامل عبر المستويات الأربعة (ببساطة، تقني، بينتستر، باحث)"""
        return self.explanation.generate_multi_level_explanation(subject, finding=finding, language=language)

    async def teach_from_finding(self, finding: IntelligenceFinding) -> SecurityLesson:
        """تحويل ثغرة مكتشفة إلى درس تعليمي فوري تفاعلي"""
        lesson = self.teacher.teach_from_finding(finding)
        await self.bus.publish(SecurityEvent(
            event_type=SecurityEventType.LESSON_CREATED,
            project_id=finding.project_id,
            target=finding.target,
            source="TeacherAgent",
            data={"lesson_id": lesson.id, "topic": lesson.topic}
        ))
        return lesson

    async def teach_finding(self, finding: IntelligenceFinding) -> SecurityLesson:
        """Alias for teach_from_finding"""
        return await self.teach_from_finding(finding)

    async def create_lesson(self, topic: str) -> SecurityLesson:
        """إنشاء درس أمني لمفهوم معين"""
        return self.teacher.create_topic_lesson(topic)

    async def start_quiz(self, topic: str) -> QuizQuestion:
        """إنشاء اختبار تفاعلي لمفهوم معين"""
        return self.teacher.get_quiz_for_topic(topic)

    async def create_quiz(self, topic: str) -> QuizQuestion:
        """Alias for start_quiz"""
        return await self.start_quiz(topic)

    async def evaluate_quiz_answer(self, quiz: QuizQuestion, choice_idx: int) -> QuizEvaluation:
        """تقييم إجابة المستخدم وتحديث ملف التعلم الشخصي"""
        return self.teacher.evaluate_quiz(quiz, choice_idx)

    async def evaluate_user_answer(self, quiz: QuizQuestion, choice_idx: int) -> QuizEvaluation:
        """Alias for evaluate_quiz_answer"""
        return await self.evaluate_quiz_answer(quiz, choice_idx)

    async def correlate_attack_chains(self, target: str, findings: List[IntelligenceFinding]) -> Dict[str, Any]:
        """ربط الثغرات وبناء مسارات الهجوم التراكمية"""
        return self.reasoning.correlate_findings(target, findings)
