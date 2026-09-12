"""
HunterAI Runtime Package
========================
Provides the Claude-style Agent Scaffolding Runtime:
- AgentRuntime
- HypothesisTree, HypothesisNode, HypothesisStatus
- PersistentWorkingMemory
- ToolRegistry, ToolRiskLevel, build_default_tool_registry
- SelfCritiqueValidator, CritiqueStatus, CritiqueVerdict
"""
from hunter_ai.runtime.hypothesis_tree import HypothesisTree, HypothesisNode, HypothesisStatus
from hunter_ai.runtime.working_memory import PersistentWorkingMemory
from hunter_ai.runtime.tool_registry import ToolRegistry, ToolRiskLevel, build_default_tool_registry
from hunter_ai.runtime.self_critique import SelfCritiqueValidator, CritiqueStatus, CritiqueVerdict
from hunter_ai.runtime.world_model import (
    ApplicationWorldModel, IdentityGraph, UserIdentity, ResourceObject,
    RoleLevel, ApplicationStateMachine, StateTransition
)
from hunter_ai.runtime.invariant_engine import (
    InvariantEngine, SecurityInvariant, InvariantViolation, InvariantType
)
from hunter_ai.runtime.scientific_engine import (
    SecurityResearchOS, CoverageTracker, CausalGraph, ScientificExperiment,
    NextBestAction, ActionKind
)
from hunter_ai.runtime.cross_endpoint import (
    CrossEndpointCorrelator, DataFlowLink, DeveloperAssumption, AssumptionKind, EndpointSignature
)
from hunter_ai.runtime.cognitive_core import (
    NoiseModel, NoiseProfile, BayesianHypothesisCompetition, CompetingExplanation,
    AutomaticInvariantDiscovery, DiscoveredRule, FalsificationEngine, ReproducibilityVerifier,
    MetamorphicEngine, MetamorphicRelation, RootCauseClusteringEngine, ClusteredVulnerability,
    MemoryDecayManager, EphemeralObservation
)
from hunter_ai.runtime.meta_reasoning import (
    CapabilityGraph, Capability, BehavioralFingerprint, DeviationReport, BehavioralFingerprinter,
    FourPersonaCouncil, PersonaVerdict, CouncilJudgment, MetaReasoner, StrategyState, MetaStrategyStatus
)
from hunter_ai.runtime.epistemic_engine import (
    EpistemicType, EpistemicNode, EvidenceGraph, PredictiveExperimentSpec,
    AgentCompiler, CompiledResearchPlan, ResearchPostmortemEvaluator, ResearchPostmortem
)
from hunter_ai.runtime.theory_engine import (
    InferredArchitecture, ArchitectureTier, LatentArchitectureInferrer,
    TrustLevel, TrustTransition, TrustBoundaryMapper,
    LifecycleStage, LifecycleViolation, ObjectLifecycleTracker,
    SemanticFieldChange, SemanticDiffAnalyzer,
    CuriousEvent, CuriosityEngine,
    DecisionReplayStep, DecisionReplayLedger
)
from hunter_ai.runtime.causal_pomdp import (
    POMDPBeliefDistribution, CausalInterventionEngine, CausalInterventionResult,
    ApiGrammarInductionEngine, ApiEndpointGrammar, ResourceGrammarSegment, ParamCategory,
    TemporalLogicVerifier, TemporalOperator, TemporalSecurityRule, TemporalTraceEvent, TemporalViolation,
    DeltaDebuggingMinimizer, MinimalTraceResult,
    SecurityModelChecker, ReachabilityViolation,
    CognitiveDiversityCouncil, CognitiveRole, PersonaOpinion, CouncilSynthesis,
    SelfEvolvingStrategyGenome, StrategyGene
)
from hunter_ai.runtime.agent_runtime import AgentRuntime

__all__ = [
    "AgentRuntime",
    "HypothesisTree",
    "HypothesisNode",
    "HypothesisStatus",
    "PersistentWorkingMemory",
    "ToolRegistry",
    "ToolRiskLevel",
    "build_default_tool_registry",
    "SelfCritiqueValidator",
    "CritiqueStatus",
    "CritiqueVerdict",
    "ApplicationWorldModel",
    "IdentityGraph",
    "UserIdentity",
    "ResourceObject",
    "RoleLevel",
    "ApplicationStateMachine",
    "StateTransition",
    "InvariantEngine",
    "SecurityInvariant",
    "InvariantViolation",
    "InvariantType",
    "SecurityResearchOS",
    "CoverageTracker",
    "CausalGraph",
    "ScientificExperiment",
    "NextBestAction",
    "ActionKind",
    "CrossEndpointCorrelator",
    "DataFlowLink",
    "DeveloperAssumption",
    "AssumptionKind",
    "EndpointSignature",
    "NoiseModel",
    "NoiseProfile",
    "BayesianHypothesisCompetition",
    "CompetingExplanation",
    "AutomaticInvariantDiscovery",
    "DiscoveredRule",
    "FalsificationEngine",
    "ReproducibilityVerifier",
    "MetamorphicEngine",
    "MetamorphicRelation",
    "RootCauseClusteringEngine",
    "ClusteredVulnerability",
    "MemoryDecayManager",
    "EphemeralObservation",
    "CapabilityGraph",
    "Capability",
    "BehavioralFingerprint",
    "DeviationReport",
    "BehavioralFingerprinter",
    "FourPersonaCouncil",
    "PersonaVerdict",
    "CouncilJudgment",
    "MetaReasoner",
    "StrategyState",
    "MetaStrategyStatus",
    "EpistemicType",
    "EpistemicNode",
    "EvidenceGraph",
    "PredictiveExperimentSpec",
    "AgentCompiler",
    "CompiledResearchPlan",
    "ResearchPostmortemEvaluator",
    "ResearchPostmortem",
    "InferredArchitecture",
    "ArchitectureTier",
    "LatentArchitectureInferrer",
    "TrustLevel",
    "TrustTransition",
    "TrustBoundaryMapper",
    "LifecycleStage",
    "LifecycleViolation",
    "ObjectLifecycleTracker",
    "SemanticFieldChange",
    "SemanticDiffAnalyzer",
    "CuriousEvent",
    "CuriosityEngine",
    "DecisionReplayStep",
    "DecisionReplayLedger",
    "POMDPBeliefDistribution",
    "CausalInterventionEngine",
    "CausalInterventionResult",
    "ApiGrammarInductionEngine",
    "ApiEndpointGrammar",
    "ResourceGrammarSegment",
    "ParamCategory",
    "TemporalLogicVerifier",
    "TemporalOperator",
    "TemporalSecurityRule",
    "TemporalTraceEvent",
    "TemporalViolation",
    "DeltaDebuggingMinimizer",
    "MinimalTraceResult",
    "SecurityModelChecker",
    "ReachabilityViolation",
    "CognitiveDiversityCouncil",
    "CognitiveRole",
    "PersonaOpinion",
    "CouncilSynthesis",
    "SelfEvolvingStrategyGenome",
    "StrategyGene",
]
