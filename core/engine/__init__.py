"""
HunterAI Autonomous Engine Package
"""
from core.engine.skill_matrix import (
    SKILL_MATRIX,
    VulnClass,
    ToolCategory,
    TeamSkillProfile,
    get_team_for_asset,
    get_teams_for_vuln,
    skill_gap_analysis,
)
from core.engine.persistence_watchdog import (
    AssessmentSnapshot,
    PersistenceWatchdog,
    StallDetector,
    RetryPolicy,
    ProgressSnapshot,
)
from core.engine.omni_hunter_engine import (
    OmniHunterEngine,
    AssessmentConfig,
    AssessmentResult,
    AssessmentPhase,
    InformationGainPlanner,
)
from core.engine.real_tool_adapter import (
    RealToolAdapter,
    ToolExecutionResult as AdapterExecutionResult,
)
from core.engine.poc_bundle_generator import (
    PoCBundleGenerator,
    FindingContext,
)
from core.auth.identity_matrix import (
    DualIdentityMatrix,
    IdentityContext,
    IDORVerdict,
    DifferentialEvidence,
)
from core.oob.oob_engine import (
    OOBEngine,
    OOBVerdictReport,
)

__all__ = [
    "SKILL_MATRIX",
    "VulnClass",
    "ToolCategory",
    "TeamSkillProfile",
    "get_team_for_asset",
    "get_teams_for_vuln",
    "skill_gap_analysis",
    "AssessmentSnapshot",
    "PersistenceWatchdog",
    "StallDetector",
    "RetryPolicy",
    "ProgressSnapshot",
    "OmniHunterEngine",
    "AssessmentConfig",
    "AssessmentResult",
    "AssessmentPhase",
    "InformationGainPlanner",
    "RealToolAdapter",
    "AdapterExecutionResult",
    "PoCBundleGenerator",
    "FindingContext",
    "DualIdentityMatrix",
    "IdentityContext",
    "IDORVerdict",
    "DifferentialEvidence",
    "OOBEngine",
    "OOBVerdictReport",
]
