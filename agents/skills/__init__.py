# agents/skills package
from agents.skills.sqli_skill import (
    SQLiSkill,
    SQLiState,
    DBMSType,
    SQLI_CHEAT_SHEET,
    run_sqli_skill,
)
from agents.skills.safe_sqli_assessment import (
    SafeSQLiAssessmentSkill,
    ScopeGate,
    ScopePolicy,
    BaselineProfiler,
    ParameterClassifier,
    DifferentialSQLiEngine,
    SecondOrderTracker,
    CodeORMAuditor,
    ReportGenerator,
    ConfidenceLevel,
    FindingClassification,
    SQLiContextType,
    ParameterType,
)

from agents.skills.ssrf_skill import (
    SSRFSkill,
    SSRFState,
)
from agents.skills.idor_skill import (
    IDORSkill,
    IDORState,
    IDType,
    run_idor_skill,
    IDPermutator,
)
from agents.skills.xss_skill import (
    XSSSkill,
    XSSState,
    XSSContextType,
    run_xss_skill,
)

from agents.skills.ssti_skill import SSTISkill
from agents.skills.xxe_skill import XXESkill
from agents.skills.cors_skill import CORSSkill
from agents.skills.file_upload_skill import FileUploadSkill
from agents.skills.jwt_oauth_skill import JWTOAuthSkill
from agents.skills.race_condition_skill import RaceConditionSkill
from agents.skills.graphql_skill import GraphQLSkill
from agents.skills.websocket_skill import WebSocketSkill
from agents.skills.idor_skill import IDORMatrixSkill

# ─── مهارات جديدة (v2 arsenal) ───
from agents.skills.open_redirect_skill import OpenRedirectSkill
from agents.skills.host_header_injection_skill import HostHeaderInjectionSkill
from agents.skills.nosql_injection_skill import NoSQLInjectionSkill
from agents.skills.crlf_injection_skill import CRLFSkill
from agents.skills.hpp_skill import HTTPParameterPollutionSkill
from agents.skills.ldap_injection_skill import LDAPInjectionSkill
from agents.skills.bug_bounty_master_skill import BugBountyMasterSkill
from agents.skills.session_flaws_skill import SessionFlawsSkill
from agents.skills.browser_adapter_skills import (
    BrowserReconAdapterSkill,
    FormIntelligenceAdapterSkill,
    NetworkIntelligenceAdapterSkill,
    BehaviorAnalysisAdapterSkill,
    BrowserSensorAdapterSkill,
)
from agents.skills.registry import SkillRegistry, SkillMeta, bootstrap_builtin_skills

__all__ = [
    "SQLiSkill",
    "SQLiState",
    "DBMSType",
    "SQLI_CHEAT_SHEET",
    "run_sqli_skill",
    "SafeSQLiAssessmentSkill",
    "ScopeGate",
    "ScopePolicy",
    "BaselineProfiler",
    "ParameterClassifier",
    "DifferentialSQLiEngine",
    "SecondOrderTracker",
    "CodeORMAuditor",
    "ReportGenerator",
    "ConfidenceLevel",
    "FindingClassification",
    "SQLiContextType",
    "ParameterType",
    "SSRFSkill",
    "SSRFState",
    "IDORSkill",
    "IDORMatrixSkill",
    "IDORState",
    "IDType",
    "run_idor_skill",
    "IDPermutator",
    "XSSSkill",
    "XSSState",
    "XSSContextType",
    "run_xss_skill",
    "SSTISkill",
    "XXESkill",
    "CORSSkill",
    "FileUploadSkill",
    "JWTOAuthSkill",
    "RaceConditionSkill",
    "GraphQLSkill",
    "WebSocketSkill",
    "OpenRedirectSkill",
    "HostHeaderInjectionSkill",
    "NoSQLInjectionSkill",
    "CRLFSkill",
    "HTTPParameterPollutionSkill",
    "LDAPInjectionSkill",
    "BugBountyMasterSkill",
    "SessionFlawsSkill",
    "BrowserReconAdapterSkill",
    "FormIntelligenceAdapterSkill",
    "NetworkIntelligenceAdapterSkill",
    "BehaviorAnalysisAdapterSkill",
    "BrowserSensorAdapterSkill",
    "SkillRegistry",
    "SkillMeta",
    "bootstrap_builtin_skills",
]


