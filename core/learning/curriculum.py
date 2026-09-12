"""
Structured 10-Level Security Curriculum
Defines the progressive training curriculum from Level 0 (HTTP Fundamentals)
up to Level 9 (Complex Multi-Step Kill Chains).
"""
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field


class CurriculumLevel(BaseModel):
    level: int
    title: str
    description: str
    objectives: List[str]
    knowledge_ids: List[str]
    sample_question: Dict[str, Any]
    lab_scenario: str


CURRICULUM_LEVELS: List[CurriculumLevel] = [
    CurriculumLevel(
        level=0,
        title="HTTP Fundamentals",
        description="Understanding HTTP protocol verbs, statelessness, status codes, and message semantics.",
        objectives=["Understand GET/POST semantics", "Interpret 200 vs 401 vs 403 vs 404 status codes"],
        knowledge_ids=["http_001"],
        sample_question={
            "question": "What is the primary difference between HTTP 401 and 403?",
            "options": ["401 is unauthorized identity, 403 is authenticated but forbidden", "401 is server error", "They are identical"],
            "correct_index": 0
        },
        lab_scenario="http_headers_inspection"
    ),
    CurriculumLevel(
        level=1,
        title="Request / Response Anatomy",
        description="Parsing HTTP headers, bodies, content types, and query strings.",
        objectives=["Analyze URL query parameters", "Inspect JSON body payloads"],
        knowledge_ids=["http_001"],
        sample_question={
            "question": "Which header indicates client payload format?",
            "options": ["Content-Type", "User-Agent", "Accept-Encoding"],
            "correct_index": 0
        },
        lab_scenario="body_format_mutation"
    ),
    CurriculumLevel(
        level=2,
        title="Authentication Systems",
        description="Session cookies, Bearer tokens, JWT mechanics, and authentication state boundaries.",
        objectives=["Inspect Bearer tokens", "Recognize session expiration"],
        knowledge_ids=["jwt_001"],
        sample_question={
            "question": "What vulnerability arises if a JWT uses 'alg': 'none'?",
            "options": ["Signature verification is bypassed completely", "Token cannot be parsed", "Server crashes with 500"],
            "correct_index": 0
        },
        lab_scenario="jwt_tampering_lab"
    ),
    CurriculumLevel(
        level=3,
        title="Object-Level Authorization (BOLA)",
        description="Tenant boundary validation, resource identifier tampering, and cross-account data isolation.",
        objectives=["Detect numeric and UUID object IDs", "Execute differential baseline vs probe requests"],
        knowledge_ids=["authz_001", "method_001"],
        sample_question={
            "question": "How do you definitively prove a BOLA vulnerability exists?",
            "options": ["Compare response body between user A and user B accessing the same resource ID", "Look for 200 OK only", "Send an invalid ID"],
            "correct_index": 0
        },
        lab_scenario="BOLA_MultiTenant_Enterprise"
    ),
    CurriculumLevel(
        level=4,
        title="Function-Level Authorization (BFLA)",
        description="Role-based access control (RBAC), administrative routing, and horizontal vs vertical privilege escalation.",
        objectives=["Identify administrative endpoints", "Test role separation across user tiers"],
        knowledge_ids=["authz_002"],
        sample_question={
            "question": "Why does a 200 OK response to an admin route not guarantee BFLA?",
            "options": ["The response might be a generic login page or redirect", "Admin routes are always public", "Status codes don't matter"],
            "correct_index": 0
        },
        lab_scenario="bfla_admin_panel_lab"
    ),
    CurriculumLevel(
        level=5,
        title="API Security & Parameter Handling",
        description="RESTful resource modeling, GraphQL endpoints, and mass assignment flaws.",
        objectives=["Analyze REST hierarchy", "Identify bound JSON parameters"],
        knowledge_ids=["authz_001"],
        sample_question={
            "question": "What is Mass Assignment?",
            "options": ["Automatic binding of client request fields into internal model properties", "Assigning tasks to multiple agents", "High CPU load"],
            "correct_index": 0
        },
        lab_scenario="mass_assignment_lab"
    ),
    CurriculumLevel(
        level=6,
        title="Input Handling & Injections",
        description="SQL Injection, Command Injection, and template injection mechanisms.",
        objectives=["Craft parameterized differential SQL probes", "Detect database syntax anomalies"],
        knowledge_ids=["sqli_001"],
        sample_question={
            "question": "What is the key indicator in blind SQL injection?",
            "options": ["Predictable behavioral or timing differences between true and false conditions", "An immediate alert popup", "Status 404"],
            "correct_index": 0
        },
        lab_scenario="Blind_SQLi_Catalog"
    ),
    CurriculumLevel(
        level=7,
        title="Differential Testing & Telemetry",
        description="Measuring response lengths, header changes, timing differences, and cryptographic hashing.",
        objectives=["Calculate cosine content deltas", "Filter out dynamic timestamps and session nonces"],
        knowledge_ids=["method_001"],
        sample_question={
            "question": "Why must dynamic tokens be normalized during differential testing?",
            "options": ["To avoid detecting benign session timestamp differences as vulnerability proof", "To speed up requests", "To bypass firewalls"],
            "correct_index": 0
        },
        lab_scenario="differential_telemetry_lab"
    ),
    CurriculumLevel(
        level=8,
        title="Vulnerability Verification & Proof",
        description="Five-stage finding lifecycle: Observed -> Suspected -> Confirmed -> Exploited -> Impact Verified.",
        objectives=["Produce tamper-evident SHA256 evidence chains", "Reject unverified hallucinations"],
        knowledge_ids=["authz_001", "sqli_001", "method_001"],
        sample_question={
            "question": "Which stage in the finding lifecycle requires differential proof?",
            "options": ["CONFIRMED", "OBSERVED", "SUSPECTED"],
            "correct_index": 0
        },
        lab_scenario="evidence_validation_lab"
    ),
    CurriculumLevel(
        level=9,
        title="Multi-Step Kill Chains",
        description="Chaining reconnaissance, authentication bypass, authorization failure, and impact realization.",
        objectives=["Model blast radius", "Identify defensive chokepoints in causal attack graphs"],
        knowledge_ids=["authz_001", "authz_002", "sqli_001", "ssrf_001"],
        sample_question={
            "question": "What is a defensive chokepoint in an attack graph?",
            "options": ["A critical node that, if remediated, breaks the maximum number of kill chains", "A slow network firewall", "A DoS bottleneck"],
            "correct_index": 0
        },
        lab_scenario="full_kill_chain_scenario"
    )
]


class SecurityCurriculum:
    """إدارة وتتبع مسارات التدريب والمنهج الأمني"""

    def __init__(self):
        self.levels: Dict[int, CurriculumLevel] = {lvl.level: lvl for lvl in CURRICULUM_LEVELS}

    def get_level(self, level: int) -> Optional[CurriculumLevel]:
        return self.levels.get(level)

    def get_all_levels(self) -> List[CurriculumLevel]:
        return sorted(self.levels.values(), key=lambda l: l.level)
