"""
Granular Skill Graph & Diagnostic Competence Model
Maintains a hierarchical Directed Acyclic Graph (DAG) of security skills and sub-skills.
Tracks atomic proficiencies, diagnoses specific agent reasoning weaknesses,
and recommends targeted training scenarios based on prerequisite traversal.
"""
import sqlite3
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field

log = logging.getLogger("core.learning.skill_graph")

DATA_DIR = Path("data/learning")
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "skill_graph.sqlite3"


class SkillNode(BaseModel):
    """عقدة كفاءة مهارية ذرية في الرسم البياني للمهارات"""
    skill_id: str
    name: str
    category: str                       # sqli, authz, recon, differential, etc.
    parent_skill: Optional[str] = None
    proficiency: float = 0.50           # [0.0, 1.0]
    attempts_count: int = 0
    success_count: int = 0
    consecutive_failures: int = 0
    prerequisites: List[str] = Field(default_factory=list)
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


# ── Canonical Granular Security Skills DAG ──────────────────────────────
CANONICAL_SKILL_TREE: List[SkillNode] = [
    # Top-level domains
    SkillNode(
        skill_id="http_protocol",
        name="HTTP Protocol Semantics",
        category="foundations",
        proficiency=0.90,
        description="Understanding statelessness, verbs, headers, status codes, and message bodies."
    ),
    SkillNode(
        skill_id="differential_testing",
        name="Differential Testing Methodology",
        category="methodology",
        parent_skill="http_protocol",
        prerequisites=["http_protocol"],
        proficiency=0.75,
        description="Establishing baselines and measuring behavioral divergences across inputs/identities."
    ),

    # SQL Injection Sub-tree
    SkillNode(
        skill_id="sqli_core",
        name="SQL Injection Core",
        category="sqli",
        parent_skill="differential_testing",
        prerequisites=["http_protocol", "differential_testing"],
        proficiency=0.70,
        description="Understanding query interpolation, input reflection, and syntax boundaries."
    ),
    SkillNode(
        skill_id="sqli_boolean_differential",
        name="SQLi Boolean Differential Reasoning",
        category="sqli",
        parent_skill="sqli_core",
        prerequisites=["sqli_core"],
        proficiency=0.65,
        description="Inferring query execution state via contrasting true/false boolean predicates."
    ),
    SkillNode(
        skill_id="sqli_error_analysis",
        name="SQLi Database Error Differentiation",
        category="sqli",
        parent_skill="sqli_core",
        prerequisites=["sqli_core"],
        proficiency=0.60,
        description="Distinguishing application validation errors (400) from RDBMS syntax exceptions (500)."
    ),
    SkillNode(
        skill_id="sqli_union_enumeration",
        name="SQLi UNION Column Enumeration",
        category="sqli",
        parent_skill="sqli_core",
        prerequisites=["sqli_boolean_differential"],
        proficiency=0.55,
        description="Determining query column count via ORDER BY boundaries and data type compatibility."
    ),
    SkillNode(
        skill_id="sqli_blind_inference",
        name="SQLi Blind Side-Effect Inference",
        category="sqli",
        parent_skill="sqli_boolean_differential",
        prerequisites=["sqli_boolean_differential"],
        proficiency=0.50,
        description="Inferring database secrets through subtle application behavior with zero visible DB output."
    ),
    SkillNode(
        skill_id="sqli_time_statistical",
        name="SQLi Time-Based Statistical Filtering",
        category="sqli",
        parent_skill="sqli_blind_inference",
        prerequisites=["sqli_blind_inference"],
        proficiency=0.45,
        description="Isolating injected sleep delays from background network jitter through repeated sampling."
    ),
    SkillNode(
        skill_id="sqli_evidence_validation",
        name="SQLi Differential Proof & Validation",
        category="sqli",
        parent_skill="sqli_core",
        prerequisites=["sqli_core"],
        proficiency=0.70,
        description="Producing conclusive cryptographic evidence hashes proving query alteration."
    ),

    # Authorization Sub-tree
    SkillNode(
        skill_id="authz_core",
        name="Authorization & Access Control",
        category="authz",
        parent_skill="differential_testing",
        prerequisites=["http_protocol", "differential_testing"],
        proficiency=0.75,
        description="Evaluating permission boundaries and session identity context."
    ),
    SkillNode(
        skill_id="authz_object_isolation",
        name="Object-Level Tenant Isolation (BOLA)",
        category="authz",
        parent_skill="authz_core",
        prerequisites=["authz_core"],
        proficiency=0.70,
        description="Testing cross-tenant data leakage by swapping object identifiers across session tokens."
    ),
    SkillNode(
        skill_id="authz_function_privilege",
        name="Function-Level Access Control (BFLA)",
        category="authz",
        parent_skill="authz_core",
        prerequisites=["authz_core"],
        proficiency=0.65,
        description="Verifying role-based route protection on administrative endpoints."
    ),

    # Reconnaissance & Attack Surface Management Sub-tree
    SkillNode(
        skill_id="recon_core",
        name="Attack Surface Reconnaissance",
        category="recon",
        parent_skill="http_protocol",
        prerequisites=["http_protocol"],
        proficiency=0.80,
        description="Comprehensive passive and active attack surface mapping, asset discovery, and endpoint clustering."
    ),
    SkillNode(
        skill_id="recon_subdomain_discovery",
        name="Subdomain Enumeration & Host Resolution",
        category="recon",
        parent_skill="recon_core",
        prerequisites=["recon_core"],
        proficiency=0.75,
        description="Orchestrating multi-source passive OSINT, DNS resolution, and alive host filtering."
    ),
    SkillNode(
        skill_id="recon_content_discovery",
        name="Content & Sensitive Artifact Discovery",
        category="recon",
        parent_skill="recon_core",
        prerequisites=["recon_core"],
        proficiency=0.70,
        description="Identifying exposed configuration backups, environment files, and administrative interfaces."
    ),
    SkillNode(
        skill_id="recon_parameter_discovery",
        name="Parameter & Query Surface Mapping",
        category="recon",
        parent_skill="recon_core",
        prerequisites=["recon_core"],
        proficiency=0.70,
        description="Uncovering undocumented parameters and entry points using differential analysis."
    )
]



class SkillGraph:
    """
    رسم بياني هرمي لتشخيص وإدارة كفاءة مهارات الـ Agent
    """

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self._init_db()
        self._seed_canonical_tree()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS skills (
                    skill_id TEXT PRIMARY KEY,
                    name TEXT,
                    category TEXT,
                    parent_skill TEXT,
                    proficiency REAL,
                    attempts_count INTEGER,
                    success_count INTEGER,
                    consecutive_failures INTEGER,
                    prerequisites TEXT,
                    description TEXT
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_skill_cat ON skills(category)")
            conn.commit()

    def _seed_canonical_tree(self):
        for node in CANONICAL_SKILL_TREE:
            if not self.get_skill(node.skill_id):
                self.save_skill(node)

    def save_skill(self, node: SkillNode):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO skills (
                    skill_id, name, category, parent_skill, proficiency,
                    attempts_count, success_count, consecutive_failures, prerequisites, description
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                node.skill_id,
                node.name,
                node.category,
                node.parent_skill,
                node.proficiency,
                node.attempts_count,
                node.success_count,
                node.consecutive_failures,
                json.dumps(node.prerequisites),
                node.description
            ))
            conn.commit()

    def get_skill(self, skill_id: str) -> Optional[SkillNode]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM skills WHERE skill_id = ?", (skill_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_node(row)

    def get_all_skills(self) -> List[SkillNode]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM skills")
            rows = cursor.fetchall()
            return [self._row_to_node(r) for r in rows]

    def record_attempt(self, skill_id: str, success: bool, weight: float = 1.0):
        """
        تحديث درجة إتقان المهارة بعد كل محاولة تمرين أو سيناريو
        """
        node = self.get_skill(skill_id)
        if not node:
            return

        node.attempts_count += 1
        if success:
            node.success_count += 1
            node.consecutive_failures = 0
            # Exponential moving average boost
            node.proficiency = round(min(1.0, node.proficiency + (0.08 * weight)), 3)
        else:
            node.consecutive_failures += 1
            node.proficiency = round(max(0.05, node.proficiency - (0.10 * weight)), 3)

        self.save_skill(node)

    def diagnose_weakest_skills(self, category: Optional[str] = None, limit: int = 3) -> List[SkillNode]:
        """
        تشخيص أضعف المهارات لدى الـ Agent لتوجيه التدريب نحوها
        """
        skills = self.get_all_skills()
        if category:
            skills = [s for s in skills if s.category == category]

        # Sort by lowest proficiency and highest consecutive failures
        skills.sort(key=lambda s: (s.proficiency, -s.consecutive_failures))
        return skills[:limit]

    def recommend_next_scenario_skill(self, category: Optional[str] = None) -> SkillNode:
        """
        اختيار المهارة التالية المناسبة للتدريب مع احترام المتطلبات المسبقة (Prerequisites)
        """
        weakest = self.diagnose_weakest_skills(category=category, limit=len(self.get_all_skills()))
        for cand in weakest:
            # Check if prerequisites are sufficiently mastered (proficiency >= 0.50)
            prereqs_met = True
            for pre_id in cand.prerequisites:
                pre_node = self.get_skill(pre_id)
                if pre_node and pre_node.proficiency < 0.50:
                    prereqs_met = False
                    break
            if prereqs_met:
                return cand

        # Fallback to absolute weakest
        return weakest[0] if weakest else self.get_skill("sqli_core")

    def _row_to_node(self, row) -> SkillNode:
        return SkillNode(
            skill_id=row[0],
            name=row[1],
            category=row[2],
            parent_skill=row[3],
            proficiency=row[4],
            attempts_count=row[5],
            success_count=row[6],
            consecutive_failures=row[7],
            prerequisites=json.loads(row[8]),
            description=row[9]
        )
