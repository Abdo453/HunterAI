"""
Structured Knowledge Store
Stores and indexes canonical security concepts, vulnerability patterns, signals,
prerequisites, verification strategies, and evidence requirements.
Uses SQLite for persistent storage and fast retrieval.
"""
import sqlite3
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field

log = logging.getLogger("core.learning.knowledge_store")

DATA_DIR = Path("data/knowledge_base")
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "structured_knowledge.sqlite3"


class KnowledgeItem(BaseModel):
    """عنصر معرفي منظم قابل للاستدعاء والاستدلال"""
    id: str
    item_type: str              # concept, vulnerability, methodology, lab_pattern
    topic: str                  # authorization, sqli, ssrf, authentication, etc.
    name: str
    prerequisites: List[str] = Field(default_factory=list)
    signals: List[str] = Field(default_factory=list)
    verification_strategy: str = ""
    evidence_requirements: List[str] = Field(default_factory=list)
    remediation_pattern: str = ""
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


# ── Canonical Pre-seeded Knowledge Modules ─────────────────────────────
CANONICAL_KNOWLEDGE: List[KnowledgeItem] = [
    KnowledgeItem(
        id="http_001",
        item_type="concept",
        topic="http",
        name="HTTP Statelessness and Identification",
        prerequisites=["networking_basics"],
        signals=["headers", "cookies", "bearer_token", "status_codes"],
        verification_strategy="Inspect Authorization headers and session cookies for identity context",
        evidence_requirements=["raw_request_headers", "status_code"],
        remediation_pattern="Use secure, HttpOnly, SameSite cookies or short-lived signed tokens",
        description="HTTP is inherently stateless; identity state is communicated via tokens or session headers."
    ),
    KnowledgeItem(
        id="authz_001",
        item_type="vulnerability",
        topic="authorization",
        name="Object-Level Authorization Failure (BOLA / IDOR)",
        prerequisites=["http_001", "authentication"],
        signals=["resource_identifier", "numeric_id", "uuid_in_path", "authenticated_request", "multi_tenant"],
        verification_strategy="Execute differential test: Request tenant A resource using tenant B credentials; compare response bodies",
        evidence_requirements=["baseline_response_200", "probe_response_200", "content_differential_hash"],
        remediation_pattern="Implement server-side object ownership verification against session identity before database query",
        description="Application exposes resource IDs in URL/body and fails to verify if requesting user owns the object."
    ),
    KnowledgeItem(
        id="authz_002",
        item_type="vulnerability",
        topic="authorization",
        name="Function-Level Authorization Failure (BFLA)",
        prerequisites=["http_001", "rbac_matrices"],
        signals=["admin_path", "role_parameter", "privileged_verb", "dashboard_route"],
        verification_strategy="Send administrative action request (POST/PUT) with standard low-privileged user token",
        evidence_requirements=["baseline_403_or_redirect", "successful_execution_200", "state_change_verified"],
        remediation_pattern="Centralize RBAC middleware enforcement at router level before controller execution",
        description="Application fails to verify caller's role before executing privileged operations."
    ),
    KnowledgeItem(
        id="sqli_001",
        item_type="vulnerability",
        topic="sql_injection",
        name="Differential & Blind SQL Injection",
        prerequisites=["http_001", "sql_syntax"],
        signals=["search_query", "filter_parameter", "sort_column", "database_error"],
        verification_strategy="Inject boolean condition pairs (' AND 1=1 vs ' AND 1=2) and measure response length or latency delta",
        evidence_requirements=["timing_delta_gte_5s", "error_disclosure_regex", "content_boolean_divergence"],
        remediation_pattern="Use parameterized prepared statements with bind variables across all queries",
        description="User input concatenated into dynamic SQL queries without parameterized binding."
    ),
    KnowledgeItem(
        id="ssrf_001",
        item_type="vulnerability",
        topic="ssrf",
        name="Server-Side Request Forgery to Internal Metadata",
        prerequisites=["http_001", "cloud_architecture"],
        signals=["url_parameter", "webhook_url", "redirect_target", "image_fetcher"],
        verification_strategy="Supply loopback or cloud metadata endpoint (169.254.169.254) and check response for sensitive IAM credentials",
        evidence_requirements=["outbound_connection_to_loopback", "aws_iam_json_response"],
        remediation_pattern="Enforce strict URL allowlists and disable server-side resolution of non-routable/loopback IP ranges",
        description="Server fetches remote resources based on user-supplied URL without strict destination IP filtering."
    ),
    KnowledgeItem(
        id="jwt_001",
        item_type="vulnerability",
        topic="authentication",
        name="Broken Authentication via Weak JWT Claims",
        prerequisites=["http_001", "cryptography_basics"],
        signals=["bearer_token_header", "jwt_structure", "none_algorithm", "jwks_uri"],
        verification_strategy="Decode JWT payload, modify role claim, sign with 'none' or weak HMAC key, send to authenticated endpoint",
        evidence_requirements=["forged_token_accepted_200", "privilege_elevation_observed"],
        remediation_pattern="Enforce explicit algorithm verification (RS256) and reject unsigned or weak HMAC tokens",
        description="JWT signature verification improperly configured or vulnerable to key confusion / alg:none."
    ),
    KnowledgeItem(
        id="method_001",
        item_type="methodology",
        topic="differential_testing",
        name="Cross-Identity Behavioral Differential Testing",
        prerequisites=["authz_001"],
        signals=["resource_access", "permission_boundary"],
        verification_strategy="1. Establish unauthenticated baseline. 2. Establish authorized owner baseline. 3. Execute cross-tenant probe. 4. Correlate differentials.",
        evidence_requirements=["differential_response_hash", "status_code_comparison"],
        remediation_pattern="Automate differential authorization regression tests in CI/CD pipelines",
        description="Scientific methodology comparing HTTP responses across identity contexts to prove access control defects."
    )
]


class KnowledgeStore:
    """
    مخزن المعرفة المنظمة:
    يخزن ويفهرس المفاهيم والأنماط والاستراتيجيات الأمنية
    """

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self._init_db()
        self._seed_canonical_knowledge()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS knowledge_items (
                    id TEXT PRIMARY KEY,
                    item_type TEXT,
                    topic TEXT,
                    name TEXT,
                    prerequisites TEXT,
                    signals TEXT,
                    verification_strategy TEXT,
                    evidence_requirements TEXT,
                    remediation_pattern TEXT,
                    description TEXT
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_topic ON knowledge_items(topic)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_type ON knowledge_items(item_type)")
            conn.commit()

    def _seed_canonical_knowledge(self):
        for item in CANONICAL_KNOWLEDGE:
            self.save_item(item)

    def save_item(self, item: KnowledgeItem):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO knowledge_items (
                    id, item_type, topic, name, prerequisites, signals,
                    verification_strategy, evidence_requirements, remediation_pattern, description
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                item.id,
                item.item_type,
                item.topic,
                item.name,
                json.dumps(item.prerequisites),
                json.dumps(item.signals),
                item.verification_strategy,
                json.dumps(item.evidence_requirements),
                item.remediation_pattern,
                item.description
            ))
            conn.commit()

    def get_item(self, item_id: str) -> Optional[KnowledgeItem]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM knowledge_items WHERE id = ?", (item_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_item(row)

    def get_by_topic(self, topic: str) -> List[KnowledgeItem]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM knowledge_items WHERE topic = ?", (topic,))
            rows = cursor.fetchall()
            return [self._row_to_item(r) for r in rows]

    def query_by_signals(self, observed_signals: List[str]) -> List[KnowledgeItem]:
        """
        البحث عن المعرفة المرتبطة بإشارات أو دلائل تمت ملاحظتها في الموقع
        """
        if not observed_signals:
            return []

        all_items = self.get_all_items()
        matched = []
        clean_signals = {s.lower().strip() for s in observed_signals}

        for item in all_items:
            item_signals = {s.lower().strip() for s in item.signals}
            overlap = len(clean_signals.intersection(item_signals))
            if overlap > 0:
                matched.append((overlap, item))

        # Sort by overlap score descending
        matched.sort(key=lambda x: x[0], reverse=True)
        return [item for _, item in matched]

    def get_all_items(self) -> List[KnowledgeItem]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM knowledge_items")
            rows = cursor.fetchall()
            return [self._row_to_item(r) for r in rows]

    def _row_to_item(self, row) -> KnowledgeItem:
        return KnowledgeItem(
            id=row[0],
            item_type=row[1],
            topic=row[2],
            name=row[3],
            prerequisites=json.loads(row[4]),
            signals=json.loads(row[5]),
            verification_strategy=row[6],
            evidence_requirements=json.loads(row[7]),
            remediation_pattern=row[8],
            description=row[9]
        )
