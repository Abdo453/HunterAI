"""
Unified Evidence Model & Evidence Store for BurpAgent
Defines a standard cryptographic artifact envelope for all digital evidence:
HTTP requests, HTTP responses, uploaded/downloaded files, tokens, cookies, DOM scripts, and differentials.
"""
import uuid
import time
import sqlite3
import json
import logging
from enum import Enum
from pathlib import Path
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field

log = logging.getLogger("burp_agent.evidence.model")

DATA_DIR = Path("data/evidence")
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "unified_evidence.sqlite3"


class BurpEvidenceType(str, Enum):
    HTTP_REQUEST = "HTTP_REQUEST"
    HTTP_RESPONSE = "HTTP_RESPONSE"
    FILE = "FILE"
    SCREENSHOT = "SCREENSHOT"
    DOM = "DOM"
    JAVASCRIPT = "JAVASCRIPT"
    COOKIE = "COOKIE"
    TOKEN = "TOKEN"
    ERROR = "ERROR"
    DIFF = "DIFF"


class UnifiedEvidence(BaseModel):
    """حاوية دليل جنائي رقمي موحدة مشفرة ببصمة SHA256"""
    id: str = Field(default_factory=lambda: f"EVID-{uuid.uuid4().hex[:8]}")
    evidence_type: BurpEvidenceType
    source: str = "BurpSensor"
    timestamp: float = Field(default_factory=time.time)
    sha256: str
    content_ref: str = ""                       # File path, URL, or memory reference
    parent_transaction_id: Optional[str] = None
    summary: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class UnifiedEvidenceStore:
    """
    مخزن الأدلة الموحد:
    يربط الأدلة بالحركات والمعاملات (Transactions) ويتيح استرجاعها حسب النوع أو الـ ID
    """

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS unified_evidence (
                    id TEXT PRIMARY KEY,
                    evidence_type TEXT,
                    source TEXT,
                    timestamp REAL,
                    sha256 TEXT,
                    content_ref TEXT,
                    parent_transaction_id TEXT,
                    summary TEXT,
                    metadata TEXT
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_evid_type ON unified_evidence(evidence_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_evid_tx ON unified_evidence(parent_transaction_id)")
            conn.commit()

    def store_evidence(self, evidence: UnifiedEvidence):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO unified_evidence (
                    id, evidence_type, source, timestamp, sha256,
                    content_ref, parent_transaction_id, summary, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                evidence.id,
                evidence.evidence_type.value,
                evidence.source,
                evidence.timestamp,
                evidence.sha256,
                evidence.content_ref,
                evidence.parent_transaction_id,
                evidence.summary,
                json.dumps(evidence.metadata)
            ))
            conn.commit()

    def get_evidence(self, evidence_id: str) -> Optional[UnifiedEvidence]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM unified_evidence WHERE id = ?", (evidence_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_evidence(row)

    def get_by_transaction(self, tx_id: str) -> List[UnifiedEvidence]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM unified_evidence WHERE parent_transaction_id = ?", (tx_id,))
            rows = cursor.fetchall()
            return [self._row_to_evidence(r) for r in rows]

    def get_all_evidence(self, limit: int = 50) -> List[UnifiedEvidence]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM unified_evidence ORDER BY timestamp DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            return [self._row_to_evidence(r) for r in rows]

    def _row_to_evidence(self, row) -> UnifiedEvidence:
        return UnifiedEvidence(
            id=row[0],
            evidence_type=BurpEvidenceType(row[1]),
            source=row[2],
            timestamp=row[3],
            sha256=row[4],
            content_ref=row[5],
            parent_transaction_id=row[6],
            summary=row[7],
            metadata=json.loads(row[8])
        )
