"""
HunterAI / ARTEX Traffic Recorder & Evidence Store
==================================================
Captures and archives full HTTP/S request-response exchanges across worker tools.
Features:
- Records raw request & response headers, bodies, timestamps, status codes, and SHA-256 hashes.
- Evidence binding: associates traffic exchanges directly with confirmed vulnerability findings.
- Searchable by URL, method, status, or keyword within captured responses.
"""
from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hunter_ai.traffic_recorder")


@dataclass
class RecordedExchange:
    exchange_id: str
    url: str
    method: str
    status_code: int
    content_type: str
    req_headers: Dict[str, str]
    req_body: str
    req_hash: str
    resp_headers: Dict[str, str]
    resp_body: str
    resp_hash: str
    duration_ms: float
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


class TrafficRecorder:
    """
    In-memory and SQLite-backed traffic exchange recording engine.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path
        self._exchanges: Dict[str, RecordedExchange] = {}
        # finding_id -> list of exchange_ids
        self._finding_evidence_map: Dict[str, List[str]] = {}

        if self.db_path:
            self._init_sqlite()

    def _init_sqlite(self):
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS exchanges (
                    id TEXT PRIMARY KEY,
                    url TEXT,
                    method TEXT,
                    status INTEGER,
                    content_type TEXT,
                    req_headers TEXT,
                    req_body TEXT,
                    req_hash TEXT,
                    resp_headers TEXT,
                    resp_body TEXT,
                    resp_hash TEXT,
                    duration_ms REAL,
                    ts REAL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS finding_evidence (
                    finding_id TEXT,
                    exchange_id TEXT,
                    PRIMARY KEY(finding_id, exchange_id)
                )
            """)
            conn.commit()

    def record_exchange(
        self,
        url: str,
        method: str,
        status_code: int,
        req_headers: Optional[Dict[str, str]] = None,
        req_body: str = "",
        resp_headers: Optional[Dict[str, str]] = None,
        resp_body: str = "",
        duration_ms: float = 0.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> RecordedExchange:
        exchange_id = f"exch_{uuid.uuid4().hex[:10]}"
        req_hdrs = req_headers or {}
        resp_hdrs = resp_headers or {}
        c_type = resp_hdrs.get("Content-Type", resp_hdrs.get("content-type", ""))

        req_hash = hashlib.sha256(req_body.encode("utf-8", "replace")).hexdigest()
        resp_hash = hashlib.sha256(resp_body.encode("utf-8", "replace")).hexdigest()

        exc = RecordedExchange(
            exchange_id=exchange_id,
            url=url,
            method=method.upper(),
            status_code=status_code,
            content_type=c_type,
            req_headers=req_hdrs,
            req_body=req_body,
            req_hash=req_hash,
            resp_headers=resp_hdrs,
            resp_body=resp_body,
            resp_hash=resp_hash,
            duration_ms=duration_ms,
            metadata=metadata or {},
        )
        self._exchanges[exchange_id] = exc

        if self.db_path:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute(
                        """
                        INSERT INTO exchanges (id, url, method, status, content_type, req_headers, req_body, req_hash, resp_headers, resp_body, resp_hash, duration_ms, ts)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            exchange_id,
                            url,
                            method.upper(),
                            status_code,
                            c_type,
                            json.dumps(req_hdrs),
                            req_body[:100000],  # safety cap
                            req_hash,
                            json.dumps(resp_hdrs),
                            resp_body[:100000],
                            resp_hash,
                            duration_ms,
                            exc.timestamp,
                        ),
                    )
                    conn.commit()
            except Exception as e:
                logger.error("Failed to write exchange to sqlite: %s", e)

        return exc

    def bind_evidence_to_finding(self, finding_id: str, exchange_ids: List[str]) -> None:
        self._finding_evidence_map.setdefault(finding_id, []).extend(exchange_ids)
        if self.db_path:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    for eid in exchange_ids:
                        conn.execute(
                            "INSERT OR IGNORE INTO finding_evidence (finding_id, exchange_id) VALUES (?, ?)",
                            (finding_id, eid),
                        )
                    conn.commit()
            except Exception as e:
                logger.error("Failed to bind evidence in sqlite: %s", e)

    def get_evidence_for_finding(self, finding_id: str) -> List[RecordedExchange]:
        eids = self._finding_evidence_map.get(finding_id, [])
        return [self._exchanges[eid] for eid in eids if eid in self._exchanges]

    def search_traffic(self, query: str, limit: int = 25) -> List[RecordedExchange]:
        q = query.lower()
        results = []
        for exc in self._exchanges.values():
            if q in exc.url.lower() or q in exc.resp_body.lower() or q in exc.req_body.lower():
                results.append(exc)
                if len(results) >= limit:
                    break
        return results
