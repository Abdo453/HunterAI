"""
Knowledge & State Database (SQLite)
High-performance relational persistence for assets, traffic, parameters, UI actions, hypotheses, and evidence.
Replaces plain text files with rich, queryable relational data structures.
"""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class KnowledgeDB:
    """
    قاعدة بيانات المعرفة وحركة المرور (traffic.db):
    تتيح للوكيل الذكي الاستعلام السريع والمنظم عن الـ Endpoints, Parameters, Traffic, UI Actions, والفرضيات.
    """

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        """تهيئة جداول قاعدة البيانات"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.executescript("""
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_value TEXT NOT NULL,
                asset_type TEXT NOT NULL,       -- domain | subdomain | ip | port | service
                ip_address TEXT,
                port INTEGER,
                service_name TEXT,
                technologies TEXT,
                status TEXT DEFAULT 'active',
                timestamp REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS endpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL UNIQUE,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                host TEXT NOT NULL,
                category TEXT DEFAULT 'general', -- auth | user | api | admin | static | general
                auth_required INTEGER DEFAULT 0,
                source_tool TEXT,
                timestamp REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS parameters (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint_id INTEGER,
                name TEXT NOT NULL,
                location TEXT NOT NULL,         -- query | body_json | body_form | header | path
                sample_value TEXT,
                is_identifier INTEGER DEFAULT 0, -- 1 if numeric id, uuid, username
                timestamp REAL NOT NULL,
                FOREIGN KEY (endpoint_id) REFERENCES endpoints(id)
            );

            CREATE TABLE IF NOT EXISTS traffic_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                req_id TEXT UNIQUE NOT NULL,
                method TEXT NOT NULL,
                url TEXT NOT NULL,
                headers_json TEXT,
                post_data TEXT,
                status_code INTEGER,
                resp_headers_json TEXT,
                resp_snippet TEXT,
                resource_type TEXT DEFAULT 'xhr',
                source_tool TEXT DEFAULT 'playwright',
                timestamp REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ui_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action_id TEXT UNIQUE NOT NULL,
                page_url TEXT NOT NULL,
                element_type TEXT NOT NULL,     -- button | tab | form_submit | link | input
                locator TEXT NOT NULL,
                text_label TEXT,
                timestamp REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ui_traffic_correlations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action_id TEXT NOT NULL,
                req_id TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                match_reason TEXT,
                timestamp REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS hypotheses (
                hyp_id TEXT PRIMARY KEY NOT NULL,
                target TEXT NOT NULL,
                title TEXT NOT NULL,
                vuln_type TEXT NOT NULL,
                observation TEXT NOT NULL,
                rationale TEXT NOT NULL,
                confidence REAL DEFAULT 0.50,
                status TEXT DEFAULT 'draft',    -- draft | testing | validated | rejected | inconclusive
                recommended_skill TEXT,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY NOT NULL,
                hyp_id TEXT,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                cvss_score REAL DEFAULT 0.0,
                vrt_id TEXT,
                cwe TEXT,
                tool_source TEXT,
                evidence_text TEXT,
                confidence REAL DEFAULT 0.80,
                status TEXT DEFAULT 'open',
                timestamp REAL NOT NULL
            );
            """)
            conn.commit()

    # ── Endpoints & Parameters CRUD ──────────────────────────────

    def insert_endpoint(
        self,
        url: str,
        method: str = "GET",
        category: str = "general",
        auth_required: bool = False,
        source_tool: str = "crawler"
    ) -> int:
        """إضافة endpoint إلى قاعدة المعرفة"""
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        path = parsed.path or "/"
        host = parsed.netloc

        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR IGNORE INTO endpoints (url, method, path, host, category, auth_required, source_tool, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (url, method.upper(), path, host, category, int(auth_required), source_tool, time.time()))
            conn.commit()

            cursor.execute("SELECT id FROM endpoints WHERE url = ? AND method = ?", (url, method.upper()))
            row = cursor.fetchone()
            return row["id"] if row else -1

    def insert_parameter(
        self,
        endpoint_id: int,
        name: str,
        location: str = "query",
        sample_value: str = "",
        is_identifier: bool = False
    ) -> int:
        """تسجيل parameter مرتبط بـ endpoint"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO parameters (endpoint_id, name, location, sample_value, is_identifier, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (endpoint_id, name, location, sample_value, int(is_identifier), time.time()))
            conn.commit()
            return cursor.lastrowid

    def get_endpoints_with_param(self, param_name: str) -> List[Dict[str, Any]]:
        """استعلام: جلب كل الـ endpoints التي تحتوي على parameter محدد (مثل id, user, token)"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT e.*, p.name as param_name, p.location, p.sample_value
                FROM endpoints e
                JOIN parameters p ON e.id = p.endpoint_id
                WHERE p.name LIKE ?
            """, (f"%{param_name}%",))
            return [dict(row) for row in cursor.fetchall()]

    def get_endpoints_by_method(self, method: str) -> List[Dict[str, Any]]:
        """استعلام: جلب كل الـ endpoints بطريقة HTTP محددة (مثل POST, PUT, DELETE)"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM endpoints WHERE method = ?", (method.upper(),))
            return [dict(row) for row in cursor.fetchall()]

    # ── Traffic & UI Actions CRUD ────────────────────────────────

    def insert_traffic(
        self,
        method: str,
        url: str,
        headers: Dict[str, str] = None,
        post_data: Optional[str] = None,
        status_code: Optional[int] = None,
        resp_headers: Dict[str, str] = None,
        resp_snippet: Optional[str] = None,
        resource_type: str = "xhr",
        source_tool: str = "playwright"
    ) -> str:
        """تسجيل طلب HTTP تم اعتراضه"""
        req_id = f"req_{str(uuid.uuid4())[:8]}"
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO traffic_records (req_id, method, url, headers_json, post_data, status_code, resp_headers_json, resp_snippet, resource_type, source_tool, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                req_id, method.upper(), url,
                json.dumps(headers or {}), post_data, status_code,
                json.dumps(resp_headers or {}), resp_snippet,
                resource_type, source_tool, time.time()
            ))
            conn.commit()
        return req_id

    def insert_ui_action(
        self,
        page_url: str,
        element_type: str,
        locator: str,
        text_label: str = ""
    ) -> str:
        """تسجيل حركة أو نقرة مستخدم في واجهة الـ DOM"""
        action_id = f"act_{str(uuid.uuid4())[:8]}"
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO ui_actions (action_id, page_url, element_type, locator, text_label, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (action_id, page_url, element_type, locator, text_label, time.time()))
            conn.commit()
        return action_id

    def insert_correlation(
        self,
        action_id: str,
        req_id: str,
        endpoint: str,
        match_reason: str = "temporal_and_url_match"
    ) -> int:
        """ربط تفاعل الواجهة بطلب الشبكة"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO ui_traffic_correlations (action_id, req_id, endpoint, match_reason, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (action_id, req_id, endpoint, match_reason, time.time()))
            conn.commit()
            return cursor.lastrowid

    def get_correlated_traffic(self) -> List[Dict[str, Any]]:
        """استعلام: جلب كافة الارتباطات بين أزرار الواجهة وحركة المرور"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT c.id, c.action_id, c.req_id, c.endpoint, c.match_reason,
                       u.element_type, u.locator, u.text_label, u.page_url,
                       t.method, t.status_code, t.post_data
                FROM ui_traffic_correlations c
                JOIN ui_actions u ON c.action_id = u.action_id
                JOIN traffic_records t ON c.req_id = t.req_id
                ORDER BY c.timestamp DESC
            """)
            return [dict(row) for row in cursor.fetchall()]

    # ── Hypotheses & Findings CRUD ───────────────────────────────

    def insert_hypothesis(
        self,
        target: str,
        title: str,
        vuln_type: str,
        observation: str,
        rationale: str,
        confidence: float = 0.50,
        recommended_skill: str = "authorization_analysis"
    ) -> str:
        """تسجيل فرضية أمنية جديدة للاختبار"""
        hyp_id = f"hyp_{str(uuid.uuid4())[:8]}"
        now = time.time()
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO hypotheses (hyp_id, target, title, vuln_type, observation, rationale, confidence, status, recommended_skill, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'draft', ?, ?, ?)
            """, (hyp_id, target, title, vuln_type, observation, rationale, confidence, recommended_skill, now, now))
            conn.commit()
        return hyp_id

    def update_hypothesis_confidence(
        self,
        hyp_id: str,
        new_confidence: float,
        new_status: Optional[str] = None
    ) -> None:
        """تحديث درجة الثقة للفرضية بعد جمع الأدلة (مثلاً 50% -> 85% -> 98%)"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            if new_status:
                cursor.execute("""
                    UPDATE hypotheses
                    SET confidence = ?, status = ?, updated_at = ?
                    WHERE hyp_id = ?
                """, (new_confidence, new_status, time.time(), hyp_id))
            else:
                cursor.execute("""
                    UPDATE hypotheses
                    SET confidence = ?, updated_at = ?
                    WHERE hyp_id = ?
                """, (new_confidence, time.time(), hyp_id))
            conn.commit()

    def get_hypotheses(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """جلب الفرضيات المسجلة"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            if status:
                cursor.execute("SELECT * FROM hypotheses WHERE status = ? ORDER BY confidence DESC", (status,))
            else:
                cursor.execute("SELECT * FROM hypotheses ORDER BY confidence DESC")
            return [dict(row) for row in cursor.fetchall()]

    # ── Summary & Metrics ────────────────────────────────────────

    def get_stats(self) -> Dict[str, int]:
        """إحصائيات شاملة عن قاعدة المعرفة"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            endpoints_count = cursor.execute("SELECT COUNT(*) FROM endpoints").fetchone()[0]
            params_count = cursor.execute("SELECT COUNT(*) FROM parameters").fetchone()[0]
            traffic_count = cursor.execute("SELECT COUNT(*) FROM traffic_records").fetchone()[0]
            correlations_count = cursor.execute("SELECT COUNT(*) FROM ui_traffic_correlations").fetchone()[0]
            hypotheses_count = cursor.execute("SELECT COUNT(*) FROM hypotheses").fetchone()[0]
            validated_hypotheses = cursor.execute("SELECT COUNT(*) FROM hypotheses WHERE status = 'validated'").fetchone()[0]

            return {
                "endpoints": endpoints_count,
                "parameters": params_count,
                "traffic_records": traffic_count,
                "ui_correlations": correlations_count,
                "hypotheses_total": hypotheses_count,
                "hypotheses_validated": validated_hypotheses
            }
