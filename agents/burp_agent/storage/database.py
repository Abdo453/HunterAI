"""
Traffic Database Manager (SQLite)
Manages the 13 relational tables for full Burp Suite traffic persistence and querying.
"""
import os
import json
import sqlite3
import logging
from typing import Any, Dict, List, Optional, Tuple
from agents.burp_agent.storage.models import (
    HTTPRequestModel, HTTPResponseModel, ParameterModel,
    EndpointModel, FileModel, WebSocketFrameModel,
    TechnologyModel, FindingModel, EvidenceModel,
    GraphNodeModel, GraphEdgeModel, AIAnalysisModel,
    TrafficSession, TriagePriority
)

log = logging.getLogger("burp_agent.database")


class TrafficDatabase:
    """إدارة وتخزين كل الترافيك والـ Findings والـ Graphs في قاعدة بيانات SQLite مخصصة"""

    def __init__(self, db_path: str = "data/traffic.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        return conn

    def _init_db(self):
        """إنشاء الجداول الـ 13 والفهارس لسرعة الاستعلام"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.executescript("""
            CREATE TABLE IF NOT EXISTS traffic_sessions (
                id TEXT PRIMARY KEY,
                target_host TEXT NOT NULL,
                created_at REAL NOT NULL,
                description TEXT,
                is_active INTEGER DEFAULT 1,
                metadata TEXT
            );

            CREATE TABLE IF NOT EXISTS http_requests (
                id TEXT PRIMARY KEY,
                session_id TEXT,
                timestamp REAL NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                method TEXT NOT NULL,
                url TEXT NOT NULL,
                path TEXT NOT NULL,
                query_string TEXT,
                headers TEXT,
                cookies TEXT,
                body TEXT,
                body_length INTEGER DEFAULT 0,
                content_type TEXT,
                client_ip TEXT,
                triage_priority TEXT DEFAULT 'NORMAL',
                triage_reasons TEXT,
                raw_request TEXT
            );

            CREATE TABLE IF NOT EXISTS http_responses (
                id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
                timestamp REAL NOT NULL,
                status_code INTEGER NOT NULL,
                status_message TEXT,
                headers TEXT,
                body TEXT,
                body_length INTEGER DEFAULT 0,
                content_type TEXT,
                response_time_ms REAL DEFAULT 0,
                server_banner TEXT,
                technologies TEXT,
                raw_response TEXT,
                FOREIGN KEY (request_id) REFERENCES http_requests(id)
            );

            CREATE TABLE IF NOT EXISTS parameters (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT,
                endpoint_id TEXT,
                name TEXT NOT NULL,
                value TEXT,
                location TEXT NOT NULL,
                param_type TEXT,
                is_sensitive INTEGER DEFAULT 0,
                is_user_controlled_id INTEGER DEFAULT 0,
                is_role_indicator INTEGER DEFAULT 0,
                sample_values TEXT,
                FOREIGN KEY (request_id) REFERENCES http_requests(id)
            );

            CREATE TABLE IF NOT EXISTS endpoints (
                id TEXT PRIMARY KEY,
                host TEXT NOT NULL,
                method TEXT NOT NULL,
                normalized_path TEXT NOT NULL,
                raw_paths TEXT,
                parameters TEXT,
                auth_required INTEGER DEFAULT 0,
                auth_types TEXT,
                roles_observed TEXT,
                status_codes_seen TEXT,
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL,
                request_count INTEGER DEFAULT 1,
                is_api INTEGER DEFAULT 0,
                is_admin INTEGER DEFAULT 0,
                is_sensitive INTEGER DEFAULT 0,
                tags TEXT
            );

            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT NOT NULL,
                filename TEXT NOT NULL,
                extension TEXT NOT NULL,
                declared_mime TEXT,
                detected_mime TEXT,
                file_size INTEGER DEFAULT 0,
                magic_bytes TEXT,
                sha256 TEXT,
                potential_risk TEXT,
                timestamp REAL NOT NULL,
                FOREIGN KEY (request_id) REFERENCES http_requests(id)
            );

            CREATE TABLE IF NOT EXISTS websocket_frames (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                connection_id TEXT NOT NULL,
                timestamp REAL NOT NULL,
                direction TEXT NOT NULL,
                opcode INTEGER DEFAULT 1,
                payload TEXT,
                payload_size INTEGER DEFAULT 0,
                is_json INTEGER DEFAULT 0,
                parsed_json TEXT
            );

            CREATE TABLE IF NOT EXISTS technologies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT NOT NULL,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                version TEXT,
                confidence REAL DEFAULT 1.0,
                evidence_request_id TEXT,
                discovered_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                vuln_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence REAL DEFAULT 0.8,
                endpoint TEXT,
                parameter TEXT,
                request_id TEXT,
                response_id TEXT,
                description TEXT NOT NULL,
                evidence TEXT NOT NULL,
                remediation TEXT,
                created_at REAL NOT NULL,
                cvss_score REAL,
                status TEXT DEFAULT 'OPEN'
            );

            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id INTEGER,
                request_id TEXT NOT NULL,
                response_id TEXT,
                endpoint_id TEXT,
                parameter_name TEXT,
                highlight_offset INTEGER,
                evidence_snippet TEXT NOT NULL,
                timestamp REAL NOT NULL,
                FOREIGN KEY (finding_id) REFERENCES findings(id)
            );

            CREATE TABLE IF NOT EXISTS graph_nodes (
                id TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                node_type TEXT NOT NULL,
                metadata TEXT,
                weight REAL DEFAULT 1.0
            );

            CREATE TABLE IF NOT EXISTS graph_edges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_node TEXT NOT NULL,
                target_node TEXT NOT NULL,
                relationship TEXT NOT NULL,
                evidence_id INTEGER,
                confidence REAL DEFAULT 1.0,
                metadata TEXT,
                FOREIGN KEY (source_node) REFERENCES graph_nodes(id),
                FOREIGN KEY (target_node) REFERENCES graph_nodes(id)
            );

            CREATE TABLE IF NOT EXISTS ai_analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT NOT NULL,
                model_name TEXT NOT NULL,
                prompt_summary TEXT NOT NULL,
                analysis_text TEXT NOT NULL,
                suggested_vulns TEXT,
                confidence_score REAL DEFAULT 0.0,
                attack_path_suggested TEXT,
                duration_ms REAL DEFAULT 0.0,
                created_at REAL NOT NULL,
                FOREIGN KEY (request_id) REFERENCES http_requests(id)
            );

            -- Performance Indexes
            CREATE INDEX IF NOT EXISTS idx_req_host ON http_requests(host);
            CREATE INDEX IF NOT EXISTS idx_req_url ON http_requests(url);
            CREATE INDEX IF NOT EXISTS idx_req_triage ON http_requests(triage_priority);
            CREATE INDEX IF NOT EXISTS idx_resp_req ON http_responses(request_id);
            CREATE INDEX IF NOT EXISTS idx_resp_status ON http_responses(status_code);
            CREATE INDEX IF NOT EXISTS idx_param_name ON parameters(name);
            CREATE INDEX IF NOT EXISTS idx_param_req ON parameters(request_id);
            CREATE INDEX IF NOT EXISTS idx_ep_host ON endpoints(host);
            CREATE INDEX IF NOT EXISTS idx_findings_sev ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_graph_src ON graph_edges(source_node);
            CREATE INDEX IF NOT EXISTS idx_graph_tgt ON graph_edges(target_node);
            """)
            conn.commit()
            log.info(f"[TrafficDB] Initialized SQLite schema with 13 tables at {self.db_path}")

    # ── Request / Response Insertion ──────────────────────────────────────────

    def insert_request(self, req: HTTPRequestModel):
        with self._get_conn() as conn:
            conn.execute("""
            INSERT OR REPLACE INTO http_requests (
                id, session_id, timestamp, host, port, protocol, method, url,
                path, query_string, headers, cookies, body, body_length,
                content_type, client_ip, triage_priority, triage_reasons, raw_request
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                req.id, req.session_id, req.timestamp, req.host, req.port,
                req.protocol, req.method, req.url, req.path, req.query_string,
                json.dumps(req.headers), json.dumps(req.cookies), req.body,
                req.body_length, req.content_type, req.client_ip,
                req.triage_priority.value if hasattr(req.triage_priority, 'value') else req.triage_priority,
                json.dumps(req.triage_reasons), req.raw_request
            ))
            conn.commit()

    def insert_response(self, resp: HTTPResponseModel):
        with self._get_conn() as conn:
            conn.execute("""
            INSERT OR REPLACE INTO http_responses (
                id, request_id, timestamp, status_code, status_message,
                headers, body, body_length, content_type, response_time_ms,
                server_banner, technologies, raw_response
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                resp.id, resp.request_id, resp.timestamp, resp.status_code,
                resp.status_message, json.dumps(resp.headers), resp.body,
                resp.body_length, resp.content_type, resp.response_time_ms,
                resp.server_banner, json.dumps(resp.technologies), resp.raw_response
            ))
            conn.commit()

    def insert_parameters(self, params: List[ParameterModel]):
        if not params:
            return
        with self._get_conn() as conn:
            conn.executemany("""
            INSERT INTO parameters (
                request_id, endpoint_id, name, value, location, param_type,
                is_sensitive, is_user_controlled_id, is_role_indicator, sample_values
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                (
                    p.request_id, p.endpoint_id, p.name, p.value,
                    p.location.value if hasattr(p.location, 'value') else p.location,
                    p.param_type, 1 if p.is_sensitive else 0,
                    1 if p.is_user_controlled_id else 0,
                    1 if p.is_role_indicator else 0,
                    json.dumps(p.sample_values)
                ) for p in params
            ])
            conn.commit()

    def upsert_endpoint(self, ep: EndpointModel):
        with self._get_conn() as conn:
            existing = conn.execute("SELECT raw_paths, parameters, roles_observed, status_codes_seen, request_count FROM endpoints WHERE id = ?", (ep.id,)).fetchone()
            if existing:
                raw_paths = list(set(json.loads(existing["raw_paths"] or "[]") + ep.raw_paths))
                params = list(set(json.loads(existing["parameters"] or "[]") + ep.parameters))
                roles = list(set(json.loads(existing["roles_observed"] or "[]") + ep.roles_observed))
                codes = list(set(json.loads(existing["status_codes_seen"] or "[]") + ep.status_codes_seen))
                req_count = existing["request_count"] + 1

                conn.execute("""
                UPDATE endpoints SET
                    raw_paths = ?, parameters = ?, roles_observed = ?, status_codes_seen = ?,
                    request_count = ?, last_seen = ?, is_admin = ?, is_api = ?
                WHERE id = ?
                """, (
                    json.dumps(raw_paths), json.dumps(params), json.dumps(roles),
                    json.dumps(codes), req_count, ep.last_seen,
                    1 if ep.is_admin else 0, 1 if ep.is_api else 0, ep.id
                ))
            else:
                conn.execute("""
                INSERT INTO endpoints (
                    id, host, method, normalized_path, raw_paths, parameters,
                    auth_required, auth_types, roles_observed, status_codes_seen,
                    first_seen, last_seen, request_count, is_api, is_admin, is_sensitive, tags
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ep.id, ep.host, ep.method, ep.normalized_path,
                    json.dumps(ep.raw_paths), json.dumps(ep.parameters),
                    1 if ep.auth_required else 0, json.dumps(ep.auth_types),
                    json.dumps(ep.roles_observed), json.dumps(ep.status_codes_seen),
                    ep.first_seen, ep.last_seen, ep.request_count,
                    1 if ep.is_api else 0, 1 if ep.is_admin else 0,
                    1 if ep.is_sensitive else 0, json.dumps(ep.tags)
                ))
            conn.commit()

    def insert_file(self, f: FileModel) -> int:
        with self._get_conn() as conn:
            cur = conn.execute("""
            INSERT INTO files (
                request_id, filename, extension, declared_mime, detected_mime,
                file_size, magic_bytes, sha256, potential_risk, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                f.request_id, f.filename, f.extension, f.declared_mime,
                f.detected_mime, f.file_size, f.magic_bytes, f.sha256,
                f.potential_risk, f.timestamp
            ))
            conn.commit()
            return cur.lastrowid

    def insert_websocket_frame(self, ws: WebSocketFrameModel) -> int:
        with self._get_conn() as conn:
            cur = conn.execute("""
            INSERT INTO websocket_frames (
                connection_id, timestamp, direction, opcode, payload,
                payload_size, is_json, parsed_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ws.connection_id, ws.timestamp, ws.direction, ws.opcode,
                ws.payload, ws.payload_size, 1 if ws.is_json else 0,
                json.dumps(ws.parsed_json) if ws.parsed_json else None
            ))
            conn.commit()
            return cur.lastrowid

    def insert_finding(self, finding: FindingModel) -> int:
        with self._get_conn() as conn:
            cur = conn.execute("""
            INSERT INTO findings (
                title, vuln_type, severity, confidence, endpoint, parameter,
                request_id, response_id, description, evidence, remediation,
                created_at, cvss_score, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                finding.title, finding.vuln_type, finding.severity,
                finding.confidence, finding.endpoint, finding.parameter,
                finding.request_id, finding.response_id, finding.description,
                finding.evidence, finding.remediation, finding.created_at,
                finding.cvss_score, finding.status
            ))
            conn.commit()
            return cur.lastrowid

    def insert_evidence(self, ev: EvidenceModel) -> int:
        with self._get_conn() as conn:
            cur = conn.execute("""
            INSERT INTO evidence (
                finding_id, request_id, response_id, endpoint_id, parameter_name,
                highlight_offset, evidence_snippet, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ev.finding_id, ev.request_id, ev.response_id, ev.endpoint_id,
                ev.parameter_name, ev.highlight_offset, ev.evidence_snippet, ev.timestamp
            ))
            conn.commit()
            return cur.lastrowid

    def upsert_graph_node(self, node: GraphNodeModel):
        with self._get_conn() as conn:
            conn.execute("""
            INSERT OR REPLACE INTO graph_nodes (id, label, node_type, metadata, weight)
            VALUES (?, ?, ?, ?, ?)
            """, (node.id, node.label, node.node_type, json.dumps(node.metadata), node.weight))
            conn.commit()

    def insert_graph_edge(self, edge: GraphEdgeModel) -> int:
        with self._get_conn() as conn:
            cur = conn.execute("""
            INSERT INTO graph_edges (source_node, target_node, relationship, evidence_id, confidence, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
            """, (
                edge.source_node, edge.target_node, edge.relationship,
                edge.evidence_id, edge.confidence, json.dumps(edge.metadata)
            ))
            conn.commit()
            return cur.lastrowid

    def insert_ai_analysis(self, analysis: AIAnalysisModel) -> int:
        with self._get_conn() as conn:
            cur = conn.execute("""
            INSERT INTO ai_analyses (
                request_id, model_name, prompt_summary, analysis_text,
                suggested_vulns, confidence_score, attack_path_suggested,
                duration_ms, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                analysis.request_id, analysis.model_name, analysis.prompt_summary,
                analysis.analysis_text, json.dumps(analysis.suggested_vulns),
                analysis.confidence_score, analysis.attack_path_suggested,
                analysis.duration_ms, analysis.created_at
            ))
            conn.commit()
            return cur.lastrowid

    # ── Query & Statistics Methods ────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        with self._get_conn() as conn:
            requests_count = conn.execute("SELECT COUNT(*) FROM http_requests").fetchone()[0]
            responses_count = conn.execute("SELECT COUNT(*) FROM http_responses").fetchone()[0]
            endpoints_count = conn.execute("SELECT COUNT(*) FROM endpoints").fetchone()[0]
            findings_count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            files_count = conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]
            ws_count = conn.execute("SELECT COUNT(*) FROM websocket_frames").fetchone()[0]
            interesting_count = conn.execute("SELECT COUNT(*) FROM http_requests WHERE triage_priority IN ('INTERESTING', 'HIGH', 'CRITICAL')").fetchone()[0]
            ai_analyses_count = conn.execute("SELECT COUNT(*) FROM ai_analyses").fetchone()[0]

            return {
                "total_requests": requests_count,
                "total_responses": responses_count,
                "endpoints_mapped": endpoints_count,
                "interesting_requests": interesting_count,
                "findings_count": findings_count,
                "files_intercepted": files_count,
                "websocket_frames": ws_count,
                "ai_analyses_run": ai_analyses_count
            }

    def list_endpoints(self, host: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            if host:
                rows = conn.execute("SELECT * FROM endpoints WHERE host = ? ORDER BY request_count DESC", (host,)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM endpoints ORDER BY request_count DESC").fetchall()
            return [dict(r) for r in rows]

    def list_findings(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute("SELECT * FROM findings ORDER BY created_at DESC").fetchall()
            return [dict(r) for r in rows]

    def get_attack_graph(self) -> Dict[str, Any]:
        with self._get_conn() as conn:
            nodes = [dict(r) for r in conn.execute("SELECT * FROM graph_nodes").fetchall()]
            edges = [dict(r) for r in conn.execute("SELECT * FROM graph_edges").fetchall()]
            return {"nodes": nodes, "edges": edges}
