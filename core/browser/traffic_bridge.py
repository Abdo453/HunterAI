"""
HunterAI Browser + Burp + Traffic DB Ingestion Bridge
====================================================
Bridges network events intercepted by Playwright or proxied through Burp
into the central SQLite Traffic Database (`traffic.db`).

Automatically extracts:
1. Newly discovered Endpoints (e.g. /api/users, /dashboard)
2. Discovered Parameters (GET query params and POST body fields)
3. Technologies from response headers (Server, X-Powered-By)
4. Streams newly discovered attack surface items directly into the EvidenceGraph!
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Set
from urllib.parse import parse_qs, urlparse

from core.evidence_graph import EvidenceGraph

logger = logging.getLogger("hunter_ai.traffic_bridge")


class TrafficBridge:
    """
    Ingests live browser & proxy network events into traffic.db and updates EvidenceGraph.
    """

    def __init__(
        self,
        db_path: str = "data/traffic.db",
        evidence_graph: Optional[EvidenceGraph] = None,
        on_new_endpoint_cb: Optional[Callable[[str, str, List[str]], Any]] = None,
    ):
        self.db_path = db_path
        self.evidence_graph = evidence_graph
        self.on_new_endpoint_cb = on_new_endpoint_cb

        self._seen_endpoints: Set[str] = set()
        self._seen_params: Set[str] = set()
        self.session_id = f"session_{int(time.time())}"

        # Initialize SQLite storage tables if needed
        self._init_sqlite()

    def _init_sqlite(self) -> None:
        """Ensure minimal robust traffic tables exist in traffic.db"""
        import sqlite3
        import os

        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                CREATE TABLE IF NOT EXISTS live_traffic (
                    id TEXT PRIMARY KEY,
                    session_id TEXT,
                    timestamp REAL,
                    method TEXT,
                    url TEXT,
                    host TEXT,
                    path TEXT,
                    status_code INTEGER,
                    resource_type TEXT,
                    headers_json TEXT,
                    is_api INTEGER DEFAULT 0
                );
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_traffic_host ON live_traffic(host);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_traffic_path ON live_traffic(path);")
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to init traffic DB at {self.db_path}: {e}")

    def ingest_request(self, event_data: Dict[str, Any]) -> None:
        """
        Ingest intercepted HTTP request:
        event_data: { "url": str, "method": str, "headers": dict, "resource_type": str, "timestamp": float }
        """
        url = event_data.get("url", "")
        if not url:
            return

        parsed = urlparse(url)
        host = parsed.hostname or ""
        path = parsed.path or "/"
        method = event_data.get("method", "GET").upper()
        resource_type = event_data.get("resource_type", "document")
        query_params = list(parse_qs(parsed.query).keys())

        endpoint_key = f"{method}:{host}{path}"
        is_new_endpoint = endpoint_key not in self._seen_endpoints

        if is_new_endpoint:
            self._seen_endpoints.add(endpoint_key)
            logger.info(f"TRAFFIC BRIDGE: Discovered new endpoint: {method} {host}{path} (Params: {query_params})")

            # 1. Feed to EvidenceGraph
            if self.evidence_graph:
                # Add observation for each parameter
                if query_params:
                    for p in query_params:
                        self.evidence_graph.record_observation(
                            sub=host,
                            url=url,
                            path=path,
                            param_name=p,
                            observation_text=f"Discovered via browser traffic interception: {method} {path}"
                        )
                else:
                    self.evidence_graph.get_or_create_endpoint(host, url, path, method=method)

            # 2. Trigger callback for HunterAI Brain
            if self.on_new_endpoint_cb:
                try:
                    self.on_new_endpoint_cb(host, path, query_params)
                except Exception as e:
                    logger.debug(f"Endpoint callback error: {e}")

        # Persist to SQLite
        self._record_to_db(
            req_id=str(uuid.uuid4()),
            method=method,
            url=url,
            host=host,
            path=path,
            status_code=0,
            resource_type=resource_type,
            headers=event_data.get("headers", {}),
        )

    def ingest_response(self, event_data: Dict[str, Any]) -> None:
        """
        Ingest intercepted HTTP response:
        event_data: { "url": str, "status": int, "headers": dict, "timestamp": float }
        """
        url = event_data.get("url", "")
        status = event_data.get("status", 0)
        parsed = urlparse(url)
        host = parsed.hostname or ""
        path = parsed.path or "/"

        headers = event_data.get("headers", {})

        # Check for interesting security response headers
        server = headers.get("server") or headers.get("Server")
        powered_by = headers.get("x-powered-by") or headers.get("X-Powered-By")

        if (server or powered_by) and self.evidence_graph:
            obs = f"Server Banner: {server} | Powered-By: {powered_by}"
            self.evidence_graph.record_observation(
                sub=host,
                url=url,
                path=path,
                param_name="",
                observation_text=obs
            )

    def _record_to_db(
        self,
        req_id: str,
        method: str,
        url: str,
        host: str,
        path: str,
        status_code: int,
        resource_type: str,
        headers: Dict[str, Any],
    ) -> None:
        import sqlite3
        import json

        is_api = 1 if ("/api/" in path.lower() or "json" in resource_type.lower()) else 0
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO live_traffic 
                    (id, session_id, timestamp, method, url, host, path, status_code, resource_type, headers_json, is_api)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        req_id,
                        self.session_id,
                        time.time(),
                        method,
                        url,
                        host,
                        path,
                        status_code,
                        resource_type,
                        json.dumps(headers),
                        is_api,
                    ),
                )
                conn.commit()
        except Exception as e:
            logger.debug(f"DB insert error: {e}")

    def get_captured_endpoints_count(self) -> int:
        return len(self._seen_endpoints)
