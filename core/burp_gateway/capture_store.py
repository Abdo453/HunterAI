"""
Capture Store & Engagement Memory
=================================
Manages structured, portable, and forensic engagement artifacts under:
data/engagements/<target>/
 ├── scope.json
 ├── requests/
 ├── responses/
 ├── endpoints.json
 ├── parameters.json
 ├── technologies.json
 ├── identities.json
 ├── hypotheses.json
 ├── tests.json
 ├── evidence/
 ├── findings/
 └── timeline.json
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import stat
import tempfile
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import parse_qs, urlparse

from core.secret_sanitizer import SecretSanitizer

logger = logging.getLogger("hunter_ai.capture_store")


def _write_scrubbed_json(path: Path, payload: Any) -> None:
    """Persist a SecretSanitizer-scrubbed JSON payload with 0o600 permissions on POSIX."""
    scrubbed = SecretSanitizer.sanitize_data(payload)
    serialized = json.dumps(scrubbed, indent=2)
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, serialized.encode("utf-8"))
        finally:
            os.close(fd)
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    else:
        path.write_text(serialized, encoding="utf-8")


@dataclass
class CapturedTransaction:
    tx_id: str = ""
    target_host: str = ""
    method: str = "GET"
    url: str = ""
    status_code: int = 200
    req_headers: Dict[str, str] = field(default_factory=dict)
    req_body: str = ""
    resp_headers: Dict[str, str] = field(default_factory=dict)
    resp_body: str = ""
    tool_source: str = "proxy"  # proxy | repeater | scanner | target
    timestamp: float = field(default_factory=lambda: time.time())
    identity: str = "GUEST"     # Identified auth context (User A, User B, Admin)
    # Extended Session Context & Lineage
    request_id: str = ""
    content_type: str = ""
    cookies: Dict[str, str] = field(default_factory=dict)
    auth_context: str = ""
    source: str = "proxy"
    parent_request: Optional[str] = None
    endpoint_id: str = ""
    parameter_ids: List[str] = field(default_factory=list)
    trace_id: str = ""          # Global trace ID propagated from Browser → Report
    browser_action_id: str = "" # BA-XXXX linking browser click/submit to this request

    def __post_init__(self):
        if not self.tx_id and self.request_id:
            self.tx_id = self.request_id
        elif not self.request_id and self.tx_id:
            self.request_id = self.tx_id

        if self.source and self.tool_source == "proxy" and self.source != "proxy":
            self.tool_source = self.source
        elif self.tool_source and not self.source:
            self.source = self.tool_source

        if not self.auth_context:
            self.auth_context = self.identity
        elif self.auth_context and self.identity == "GUEST":
            self.identity = self.auth_context

        # Extract content type if missing
        if not self.content_type:
            ct = self.resp_headers.get("Content-Type") or self.resp_headers.get("content-type") or \
                 self.req_headers.get("Content-Type") or self.req_headers.get("content-type") or ""
            self.content_type = ct.split(";")[0].strip() if ct else ""

        # Extract cookies from headers if missing
        if not self.cookies:
            cookie_hdr = self.req_headers.get("Cookie") or self.req_headers.get("cookie") or ""
            if cookie_hdr:
                for pair in cookie_hdr.split(";"):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        self.cookies[k.strip()] = v.strip()
            set_cookie = self.resp_headers.get("Set-Cookie") or self.resp_headers.get("set-cookie") or ""
            if set_cookie:
                for item in set_cookie.split(","):
                    first_part = item.split(";")[0]
                    if "=" in first_part:
                        k, v = first_part.split("=", 1)
                        self.cookies[k.strip()] = v.strip()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CaptureStore:
    """Persistent engagement filesystem manager"""

    def __init__(self, target: str, base_dir: Optional[Path] = None):
        parsed = urlparse(target if "://" in target else f"http://{target}")
        self.target_host = (parsed.hostname or target).lower().replace(":", "_").replace(".", "_")
        # Use a fresh temporary engagement by default.  Persisting a target's
        # traffic is opt-in through an explicit base_dir.
        self._session_only = base_dir is None
        storage_root = Path(base_dir) if base_dir is not None else Path(tempfile.mkdtemp(prefix="hunterai-engagement-"))
        self.root_dir = storage_root / self.target_host

        # Create subdirectories
        (self.root_dir / "requests").mkdir(parents=True, exist_ok=True)
        (self.root_dir / "responses").mkdir(parents=True, exist_ok=True)
        (self.root_dir / "evidence").mkdir(parents=True, exist_ok=True)
        (self.root_dir / "findings").mkdir(parents=True, exist_ok=True)
        (self.root_dir / "cases").mkdir(parents=True, exist_ok=True)

        self.scope_file = self.root_dir / "scope.json"
        self.endpoints_file = self.root_dir / "endpoints.json"
        self.parameters_file = self.root_dir / "parameters.json"
        self.technologies_file = self.root_dir / "technologies.json"
        self.identities_file = self.root_dir / "identities.json"
        self.hypotheses_file = self.root_dir / "hypotheses.json"
        self.tests_file = self.root_dir / "tests.json"
        self.timeline_file = self.root_dir / "timeline.json"

        # In-memory indices
        self.endpoints: Set[str] = set()
        self.parameters: Set[str] = set()
        self.technologies: Set[str] = set()
        self.identities: Dict[str, Dict[str, Any]] = {}
        self.hypotheses: List[Dict[str, Any]] = []
        self.tests: List[Dict[str, Any]] = []
        self.timeline: List[Dict[str, Any]] = []
        self.findings: List[Dict[str, Any]] = []
        self.transactions: Dict[str, CapturedTransaction] = {}
        self._trace_index: Dict[str, List[str]] = {}  # trace_id -> [tx_id, ...]
        self._browser_action_index: Dict[str, List[str]] = {}  # browser_action_id -> [tx_id, ...]

        if not self._session_only:
            self._load_existing()

    def _load_existing(self):
        try:
            if self.endpoints_file.exists():
                with open(self.endpoints_file, "r", encoding="utf-8") as f:
                    self.endpoints = set(json.load(f))
            if self.parameters_file.exists():
                with open(self.parameters_file, "r", encoding="utf-8") as f:
                    self.parameters = set(json.load(f))
            if self.identities_file.exists():
                with open(self.identities_file, "r", encoding="utf-8") as f:
                    self.identities = json.load(f)
            if self.hypotheses_file.exists():
                with open(self.hypotheses_file, "r", encoding="utf-8") as f:
                    self.hypotheses = json.load(f)
            if self.timeline_file.exists():
                with open(self.timeline_file, "r", encoding="utf-8") as f:
                    self.timeline = json.load(f)
        except Exception as e:
            logger.debug(f"Non-critical load error in CaptureStore: {e}")

    def save_scope(self, in_scope: List[str], out_of_scope: List[str]):
        with open(self.scope_file, "w", encoding="utf-8") as f:
            json.dump({"in_scope": in_scope, "out_of_scope": out_of_scope, "updated": time.time()}, f, indent=2)

    def store_transaction(self, tx: CapturedTransaction) -> str:
        """Stores request/response pair and extracts parameters, endpoints, lineage, and identity"""
        tx_hash = hashlib.sha256(f"{tx.method}:{tx.url}:{tx.timestamp}".encode()).hexdigest()[:12]
        tx.tx_id = tx.tx_id or f"tx_{tx_hash}"
        tx.request_id = tx.request_id or tx.tx_id

        # Harvest endpoints & parameters
        parsed = urlparse(tx.url)
        endpoint_clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        tx.endpoint_id = tx.endpoint_id or endpoint_clean
        self.endpoints.add(endpoint_clean)

        extracted_params: Set[str] = set(parse_qs(parsed.query).keys())
        if tx.req_body:
            ct = (tx.content_type or "").lower()
            if "form" in ct or ("=" in tx.req_body and not tx.req_body.strip().startswith("{")):
                try:
                    for k in parse_qs(tx.req_body).keys():
                        extracted_params.add(k)
                except Exception:
                    pass
            if "json" in ct or tx.req_body.strip().startswith("{"):
                try:
                    b_obj = json.loads(tx.req_body)
                    if isinstance(b_obj, dict):
                        extracted_params.update(b_obj.keys())
                except Exception:
                    pass

        self.parameters.update(extracted_params)
        tx.parameter_ids = list(set(tx.parameter_ids + list(extracted_params)))

        # Write scrubbed request and response streams to disk (in-memory `tx` remains intact for replay)
        req_path = self.root_dir / "requests" / f"{tx.tx_id}.json"
        _write_scrubbed_json(req_path, {
            "request_id": tx.request_id,
            "tx_id": tx.tx_id,
            "timestamp": tx.timestamp,
            "method": tx.method,
            "url": tx.url,
            "headers": tx.req_headers,
            "body": tx.req_body,
            "tool": tx.tool_source,
            "source": tx.source,
            "parent_request": tx.parent_request,
            "endpoint_id": tx.endpoint_id,
            "parameter_ids": tx.parameter_ids,
            "cookies": tx.cookies,
            "auth_context": tx.auth_context,
            "trace_id": tx.trace_id,
            "browser_action_id": tx.browser_action_id,
        })

        resp_path = self.root_dir / "responses" / f"{tx.tx_id}.json"
        _write_scrubbed_json(resp_path, {
            "request_id": tx.request_id,
            "tx_id": tx.tx_id,
            "status_code": tx.status_code,
            "content_type": tx.content_type,
            "headers": tx.resp_headers,
            "body": tx.resp_body[:10000],  # Store preview
        })

        # Detect identity context (Auth headers or cookies) — never persist raw token snippets
        auth_hdr = tx.req_headers.get("authorization", "") or tx.req_headers.get("Authorization", "")
        if auth_hdr.startswith("Bearer "):
            identity_hash = hashlib.sha256(auth_hdr.encode()).hexdigest()
            identity_name = f"BEARER_{identity_hash[:6]}"
            tx.identity = identity_name
            tx.auth_context = identity_name
            self.identities[identity_name] = {
                "type": "bearer",
                "token_fingerprint": identity_hash[:12],
                "token_prefix": SecretSanitizer.MASK_BULLET,
                "last_seen": tx.timestamp,
                "associated_urls": list(set(self.identities.get(identity_name, {}).get("associated_urls", []) + [endpoint_clean]))[:20],
            }

        # Cache in memory
        self.transactions[tx.tx_id] = tx
        if tx.request_id:
            self.transactions[tx.request_id] = tx

        if tx.trace_id:
            self._trace_index.setdefault(tx.trace_id, []).append(tx.tx_id)
        if tx.browser_action_id:
            self._browser_action_index.setdefault(tx.browser_action_id, []).append(tx.tx_id)

        # Log timeline event
        self.record_timeline_event("BURP_TRAFFIC_INGESTED", {
            "tx_id": tx.tx_id,
            "request_id": tx.request_id,
            "method": tx.method,
            "url": tx.url,
            "status": tx.status_code,
            "tool": tx.tool_source,
            "parent_request": tx.parent_request,
            "endpoint_id": tx.endpoint_id
        })

        self._flush_indices()
        return tx.tx_id

    def get_transaction(self, request_id: str) -> Optional[CapturedTransaction]:
        """Retrieves a transaction from cache or disk"""
        if request_id in self.transactions:
            return self.transactions[request_id]

        req_path = self.root_dir / "requests" / f"{request_id}.json"
        resp_path = self.root_dir / "responses" / f"{request_id}.json"
        if not req_path.exists():
            return None

        try:
            with open(req_path, "r", encoding="utf-8") as f:
                r_data = json.load(f)
            resp_data = {}
            if resp_path.exists():
                with open(resp_path, "r", encoding="utf-8") as f:
                    resp_data = json.load(f)

            tx = CapturedTransaction(
                tx_id=r_data.get("tx_id", request_id),
                request_id=r_data.get("request_id", request_id),
                target_host=self.target_host,
                method=r_data.get("method", "GET"),
                url=r_data.get("url", ""),
                status_code=resp_data.get("status_code", 200),
                req_headers=r_data.get("headers", {}),
                req_body=r_data.get("body", ""),
                resp_headers=resp_data.get("headers", {}),
                resp_body=resp_data.get("body", ""),
                tool_source=r_data.get("tool", "proxy"),
                source=r_data.get("source", "proxy"),
                timestamp=r_data.get("timestamp", time.time()),
                identity=r_data.get("auth_context", "GUEST"),
                auth_context=r_data.get("auth_context", "GUEST"),
                cookies=r_data.get("cookies", {}),
                content_type=resp_data.get("content_type", ""),
                parent_request=r_data.get("parent_request"),
                endpoint_id=r_data.get("endpoint_id", ""),
                parameter_ids=r_data.get("parameter_ids", []),
                trace_id=r_data.get("trace_id", ""),
                browser_action_id=r_data.get("browser_action_id", "")
            )
            self.transactions[request_id] = tx
            return tx
        except Exception as e:
            logger.debug(f"Failed to load transaction {request_id}: {e}")
            return None

    def list_transactions(self, limit: Optional[int] = None) -> List[CapturedTransaction]:
        """Returns captured transactions in insertion order without duplicate aliases."""
        unique: Dict[str, CapturedTransaction] = {}
        for transaction in self.transactions.values():
            unique[transaction.tx_id] = transaction
        if not self._session_only:
            req_dir = self.root_dir / "requests"
            if req_dir.is_dir():
                for req_file in sorted(req_dir.glob("*.json"), key=lambda p: p.stat().st_mtime):
                    tid = req_file.stem
                    if tid not in unique:
                        loaded = self.get_transaction(tid)
                        if loaded is not None:
                            unique[loaded.tx_id] = loaded
        transactions = list(unique.values())
        return transactions[-limit:] if limit is not None else transactions

    @staticmethod
    def format_transaction_row(
        tx: CapturedTransaction,
        *,
        redact: bool = True,
        include_bodies: bool = False,
    ) -> Dict[str, Any]:
        """Convert a CapturedTransaction into a structured HTTP table row.

        Always includes the canonical keys:
        ``id, time, method, host, path, status, length, request_headers, response_status``
        while preserving SecretSanitizer redaction.
        """
        parsed = urlparse(tx.url or "")
        host = tx.target_host or (parsed.hostname or "")
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        ts_val = float(tx.timestamp or 0.0)
        iso_time = datetime.fromtimestamp(ts_val, tz=timezone.utc).isoformat() if ts_val > 0 else ""

        req_headers = dict(tx.req_headers or {})
        resp_headers = dict(tx.resp_headers or {})
        if redact:
            req_headers = SecretSanitizer.sanitize_data(req_headers)
            resp_headers = SecretSanitizer.sanitize_data(resp_headers)

        status_int = int(tx.status_code or 0)
        row: Dict[str, Any] = {
            "id": tx.tx_id,
            "tx_id": tx.tx_id,
            "time": iso_time,
            "timestamp": ts_val,
            "method": (tx.method or "GET").upper(),
            "host": host,
            "target_host": host,
            "path": path,
            "url": tx.url or "",
            "status": status_int,
            "response_status": status_int,
            "status_code": status_int,
            "length": len(tx.resp_body or ""),
            "request_headers": req_headers,
            "response_headers": resp_headers,
            "tool_source": tx.tool_source,
            "content_type": tx.content_type,
        }
        if include_bodies:
            req_body = str(tx.req_body or "")
            resp_body = str(tx.resp_body or "")
            if redact:
                req_body = SecretSanitizer.sanitize_text(req_body)
                resp_body = SecretSanitizer.sanitize_text(resp_body)
            row["req_headers"] = req_headers
            row["resp_headers"] = resp_headers
            row["req_body"] = req_body
            row["resp_body"] = resp_body
        return row

    def query_structured_transactions(
        self,
        *,
        limit: int = 100,
        host: Optional[str] = None,
        method: Optional[str] = None,
        redact: bool = True,
        include_bodies: bool = False,
        newest_first: bool = False,
    ) -> List[Dict[str, Any]]:
        """Query structured HTTP transaction rows for `/api/burp/traffic` and live inspection."""
        all_tx = self.list_transactions(limit=None)
        host_filter = (host or "").strip().lower()
        if host_filter and "://" in host_filter:
            host_filter = (urlparse(host_filter).hostname or host_filter).lower()
        method_filter = (method or "").strip().upper()

        rows: List[Dict[str, Any]] = []
        for tx in all_tx:
            row = self.format_transaction_row(tx, redact=redact, include_bodies=include_bodies)
            if host_filter:
                row_host = str(row.get("host") or "").lower()
                row_url = str(row.get("url") or "").lower()
                if host_filter not in row_host and host_filter not in row_url:
                    continue
            if method_filter and row.get("method") != method_filter:
                continue
            rows.append(row)

        if newest_first:
            rows.reverse()
            return rows[: max(1, int(limit))]
        return rows[-max(1, int(limit)) :]

    def get_structured_transaction(
        self,
        request_id: str,
        *,
        redact: bool = True,
        include_bodies: bool = True,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve a single transaction formatted as a structured row."""
        tx = self.get_transaction(request_id)
        if tx is None:
            return None
        return self.format_transaction_row(tx, redact=redact, include_bodies=include_bodies)

    def query_live_inspection_rows(
        self,
        *,
        target: Optional[str] = None,
        limit: int = 100,
        redact: bool = True,
    ) -> List[Dict[str, Any]]:
        """Return structured rows with request/response bodies for `enhanced_burp_inspect_view(source='live')`."""
        return self.query_structured_transactions(
            limit=limit,
            host=target,
            redact=redact,
            include_bodies=True,
            newest_first=True,
        )

    def get_by_trace_id(self, trace_id: str) -> List[CapturedTransaction]:
        """Returns all transactions associated with a trace_id"""
        tx_ids = self._trace_index.get(trace_id, [])
        results = []
        for tid in tx_ids:
            tx = self.get_transaction(tid)
            if tx:
                results.append(tx)
        return results

    def get_by_browser_action_id(self, browser_action_id: str) -> List[CapturedTransaction]:
        """Returns all transactions triggered by a specific browser action"""
        tx_ids = self._browser_action_index.get(browser_action_id, [])
        results = []
        for tid in tx_ids:
            tx = self.get_transaction(tid)
            if tx:
                results.append(tx)
        return results

    def correlate_requests(self, parent_id: str, child_id: str) -> bool:
        """Explicitly correlate two requests into parent-child lineage"""
        child = self.get_transaction(child_id)
        if not child:
            return False
        child.parent_request = parent_id
        # Re-save updated child request file (scrubbed)
        req_path = self.root_dir / "requests" / f"{child.tx_id}.json"
        if req_path.exists():
            try:
                with open(req_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                data["parent_request"] = parent_id
                _write_scrubbed_json(req_path, data)
            except Exception as exc:
                logger.warning("Failed updating correlated request %s: %s", child.tx_id, exc)
        self.record_timeline_event("REQUEST_CORRELATED", {
            "parent_id": parent_id,
            "child_id": child_id
        })
        return True

    def get_request_lineage(self, request_id: str) -> List[Dict[str, Any]]:
        """Traverses parent_request ancestor chain back to root request"""
        lineage = []
        curr_id: Optional[str] = request_id
        seen: Set[str] = set()

        while curr_id and curr_id not in seen:
            seen.add(curr_id)
            tx = self.get_transaction(curr_id)
            if not tx:
                break
            lineage.append(tx.to_dict())
            curr_id = tx.parent_request

        lineage.reverse()  # Root ancestor first -> down to current request
        return lineage

    def add_hypothesis(self, vuln_type: str, endpoint: str, rationale: str, required_evidence: List[str]):
        hyp = {
            "vuln_type": vuln_type,
            "endpoint": endpoint,
            "rationale": rationale,
            "required_evidence": required_evidence,
            "created_at": time.time(),
            "status": "OPEN"
        }
        self.hypotheses.append(hyp)
        with open(self.hypotheses_file, "w", encoding="utf-8") as f:
            json.dump(self.hypotheses, f, indent=2)

    def record_finding(self, finding_dict: Dict[str, Any]):
        finding_id = finding_dict.get("id") or f"fnd_{uuid_snippet()}"
        finding_dict["id"] = finding_id
        self.findings.append(finding_dict)
        f_path = self.root_dir / "findings" / f"{finding_id}.json"
        _write_scrubbed_json(f_path, finding_dict)

        self.record_timeline_event("FINDING_CONFIRMED", {
            "id": finding_id,
            "title": finding_dict.get("title"),
            "severity": finding_dict.get("severity")
        })

    def record_timeline_event(self, event_type: str, details: Dict[str, Any]):
        self.timeline.append({
            "timestamp": time.time(),
            "event_type": event_type,
            "details": details
        })
        _write_scrubbed_json(self.timeline_file, self.timeline[-200:])

    def _flush_indices(self):
        try:
            _write_scrubbed_json(self.endpoints_file, sorted(list(self.endpoints)))
            _write_scrubbed_json(self.parameters_file, sorted(list(self.parameters)))
            _write_scrubbed_json(self.identities_file, self.identities)
        except Exception as exc:
            logger.warning("Failed flushing CaptureStore indices: %s", exc)

    def get_summary(self) -> Dict[str, Any]:
        return {
            "target": self.target_host,
            "root_dir": str(self.root_dir),
            "endpoints_count": len(self.endpoints),
            "parameters_count": len(self.parameters),
            "identities_count": len(self.identities),
            "hypotheses_count": len(self.hypotheses),
            "findings_count": len(self.findings),
            "timeline_events": len(self.timeline),
            "total_transactions": len(self.list_transactions()),
        }


def uuid_snippet():
    return hashlib.sha256(str(time.time()).encode()).hexdigest()[:8]
