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
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger("hunter_ai.capture_store")


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

    def __init__(
        self,
        target: str,
        base_dir: Optional[Union[str, Path]] = "data/engagements/default",
    ):
        parsed = urlparse(target if "://" in target else f"http://{target}")
        self.target_host = (parsed.hostname or target).lower().replace(":", "_").replace(".", "_")
        if isinstance(base_dir, str) and not base_dir.strip():
            base_dir = "data/engagements/default"
        # Persist by default under data/engagements/default; passing base_dir=None
        # explicitly opts into an isolated temporary session-only directory.
        self._session_only = base_dir is None
        storage_root = Path(base_dir) if base_dir is not None else Path(tempfile.mkdtemp(prefix="hunterai-engagement-"))
        self.base_dir = storage_root
        self.root_dir = storage_root / self.target_host

        # Explicitly create base, root, and engagement subdirectories
        os.makedirs(self.base_dir, exist_ok=True)
        os.makedirs(self.root_dir, exist_ok=True)
        for subdir in ("requests", "responses", "evidence", "findings", "cases"):
            os.makedirs(self.root_dir / subdir, exist_ok=True)

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
            self.load_previous_session()

    def _load_json_file(self, path: Path) -> Any:
        """Safely read and decode a JSON file, returning None on missing or corrupt data."""
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.debug(f"Non-critical load error in CaptureStore ({path}): {e}")
            return None

    @staticmethod
    def _merge_unique_dicts(target_list: List[Dict[str, Any]], items: Any) -> None:
        """Merge list-of-dict records into target_list without inserting duplicates."""
        if not isinstance(items, list):
            return
        seen = {
            json.dumps(item, sort_keys=True, default=str)
            for item in target_list
            if isinstance(item, dict)
        }
        for item in items:
            if isinstance(item, dict):
                key = json.dumps(item, sort_keys=True, default=str)
                if key not in seen:
                    seen.add(key)
                    target_list.append(item)

    def load_previous_session(self) -> None:
        """Reload persisted engagement indices, findings, and transactions from disk."""
        endpoints_data = self._load_json_file(self.endpoints_file)
        if isinstance(endpoints_data, list):
            self.endpoints.update(str(item) for item in endpoints_data)

        parameters_data = self._load_json_file(self.parameters_file)
        if isinstance(parameters_data, list):
            self.parameters.update(str(item) for item in parameters_data)

        technologies_data = self._load_json_file(self.technologies_file)
        if isinstance(technologies_data, list):
            self.technologies.update(str(item) for item in technologies_data)

        identities_data = self._load_json_file(self.identities_file)
        if isinstance(identities_data, dict):
            self.identities.update(identities_data)

        self._merge_unique_dicts(self.hypotheses, self._load_json_file(self.hypotheses_file))
        self._merge_unique_dicts(self.tests, self._load_json_file(self.tests_file))
        self._merge_unique_dicts(self.timeline, self._load_json_file(self.timeline_file))

        # Reload persisted findings from findings/*.json without duplicating existing IDs
        findings_dir = self.root_dir / "findings"
        if findings_dir.exists():
            seen_finding_ids = {
                f.get("id")
                for f in self.findings
                if isinstance(f, dict) and f.get("id")
            }
            seen_findings_raw = {
                json.dumps(f, sort_keys=True, default=str)
                for f in self.findings
                if isinstance(f, dict)
            }
            finding_files = sorted(
                findings_dir.glob("*.json"),
                key=lambda p: (p.stat().st_mtime, p.name),
            )
            for f_path in finding_files:
                finding_data = self._load_json_file(f_path)
                if not isinstance(finding_data, dict):
                    continue
                finding_id = finding_data.get("id")
                if finding_id:
                    if finding_id in seen_finding_ids:
                        continue
                    seen_finding_ids.add(finding_id)
                else:
                    serialized = json.dumps(finding_data, sort_keys=True, default=str)
                    if serialized in seen_findings_raw:
                        continue
                    seen_findings_raw.add(serialized)
                self.findings.append(finding_data)

        # Reload persisted HTTP transactions and lineage/trace indices
        requests_dir = self.root_dir / "requests"
        if requests_dir.exists():
            loaded_txs: List[CapturedTransaction] = []
            for req_path in sorted(requests_dir.glob("*.json")):
                stem = req_path.stem
                tx = self.transactions.get(stem) or self._load_transaction_from_disk(stem)
                if tx is not None:
                    loaded_txs.append(tx)
            loaded_txs.sort(key=lambda t: t.timestamp)
            for tx in loaded_txs:
                if tx.tx_id and tx.tx_id not in self.transactions:
                    self.transactions[tx.tx_id] = tx
                if tx.request_id and tx.request_id not in self.transactions:
                    self.transactions[tx.request_id] = tx
                if tx.trace_id:
                    trace_bucket = self._trace_index.setdefault(tx.trace_id, [])
                    if tx.tx_id not in trace_bucket:
                        trace_bucket.append(tx.tx_id)
                if tx.browser_action_id:
                    action_bucket = self._browser_action_index.setdefault(tx.browser_action_id, [])
                    if tx.tx_id not in action_bucket:
                        action_bucket.append(tx.tx_id)

    def _load_existing(self) -> None:
        """Backwards-compatible alias for load_previous_session()."""
        self.load_previous_session()

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

        # Write request and response streams
        req_path = self.root_dir / "requests" / f"{tx.tx_id}.json"
        with open(req_path, "w", encoding="utf-8") as f:
            json.dump({
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
                "browser_action_id": tx.browser_action_id
            }, f, indent=2)

        resp_path = self.root_dir / "responses" / f"{tx.tx_id}.json"
        with open(resp_path, "w", encoding="utf-8") as f:
            json.dump({
                "request_id": tx.request_id,
                "tx_id": tx.tx_id,
                "status_code": tx.status_code,
                "content_type": tx.content_type,
                "headers": tx.resp_headers,
                "body": tx.resp_body[:10000]  # Store preview
            }, f, indent=2)

        # Detect identity context (Auth headers or cookies)
        auth_hdr = tx.req_headers.get("authorization", "") or tx.req_headers.get("Authorization", "")
        if auth_hdr.startswith("Bearer "):
            token_snippet = auth_hdr[7:20]
            identity_name = f"BEARER_{hashlib.sha256(auth_hdr.encode()).hexdigest()[:6]}"
            tx.identity = identity_name
            tx.auth_context = identity_name
            self.identities[identity_name] = {
                "type": "bearer",
                "token_prefix": token_snippet,
                "last_seen": tx.timestamp,
                "associated_urls": list(set(self.identities.get(identity_name, {}).get("associated_urls", []) + [endpoint_clean]))[:20]
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

    def _load_transaction_from_disk(self, request_id: str) -> Optional[CapturedTransaction]:
        """Reads a single transaction's request/response files from disk."""
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

            return CapturedTransaction(
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
                browser_action_id=r_data.get("browser_action_id", ""),
            )
        except Exception as e:
            logger.debug(f"Failed to load transaction {request_id}: {e}")
            return None

    def get_transaction(self, request_id: str) -> Optional[CapturedTransaction]:
        """Retrieves a transaction from cache or disk"""
        if request_id in self.transactions:
            return self.transactions[request_id]

        tx = self._load_transaction_from_disk(request_id)
        if tx is None:
            return None

        self.transactions[request_id] = tx
        if tx.tx_id:
            self.transactions[tx.tx_id] = tx
        if tx.request_id:
            self.transactions[tx.request_id] = tx
        return tx

    def list_transactions(self, limit: Optional[int] = None) -> List[CapturedTransaction]:
        """Returns captured transactions in insertion order without duplicate aliases."""
        unique: Dict[str, CapturedTransaction] = {}
        for transaction in self.transactions.values():
            unique[transaction.tx_id] = transaction
        transactions = list(unique.values())
        return transactions[-limit:] if limit is not None else transactions

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
        # Re-save updated child request file
        req_path = self.root_dir / "requests" / f"{child.tx_id}.json"
        if req_path.exists():
            try:
                with open(req_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                data["parent_request"] = parent_id
                with open(req_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
            except Exception:
                pass
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
        existing_idx = next(
            (i for i, existing in enumerate(self.findings) if isinstance(existing, dict) and existing.get("id") == finding_id),
            None,
        )
        if existing_idx is not None:
            self.findings[existing_idx] = finding_dict
        else:
            self.findings.append(finding_dict)
        f_path = self.root_dir / "findings" / f"{finding_id}.json"
        with open(f_path, "w", encoding="utf-8") as f:
            json.dump(finding_dict, f, indent=2)

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
        with open(self.timeline_file, "w", encoding="utf-8") as f:
            json.dump(self.timeline[-200:], f, indent=2)

    def _flush_indices(self):
        try:
            with open(self.endpoints_file, "w", encoding="utf-8") as f:
                json.dump(sorted(list(self.endpoints)), f, indent=2)
            with open(self.parameters_file, "w", encoding="utf-8") as f:
                json.dump(sorted(list(self.parameters)), f, indent=2)
            with open(self.identities_file, "w", encoding="utf-8") as f:
                json.dump(self.identities, f, indent=2)
        except Exception:
            pass

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
    return uuid.uuid4().hex[:8]
