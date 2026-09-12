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
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
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
        self.root_dir = (base_dir or Path("data/engagements")) / self.target_host

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
                "auth_context": tx.auth_context
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
                parameter_ids=r_data.get("parameter_ids", [])
            )
            self.transactions[request_id] = tx
            return tx
        except Exception as e:
            logger.debug(f"Failed to load transaction {request_id}: {e}")
            return None

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
        }


def uuid_snippet():
    return hashlib.sha256(str(time.time()).encode()).hexdigest()[:8]
