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
    tx_id: str
    target_host: str
    method: str
    url: str
    status_code: int
    req_headers: Dict[str, str] = field(default_factory=dict)
    req_body: str = ""
    resp_headers: Dict[str, str] = field(default_factory=dict)
    resp_body: str = ""
    tool_source: str = "proxy"  # proxy | repeater | scanner | target
    timestamp: float = field(default_factory=lambda: time.time())
    identity: str = "GUEST"     # Identified auth context (User A, User B, Admin)

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
        """Stores request/response pair and extracts parameters, endpoints, and identity"""
        tx_hash = hashlib.sha256(f"{tx.method}:{tx.url}:{tx.timestamp}".encode()).hexdigest()[:12]
        tx.tx_id = tx.tx_id or f"tx_{tx_hash}"

        # Write request and response streams
        req_path = self.root_dir / "requests" / f"{tx.tx_id}.json"
        with open(req_path, "w", encoding="utf-8") as f:
            json.dump({
                "tx_id": tx.tx_id,
                "timestamp": tx.timestamp,
                "method": tx.method,
                "url": tx.url,
                "headers": tx.req_headers,
                "body": tx.req_body,
                "tool": tx.tool_source
            }, f, indent=2)

        resp_path = self.root_dir / "responses" / f"{tx.tx_id}.json"
        with open(resp_path, "w", encoding="utf-8") as f:
            json.dump({
                "tx_id": tx.tx_id,
                "status_code": tx.status_code,
                "headers": tx.resp_headers,
                "body": tx.resp_body[:10000]  # Store preview
            }, f, indent=2)

        # Harvest endpoints & parameters
        parsed = urlparse(tx.url)
        endpoint_clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        self.endpoints.add(endpoint_clean)
        for p in parse_qs(parsed.query).keys():
            self.parameters.add(p)

        # Detect identity context (Auth headers or cookies)
        auth_hdr = tx.req_headers.get("authorization", "") or tx.req_headers.get("Authorization", "")
        if auth_hdr.startswith("Bearer "):
            token_snippet = auth_hdr[7:20]
            identity_name = f"BEARER_{hashlib.sha256(auth_hdr.encode()).hexdigest()[:6]}"
            tx.identity = identity_name
            self.identities[identity_name] = {
                "type": "bearer",
                "token_prefix": token_snippet,
                "last_seen": tx.timestamp,
                "associated_urls": list(set(self.identities.get(identity_name, {}).get("associated_urls", []) + [endpoint_clean]))[:20]
            }

        # Log timeline event
        self.record_timeline_event("BURP_TRAFFIC_INGESTED", {
            "tx_id": tx.tx_id,
            "method": tx.method,
            "url": tx.url,
            "status": tx.status_code,
            "tool": tx.tool_source
        })

        self._flush_indices()
        return tx.tx_id

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
