"""
Request Recorder — Captures all HTTP interactions with REQ-XXXXXX IDs.
Secret redaction applied before any UI/report display.
"""
from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# Regex patterns for common secrets to redact
_SECRET_PATTERNS = [
    (re.compile(r"(Authorization:\s*Bearer\s+)[A-Za-z0-9\-_\.]+", re.I), r"\1[REDACTED]"),
    (re.compile(r"(Authorization:\s*Basic\s+)[A-Za-z0-9+/=]+", re.I),   r"\1[REDACTED]"),
    (re.compile(r"(api[_\-]?key[=:\s]+)[A-Za-z0-9\-_]{16,}", re.I),     r"\1[REDACTED]"),
    (re.compile(r"(token[=:\s]+)[A-Za-z0-9\-_\.]{20,}", re.I),           r"\1[REDACTED]"),
    (re.compile(r"(password[=:\s]+)\S+", re.I),                           r"\1[REDACTED]"),
    (re.compile(r"(secret[=:\s]+)\S+", re.I),                             r"\1[REDACTED]"),
    (re.compile(r"(X-Api-Key:\s+)[^\r\n]+", re.I),                        r"\1[REDACTED]"),
    (re.compile(r"(Cookie:\s+)[^\r\n]*session[^\r\n]*", re.I),            r"\1[REDACTED]"),
]


def _redact(text: str) -> str:
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


@dataclass
class RequestRecord:
    req_id: str = field(default_factory=lambda: f"REQ-{uuid.uuid4().hex[:6].upper()}")
    method: str = "GET"
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    response_status: int = 0
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    agent: str = ""
    tool: str = ""
    trace_id: str = ""
    browser_action_id: str = ""
    timestamp: float = field(default_factory=time.time)
    duration_ms: float = 0.0
    tags: List[str] = field(default_factory=list)

    def to_safe_dict(self) -> Dict[str, Any]:
        """Returns display-safe dict with secrets redacted. Use for UI and reports."""
        raw_headers = "\n".join(f"{k}: {v}" for k, v in self.headers.items())
        raw_resp_hdr = "\n".join(f"{k}: {v}" for k, v in self.response_headers.items())
        return {
            "req_id":          self.req_id,
            "method":          self.method,
            "url":             self.url,
            "headers":         _redact(raw_headers),
            "body":            _redact(self.body[:500]),
            "response_status": self.response_status,
            "response_headers":_redact(raw_resp_hdr),
            "response_body":   _redact(self.response_body[:500]),
            "agent":           self.agent,
            "tool":            self.tool,
            "trace_id":        self.trace_id,
            "browser_action_id": self.browser_action_id,
            "timestamp":       self.timestamp,
            "duration_ms":     self.duration_ms,
            "tags":            self.tags,
        }

    def to_dict(self) -> Dict[str, Any]:
        """Internal dict — secrets NOT redacted. Do NOT send to UI/report."""
        return {
            "req_id": self.req_id, "method": self.method, "url": self.url,
            "headers": self.headers, "body": self.body,
            "response_status": self.response_status,
            "response_headers": self.response_headers,
            "response_body": self.response_body,
            "agent": self.agent, "tool": self.tool,
            "trace_id": self.trace_id, "browser_action_id": self.browser_action_id,
            "timestamp": self.timestamp, "duration_ms": self.duration_ms, "tags": self.tags,
        }


class RequestRecorder:
    """Stores all HTTP interactions in memory, indexed by req_id and trace_id."""

    def __init__(self, max_records: int = 10_000) -> None:
        self._records: Dict[str, RequestRecord] = {}
        self._trace_index: Dict[str, List[str]] = {}   # trace_id -> [req_id, ...]
        self._browser_index: Dict[str, List[str]] = {} # browser_action_id -> [req_id, ...]
        self._max_records = max_records

    def record(self, req: RequestRecord) -> str:
        if len(self._records) >= self._max_records:
            oldest = next(iter(self._records))
            del self._records[oldest]

        self._records[req.req_id] = req

        if req.trace_id:
            self._trace_index.setdefault(req.trace_id, []).append(req.req_id)
        if req.browser_action_id:
            self._browser_index.setdefault(req.browser_action_id, []).append(req.req_id)

        return req.req_id

    def get(self, req_id: str) -> Optional[RequestRecord]:
        return self._records.get(req_id)

    def get_by_trace(self, trace_id: str) -> List[RequestRecord]:
        return [self._records[rid] for rid in self._trace_index.get(trace_id, []) if rid in self._records]

    def get_by_browser_action(self, browser_action_id: str) -> List[RequestRecord]:
        return [self._records[rid] for rid in self._browser_index.get(browser_action_id, []) if rid in self._records]

    def get_recent(self, n: int = 50) -> List[RequestRecord]:
        return list(self._records.values())[-n:]

    def to_safe_list(self, n: int = 50) -> List[Dict[str, Any]]:
        """Returns recent records with secrets redacted — safe for UI."""
        return [r.to_safe_dict() for r in self.get_recent(n)]

    def summary(self) -> Dict[str, Any]:
        statuses: Dict[int, int] = {}
        for r in self._records.values():
            statuses[r.response_status] = statuses.get(r.response_status, 0) + 1
        return {
            "total": len(self._records),
            "status_counts": statuses,
            "traces": len(self._trace_index),
        }

    def __len__(self) -> int:
        return len(self._records)
