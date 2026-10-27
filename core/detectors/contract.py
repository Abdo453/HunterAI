"""Detector contract for safe, deterministic, read-only verification.

Every detector in this package follows the same shape:

1. it receives a :class:`DetectionContext` (target, path, parameter);
2. it sends a small number of ``GET`` probes through an
   :class:`~core.detectors.transport.HttpTransport`;
3. it returns a :class:`Detection` that is either confirmed (with a
   :class:`~core.finding_model.Finding`) or explicitly unconfirmed, with the
   reason and the raw exchanges attached.

Design rules
------------
* **Read-only.**  The transport only exposes ``GET``/``HEAD``.  There is no
  generic ``request()`` that could be used to send a write verb.
* **Differential.**  A finding needs a control comparison, not a single
  suspicious response.  Reflection, generic 500s and look-alike responses are
  rejected.
* **Evidence first.**  Every exchange carries a request hash and a response
  hash; the evidence chain links them so a finding can be re-evaluated.
* **No silent success.**  ``confirmed=False`` always carries a reason.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Protocol
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from core.finding_model import Finding

if TYPE_CHECKING:  # pragma: no cover - typing only
    from core.detectors.transport import HttpTransport


class ProbeMethod(str, Enum):
    """The only HTTP methods the lab is allowed to send."""

    GET = "GET"
    HEAD = "HEAD"


@dataclass(frozen=True)
class Probe:
    """One immutable HTTP request."""

    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        method = str(self.method or "").upper()
        allowed = {item.value for item in ProbeMethod}
        if method not in allowed:
            raise ValueError(
                f"method {self.method!r} is not allowed; the lab is read-only "
                f"({', '.join(sorted(allowed))})"
            )
        object.__setattr__(self, "method", method)
        object.__setattr__(self, "headers", dict(self.headers))

    def canonical(self) -> str:
        headers = "\n".join(
            f"{key.lower()}:{value}" for key, value in sorted(self.headers.items())
        )
        return f"{self.method} {self.url}\n{headers}"


@dataclass(frozen=True)
class ProbeExchange:
    """A request plus the exact response that came back."""

    probe: Probe
    status_code: int
    response_headers: Dict[str, str]
    body: str
    elapsed_ms: float
    request_hash: str
    response_hash: str
    truncated: bool = False
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": self.probe.method,
            "url": self.probe.url,
            "status_code": self.status_code,
            "request_hash": self.request_hash,
            "response_hash": self.response_hash,
            "truncated": self.truncated,
            "timestamp": self.timestamp,
            "body_snippet": self.body[:500],
        }


@dataclass
class Detection:
    """The outcome of one detector run."""

    vuln_class: str
    confirmed: bool
    confidence: float
    reason: str
    finding: Optional[Finding] = None
    exchanges: List[ProbeExchange] = field(default_factory=list)
    detector: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detector": self.detector,
            "vuln_class": self.vuln_class,
            "confirmed": self.confirmed,
            "confidence": self.confidence,
            "reason": self.reason,
            "finding": self.finding.to_dict() if self.finding else None,
            "exchanges": [exchange.to_dict() for exchange in self.exchanges],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


@dataclass
class DetectionContext:
    """Everything a detector needs to probe one parameter or resource."""

    base_url: str
    path: str
    parameter: str = ""
    extra_params: Dict[str, str] = field(default_factory=dict)

    # IDOR-specific fields.
    id_parameter: str = "id"
    resource_id: str = "1"
    owner_headers: Dict[str, str] = field(default_factory=dict)
    other_headers: Dict[str, str] = field(default_factory=dict)
    owner_marker: str = ""
    check_anonymous: bool = True


class Detector(Protocol):
    """Structural contract implemented by every detector."""

    name: str
    vuln_class: str

    def detect(self, context: DetectionContext, transport: "HttpTransport") -> Detection:
        ...


# ---------------------------------------------------------------------------
# Helpers shared by the detectors
# ---------------------------------------------------------------------------

def build_url(base_url: str, path: str, params: Optional[Dict[str, str]] = None) -> str:
    """Join an origin, a path and query parameters without duplicating keys."""
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"base_url must be http(s)://host, got {base_url!r}")
    clean_path = path or "/"
    if not clean_path.startswith("/"):
        clean_path = "/" + clean_path
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    for key, value in (params or {}).items():
        if value is not None:
            query[key] = value
    return urlunparse(
        (parsed.scheme, parsed.netloc, clean_path, "", urlencode(query, doseq=True), "")
    )


def normalize_body(body: str) -> str:
    """Collapse whitespace so cosmetic formatting is not a differential."""
    return " ".join(str(body or "").split())


def sha256_text(value: str) -> str:
    return hashlib.sha256(str(value).encode("utf-8", errors="replace")).hexdigest()


def sha256_json(value: Any) -> str:
    blob = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    )
    return sha256_text(blob)


def to_exchange_record(exchange: ProbeExchange):
    """Convert a probe exchange into the unified finding record."""
    from core.finding_model import HttpExchangeRecord

    return HttpExchangeRecord(
        method=exchange.probe.method,
        url=exchange.probe.url,
        headers=dict(exchange.probe.headers),
        status_code=exchange.status_code,
        response_headers=dict(exchange.response_headers),
        response_body_snippet=exchange.body[:300],
        timestamp=exchange.timestamp,
    )
