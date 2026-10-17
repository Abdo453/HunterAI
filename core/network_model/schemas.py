"""Canonical network data model — Host / Service / ProtocolTrace / NetworkFinding.

This is the *shared* language that every network tool pilot (L1→L5) normalizes
into, and the vocabulary the network side of the Evidence Graph speaks. It
generalizes the nmap pilot's ``NmapPortRecord`` so that non-nmap tools
(masscan, rustscan, netexec, impacket, ...) land in the same shape.

Evidence levels follow the platform-wide forensic tiers (ARCHITECTURE.md):
  E0 = observed (raw tool output, unreviewed)
  E2 = reproducible (deterministic re-run / control comparison)
  E5 = sealed (signed, tamper-evident replay bundle)
"""
from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


class NetworkEvidenceLevel(str):
    E0 = "E0"  # Observed — raw tool output, needs review
    E2 = "E2"  # Reproducible — deterministic differential confirmation
    E5 = "E5"  # Sealed — signed replay bundle


class ServiceState(str):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"
    UNKNOWN = "unknown"


class ServiceConfidence(str):
    CONFIRMED = "confirmed"  # banner + version match
    PROBABLE = "probable"    # strong banner match
    POSSIBLE = "possible"    # port only / weak banner
    UNKNOWN = "unknown"


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


@dataclass
class ServiceRecord:
    """A single observed service on a host:port endpoint."""

    host: str
    port: int
    protocol: str = "tcp"  # transport: tcp / udp
    state: str = ServiceState.OPEN
    service_name: Optional[str] = None
    service_product: Optional[str] = None
    service_version: Optional[str] = None
    banner: Optional[str] = None
    cpe: Optional[str] = None
    confidence: str = ServiceConfidence.UNKNOWN
    evidence_level: str = NetworkEvidenceLevel.E0
    source_tool: str = ""
    record_id: str = ""
    captured_at: float = field(default_factory=time.time)
    extra: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.record_id:
            self.record_id = _new_id("svc")

    @property
    def canonical_key(self) -> str:
        """De-duplication key: ``tcp://host:port``."""
        return f"{self.protocol}://{self.host}:{self.port}"

    @property
    def endpoint(self) -> str:
        return self.canonical_key

    @property
    def is_high_value(self) -> bool:
        """Coarse flag for services that historically lead to compromise."""
        high_value = {
            "smb", "microsoft-ds", "netbios-ssn", "ldap", "ldaps", "kerberos",
            "msrpc", "rdp", "ms-wbt-server", "winrm", "wsman", "ssh", "telnet",
            "ftp", "docker", "kubernetes", "elasticsearch", "redis", "mongodb",
            "mssql", "mysql", "postgresql", "vnc", "rlogin", "rsync", "oracle",
        }
        return (self.service_name or "").strip().lower() in high_value

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_nmap_record(cls, rec: Any) -> "ServiceRecord":
        """Adapt a ``core.nmap.schemas.NmapPortRecord`` into a ServiceRecord."""
        return cls(
            host=getattr(rec, "host", ""),
            port=int(getattr(rec, "port", 0) or 0),
            protocol=getattr(rec, "protocol", "tcp") or "tcp",
            state=getattr(rec, "state", ServiceState.UNKNOWN) or ServiceState.UNKNOWN,
            service_name=getattr(rec, "service_name", None),
            service_product=getattr(rec, "service_product", None),
            service_version=getattr(rec, "service_version", None),
            banner=getattr(rec, "banner", None),
            confidence=getattr(rec, "confidence", ServiceConfidence.UNKNOWN),
            evidence_level=getattr(rec, "evidence_level", NetworkEvidenceLevel.E0),
            source_tool=getattr(rec, "source_tool", "nmap") or "nmap",
        )


@dataclass
class HostRecord:
    """A live network host and everything observed about it."""

    host: str  # operator-supplied identifier (hostname or IP)
    address: Optional[str] = None  # resolved IP, when known
    hostnames: List[str] = field(default_factory=list)
    state: str = "up"
    os_guess: Optional[str] = None
    services: List[ServiceRecord] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    evidence_level: str = NetworkEvidenceLevel.E0
    source_tool: str = ""
    record_id: str = ""
    captured_at: float = field(default_factory=time.time)
    extra: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.record_id:
            self.record_id = _new_id("host")

    @property
    def canonical_key(self) -> str:
        return (self.address or self.host or "").strip().lower()

    @property
    def open_services(self) -> List[ServiceRecord]:
        return [s for s in self.services if s.state == ServiceState.OPEN]

    @property
    def open_ports(self) -> List[int]:
        return sorted({s.port for s in self.open_services})

    def add_service(self, service: ServiceRecord) -> ServiceRecord:
        """Add or replace a service by ``protocol://host:port`` key."""
        key = service.canonical_key
        for idx, existing in enumerate(self.services):
            if existing.canonical_key == key:
                self.services[idx] = service
                return service
        self.services.append(service)
        return service

    def high_value_services(self) -> List[ServiceRecord]:
        return [s for s in self.open_services if s.is_high_value]

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["services"] = [s.to_dict() for s in self.services]
        return data


@dataclass
class ProtocolTrace:
    """A raw protocol exchange captured during network testing (evidence)."""

    host: str
    port: int
    protocol: str = "tcp"
    summary: str = ""
    request: Optional[str] = None
    response: Optional[str] = None
    transport: str = "tcp"
    evidence_level: str = NetworkEvidenceLevel.E0
    source_tool: str = ""
    trace_id: str = ""
    captured_at: float = field(default_factory=time.time)
    raw: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.trace_id:
            self.trace_id = _new_id("trace")

    @property
    def sha256(self) -> str:
        """Deterministic hash of the request/response pair (evidence integrity)."""
        blob = f"{self.protocol}|{self.host}|{self.port}|{self.request}|{self.response}"
        return hashlib.sha256(blob.encode("utf-8", errors="replace")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["sha256"] = self.sha256
        return data


@dataclass
class NetworkFinding:
    """A candidate/failed/confirmed network finding.

    Mirrors the platform creed: a finding is ``candidate`` until the network
    Evidence Court confirms it with reproducible proof — never on an LLM claim.
    """

    title: str
    host: str
    port: Optional[int] = None
    protocol: str = "tcp"
    service_name: Optional[str] = None
    vuln_class: str = ""
    severity: str = "INFO"
    confidence: float = 0.0
    evidence_level: str = NetworkEvidenceLevel.E0
    status: str = "candidate"  # candidate | confirmed | false_positive | unverified
    description: str = ""
    reproduction_command: str = ""
    remediation: str = ""
    cwe: Optional[str] = None
    references: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    finding_id: str = ""
    created_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if not self.finding_id:
            self.finding_id = _new_id("netfind")

    @property
    def endpoint(self) -> str:
        return f"{self.protocol}://{self.host}:{self.port}" if self.port else f"{self.protocol}://{self.host}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
