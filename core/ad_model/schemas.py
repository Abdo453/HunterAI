"""Active Directory canonical data model — Domain / DC / Principal / Share.

This is the AD analogue of :mod:`core.network_model`: the shared vocabulary that
the AD pilots (enum4linux-ng, netexec, impacket, ...) normalize into, and the
structure the AD enumeration planner and the Evidence Court read from.

Design creed (unchanged): an object observed here is *raw evidence* (E0). A
"kerberoastable account" is a **hypothesis**, never a confirmed compromise,
until the court adjudicates reproducible proof.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


class ADEvidenceLevel(str):
    E0 = "E0"  # Observed — raw enumeration output
    E2 = "E2"  # Reproducible — deterministic re-enumeration


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


# Services that together indicate a Domain Controller.
DC_MARKER_SERVICES = {"kerberos", "kdc", "ldap", "ldaps", "gc", "ldap-gc"}


@dataclass
class ADPrincipal:
    """A user, computer, or group observed in the directory."""

    name: str
    sam_account_name: Optional[str] = None
    dn: Optional[str] = None
    domain: Optional[str] = None
    kind: str = "user"  # user | computer | group
    enabled: bool = True
    spn_list: List[str] = field(default_factory=list)
    does_not_require_preauth: bool = False  # AS-REP roastable
    admin_count: bool = False
    unconstrained_delegation: bool = False
    constrained_delegation: List[str] = field(default_factory=list)
    member_of: List[str] = field(default_factory=list)
    last_logon: Optional[str] = None
    password_last_set: Optional[str] = None
    description: Optional[str] = None
    source_tool: str = ""
    evidence_level: str = ADEvidenceLevel.E0
    record_id: str = ""

    def __post_init__(self) -> None:
        if not self.record_id:
            self.record_id = _new_id("adp")

    @property
    def canonical_key(self) -> str:
        ident = (self.sam_account_name or self.name or "").strip().lower()
        return f"{self.kind}:{ident}"

    @property
    def kerberoastable(self) -> bool:
        """A user account with an SPN is Kerberoastable (needs a valid TGT)."""
        return self.kind == "user" and bool(self.spn_list) and self.enabled

    @property
    def asreproastable(self) -> bool:
        """No pre-auth required → AS-REP hash obtainable without credentials."""
        return self.kind == "user" and self.does_not_require_preauth and self.enabled

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["kerberoastable"] = self.kerberoastable
        data["asreproastable"] = self.asreproastable
        return data


@dataclass
class ADShare:
    """An SMB share observed on a host."""

    name: str
    host: str
    domain: Optional[str] = None
    access: Optional[str] = None  # e.g. "READ", "READ,WRITE", "NONE"
    comment: Optional[str] = None
    is_anonymous: bool = False
    source_tool: str = ""
    evidence_level: str = ADEvidenceLevel.E0
    record_id: str = ""

    def __post_init__(self) -> None:
        if not self.record_id:
            self.record_id = _new_id("adshare")

    @property
    def writable(self) -> bool:
        return "WRITE" in (self.access or "").upper()

    @property
    def canonical_key(self) -> str:
        return f"{self.host.strip().lower()}:{self.name.strip().lower()}"

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["writable"] = self.writable
        return data


@dataclass
class ADDomainInfo:
    """Domain-level facts: policy, functional level, trust relationships."""

    domain: str
    netbios: Optional[str] = None
    forest: Optional[str] = None
    functional_level: Optional[str] = None
    machine_account_quota: Optional[int] = None
    password_policy: Dict[str, Any] = field(default_factory=dict)
    trusts: List[str] = field(default_factory=list)
    source_tool: str = ""
    evidence_level: str = ADEvidenceLevel.E0
    record_id: str = ""

    def __post_init__(self) -> None:
        if not self.record_id:
            self.record_id = _new_id("addom")

    @property
    def canonical_key(self) -> str:
        return (self.domain or "").strip().lower()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ADDomainController:
    """A host identified as a Domain Controller."""

    host: str
    domain: Optional[str] = None
    address: Optional[str] = None
    services: List[str] = field(default_factory=list)
    is_readonly: bool = False
    os_family: Optional[str] = None
    smb_signing: Optional[bool] = None
    smbv1_enabled: Optional[bool] = None
    source_tool: str = ""
    evidence_level: str = ADEvidenceLevel.E0
    record_id: str = ""

    def __post_init__(self) -> None:
        if not self.record_id:
            self.record_id = _new_id("addc")

    @property
    def canonical_key(self) -> str:
        return (self.address or self.host or "").strip().lower()

    @property
    def is_domain_controller(self) -> bool:
        svc = {s.strip().lower() for s in self.services}
        # Kerberos/LDAP together is the strongest DC signal.
        return len(svc & DC_MARKER_SERVICES) >= 2 or "kerberos" in svc or "kdc" in svc

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["is_domain_controller"] = self.is_domain_controller
        return data
