"""ADGraph — the Active Directory attack-surface graph.

    domain ⇄ domain-controller ⇄ principal (user/group/computer) ⇄ share

Dependency-free in-memory store, projectable into the platform Evidence Graph
via :meth:`ADGraph.to_evidence_nodes`, and buildable from an existing
:class:`~core.network_model.HostGraph` via :meth:`ADGraph.from_host_graph`.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from core.ad_model.schemas import (
    ADDomainController,
    ADDomainInfo,
    ADEvidenceLevel,
    ADPrincipal,
    ADShare,
)
from core.network_model import HostGraph


class ADGraph:
    """In-memory Active Directory graph (domains, DCs, principals, shares)."""

    def __init__(self) -> None:
        self._domains: Dict[str, ADDomainInfo] = {}
        self._dcs: Dict[str, ADDomainController] = {}
        self._principals: Dict[str, ADPrincipal] = {}
        self._shares: Dict[str, ADShare] = {}

    # ── Domains ──────────────────────────────────────────────────────────────
    def add_domain(self, domain: ADDomainInfo) -> ADDomainInfo:
        key = domain.canonical_key
        if not key:
            return domain
        existing = self._domains.get(key)
        if existing is None:
            self._domains[key] = domain
            return domain
        # Merge: fill blanks, union trusts.
        existing.netbios = existing.netbios or domain.netbios
        existing.forest = existing.forest or domain.forest
        existing.functional_level = existing.functional_level or domain.functional_level
        if domain.machine_account_quota is not None:
            existing.machine_account_quota = domain.machine_account_quota
        if domain.password_policy:
            existing.password_policy = {**existing.password_policy, **domain.password_policy}
        existing.trusts = sorted(set(existing.trusts) | set(domain.trusts))
        return existing

    def get_domain(self, domain: str) -> Optional[ADDomainInfo]:
        return self._domains.get((domain or "").strip().lower())

    # ── Domain controllers ───────────────────────────────────────────────────
    def add_dc(self, dc: ADDomainController) -> ADDomainController:
        key = dc.canonical_key
        if not key:
            return dc
        existing = self._dcs.get(key)
        if existing is None:
            self._dcs[key] = dc
            return dc
        existing.domain = existing.domain or dc.domain
        existing.address = existing.address or dc.address
        existing.services = sorted(set(existing.services) | set(dc.services))
        existing.is_readonly = existing.is_readonly or dc.is_readonly
        existing.os_family = existing.os_family or dc.os_family
        if dc.smb_signing is not None:
            existing.smb_signing = dc.smb_signing
        if dc.smbv1_enabled is not None:
            existing.smbv1_enabled = dc.smbv1_enabled
        return existing

    def get_dc(self, host: str) -> Optional[ADDomainController]:
        key = (host or "").strip().lower()
        if key in self._dcs:
            return self._dcs[key]
        for dc in self._dcs.values():
            if dc.address and dc.address.strip().lower() == key:
                return dc
        return None

    def domain_controllers(self) -> List[ADDomainController]:
        return list(self._dcs.values())

    def primary_dc(self) -> Optional[ADDomainController]:
        for dc in self._dcs.values():
            if dc.is_domain_controller:
                return dc
        return next(iter(self._dcs.values()), None)

    # ── Principals ───────────────────────────────────────────────────────────
    def add_principal(self, principal: ADPrincipal) -> ADPrincipal:
        key = principal.canonical_key
        if not key or key.endswith(":"):
            return principal
        existing = self._principals.get(key)
        if existing is None:
            self._principals[key] = principal
            return principal
        existing.domain = existing.domain or principal.domain
        existing.dn = existing.dn or principal.dn
        existing.enabled = existing.enabled or principal.enabled
        existing.spn_list = sorted(set(existing.spn_list) | set(principal.spn_list))
        existing.member_of = sorted(set(existing.member_of) | set(principal.member_of))
        existing.does_not_require_preauth = (
            existing.does_not_require_preauth or principal.does_not_require_preauth
        )
        existing.admin_count = existing.admin_count or principal.admin_count
        existing.unconstrained_delegation = (
            existing.unconstrained_delegation or principal.unconstrained_delegation
        )
        existing.constrained_delegation = sorted(
            set(existing.constrained_delegation) | set(principal.constrained_delegation)
        )
        return existing

    def add_principals(self, principals: List[ADPrincipal]) -> int:
        for p in principals:
            self.add_principal(p)
        return len(principals)

    def principals(self, domain: Optional[str] = None, kind: Optional[str] = None) -> List[ADPrincipal]:
        out = list(self._principals.values())
        if domain:
            want = domain.strip().lower()
            out = [p for p in out if (p.domain or "").strip().lower() == want]
        if kind:
            out = [p for p in out if p.kind == kind]
        return out

    def kerberoastable(self, domain: Optional[str] = None) -> List[ADPrincipal]:
        return [p for p in self.principals(domain=domain) if p.kerberoastable]

    def asreproastable(self, domain: Optional[str] = None) -> List[ADPrincipal]:
        return [p for p in self.principals(domain=domain) if p.asreproastable]

    def unconstrained_delegation(self, domain: Optional[str] = None) -> List[ADPrincipal]:
        return [p for p in self.principals(domain=domain) if p.unconstrained_delegation]

    # ── Shares ───────────────────────────────────────────────────────────────
    def add_share(self, share: ADShare) -> ADShare:
        key = share.canonical_key
        if not key or key.endswith(":"):
            return share
        existing = self._shares.get(key)
        if existing is None:
            self._shares[key] = share
            return share
        existing.domain = existing.domain or share.domain
        existing.access = share.access or existing.access
        existing.comment = existing.comment or share.comment
        existing.is_anonymous = existing.is_anonymous or share.is_anonymous
        return existing

    def add_shares(self, shares: List[ADShare]) -> int:
        for s in shares:
            self.add_share(s)
        return len(shares)

    def shares(self, host: Optional[str] = None) -> List[ADShare]:
        out = list(self._shares.values())
        if host:
            want = host.strip().lower()
            out = [s for s in out if s.host.strip().lower() == want]
        return out

    def writable_shares(self) -> List[ADShare]:
        return [s for s in self._shares.values() if s.writable]

    def anonymous_shares(self) -> List[ADShare]:
        return [s for s in self._shares.values() if s.is_anonymous]

    # ── Aggregate ────────────────────────────────────────────────────────────
    def summary(self) -> Dict[str, Any]:
        return {
            "domains": len(self._domains),
            "domain_controllers": sum(1 for d in self._dcs.values() if d.is_domain_controller),
            "principals": len(self._principals),
            "users": sum(1 for p in self._principals.values() if p.kind == "user"),
            "kerberoastable": len(self.kerberoastable()),
            "asreproastable": len(self.asreproastable()),
            "unconstrained_delegation": len(self.unconstrained_delegation()),
            "shares": len(self._shares),
            "writable_shares": len(self.writable_shares()),
            "anonymous_shares": len(self.anonymous_shares()),
        }

    # ── Serialization / Evidence Graph projection ────────────────────────────
    def to_dict(self) -> Dict[str, Any]:
        return {
            "domains": [d.to_dict() for d in self._domains.values()],
            "domain_controllers": [d.to_dict() for d in self._dcs.values()],
            "principals": [p.to_dict() for p in self._principals.values()],
            "shares": [s.to_dict() for s in self._shares.values()],
            "summary": self.summary(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ADGraph":
        graph = cls()
        for d in data.get("domains", []) or []:
            graph.add_domain(ADDomainInfo(**{
                k: v for k, v in d.items() if k in ADDomainInfo.__dataclass_fields__
            }))
        for dc in data.get("domain_controllers", []) or []:
            graph.add_dc(ADDomainController(**{
                k: v for k, v in dc.items() if k in ADDomainController.__dataclass_fields__
            }))
        for p in data.get("principals", []) or []:
            graph.add_principal(ADPrincipal(**{
                k: v for k, v in p.items() if k in ADPrincipal.__dataclass_fields__
            }))
        for s in data.get("shares", []) or []:
            graph.add_share(ADShare(**{
                k: v for k, v in s.items() if k in ADShare.__dataclass_fields__
            }))
        return graph

    def to_evidence_nodes(self) -> List[Dict[str, Any]]:
        """Project AD entities into generic Evidence Graph nodes + edges."""
        nodes: List[Dict[str, Any]] = []
        for dom in self._domains.values():
            nodes.append({
                "type": "ad_domain", "id": dom.record_id, "label": dom.domain,
                "evidence_level": dom.evidence_level or ADEvidenceLevel.E0,
                "attributes": dom.to_dict(),
            })
        for dc in self._dcs.values():
            nodes.append({
                "type": "ad_domain_controller", "id": dc.record_id,
                "label": dc.address or dc.host,
                "evidence_level": dc.evidence_level or ADEvidenceLevel.E0,
                "attributes": dc.to_dict(),
            })
        for p in self._principals.values():
            nodes.append({
                "type": "ad_principal", "id": p.record_id, "label": p.canonical_key,
                "evidence_level": p.evidence_level or ADEvidenceLevel.E0,
                "attributes": p.to_dict(),
            })
        for s in self._shares.values():
            nodes.append({
                "type": "ad_share", "id": s.record_id, "label": s.canonical_key,
                "evidence_level": s.evidence_level or ADEvidenceLevel.E0,
                "attributes": s.to_dict(),
            })
        return nodes

    # ── Bridge from the network graph ─────────────────────────────────────────
    @classmethod
    def from_host_graph(cls, host_graph: HostGraph) -> "ADGraph":
        """Best-effort projection: hosts exposing DC marker services become DCs.

        This lets the same discovery pipeline feed AD planning without a second
        scan: any host with Kerberos/LDAP-family services is treated as a DC
        candidate (still E0 — it must be confirmed by authenticated enumeration).
        """
        graph = cls()
        kerberos_ports = {88, 464}
        ldap_ports = {389, 636, 3268, 3269}
        for host in host_graph.hosts:
            services = host.open_services
            svc_names = {(s.service_name or "").strip().lower() for s in services}
            ports = {s.port for s in services}
            markers = set(svc_names)
            if ports & kerberos_ports:
                markers.add("kerberos")
            if ports & ldap_ports:
                markers.add("ldap")
            if {"kerberos", "ldap"} & markers:
                graph.add_dc(ADDomainController(
                    host=host.host,
                    address=host.address,
                    services=sorted(m for m in markers if m),
                    os_family=host.os_guess,
                    source_tool="network_pipeline",
                ))
        return graph
