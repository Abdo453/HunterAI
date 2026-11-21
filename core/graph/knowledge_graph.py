"""
HunterAI Structural Knowledge Graph
===================================
The central structural brain connecting:
Asset -> Host -> Endpoint -> Parameter/Method -> Identity -> Resource -> Finding -> Evidence
Enables semantic reasoning and attack path prioritization rather than flat fuzzing.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


class SensitivityLevel(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED_PII = "RESTRICTED_PII"


@dataclass
class IdentityNode:
    role: str  # "anonymous", "standard_user_a", "standard_user_b", "admin"
    account_id: str
    tokens: Dict[str, str] = field(default_factory=dict)
    accessible_resources: Set[str] = field(default_factory=set)


@dataclass
class ResourceNode:
    resource_id: str
    resource_type: str  # "order", "medical_record", "document", "financial_profile"
    owner_identity: str
    sensitivity: SensitivityLevel = SensitivityLevel.CONFIDENTIAL
    endpoint_path: str = ""


@dataclass
class GraphEndpointNode:
    path: str
    method: str = "GET"
    parameters: List[str] = field(default_factory=list)
    requires_auth: bool = False
    linked_resources: List[str] = field(default_factory=list)
    associated_findings: List[str] = field(default_factory=list)
    empirically_verified: bool = True


@dataclass
class HostNode:
    hostname: str
    ip_address: str = ""
    os_family: str = ""
    empirically_verified: bool = True
    open_ports: List[int] = field(default_factory=list)
    discovered_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "os_family": self.os_family,
            "empirically_verified": self.empirically_verified,
            "open_ports": list(self.open_ports),
            "discovered_at": self.discovered_at,
        }


@dataclass
class PortServiceNode:
    host: str
    port: int
    protocol: str = "tcp"
    service_name: str = "http"
    version: str = ""
    banner: str = ""
    empirically_verified: bool = True

    @property
    def node_id(self) -> str:
        return f"{self.host}:{self.port}/{self.protocol}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "service_name": self.service_name,
            "version": self.version,
            "banner": self.banner,
            "empirically_verified": self.empirically_verified,
        }


@dataclass
class CVEFindingNode:
    finding_id: str
    host: str
    vuln_class: str
    cve_id: str = ""
    severity: str = "High"
    confidence: float = 0.90
    endpoint_or_port: str = ""
    empirically_verified: bool = True
    evidence_hash: str = ""
    prerequisites: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "host": self.host,
            "vuln_class": self.vuln_class,
            "cve_id": self.cve_id,
            "severity": self.severity,
            "confidence": self.confidence,
            "endpoint_or_port": self.endpoint_or_port,
            "empirically_verified": self.empirically_verified,
            "evidence_hash": self.evidence_hash,
            "prerequisites": list(self.prerequisites),
        }


@dataclass
class GraphEdge:
    source_id: str
    target_id: str
    relation: str
    empirically_verified: bool = True
    evidence_ref: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source_id,
            "target": self.target_id,
            "relation": self.relation,
            "empirically_verified": self.empirically_verified,
            "evidence_ref": self.evidence_ref,
        }


class KnowledgeGraph:
    """
    Empirical relational knowledge graph (Trinity-inspired) representing
    verified relationships between hosts, open ports, services, endpoints,
    identities, resources, and CVEs/findings to prevent LLM context collapse.
    """

    def __init__(self, root_asset: str, storage_dir: str = "data/memory"):
        self.root_asset = root_asset
        self.storage_dir = Path(storage_dir)
        self.identities: Dict[str, IdentityNode] = {}
        self.resources: Dict[str, ResourceNode] = {}
        self.endpoints: Dict[str, GraphEndpointNode] = {}
        self.finding_links: Dict[str, List[str]] = {}
        self.hosts: Dict[str, HostNode] = {}
        self.port_services: Dict[str, PortServiceNode] = {}
        self.cve_findings: Dict[str, CVEFindingNode] = {}
        self.edges: List[GraphEdge] = []

    def _safe_asset_name(self) -> str:
        clean = re.sub(r"[^a-zA-Z0-9._-]", "_", self.root_asset or "target")
        return clean.strip("_") or "target"

    def default_storage_path(self) -> Path:
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        return self.storage_dir / f"knowledge_graph_{self._safe_asset_name()}.json"

    def register_identity(self, role: str, account_id: str, tokens: Optional[Dict[str, str]] = None) -> IdentityNode:
        ident = IdentityNode(role=role, account_id=account_id, tokens=tokens or {})
        self.identities[role] = ident
        return ident

    def register_resource(self, res_id: str, res_type: str, owner_role: str, endpoint_path: str) -> ResourceNode:
        res = ResourceNode(resource_id=res_id, resource_type=res_type, owner_identity=owner_role, endpoint_path=endpoint_path)
        self.resources[res_id] = res
        if owner_role in self.identities:
            self.identities[owner_role].accessible_resources.add(res_id)
        return res

    def register_endpoint(
        self,
        path: str,
        method: str = "GET",
        params: Optional[List[str]] = None,
        empirically_verified: bool = True,
        host: Optional[str] = None,
    ) -> GraphEndpointNode:
        key = f"{method.upper()}:{path}"
        if key not in self.endpoints:
            self.endpoints[key] = GraphEndpointNode(
                path=path,
                method=method.upper(),
                parameters=list(params or []),
                empirically_verified=empirically_verified,
            )
        else:
            existing = self.endpoints[key]
            for p in (params or []):
                if p not in existing.parameters:
                    existing.parameters.append(p)
            if empirically_verified:
                existing.empirically_verified = True
        target_host = host or self.root_asset
        self.add_edge(f"host:{target_host}", f"endpoint:{key}", "EXPOSES_ENDPOINT", empirically_verified=empirically_verified)
        return self.endpoints[key]

    def register_host(
        self,
        hostname: str,
        ip_address: str = "",
        os_family: str = "",
        empirically_verified: bool = True,
    ) -> HostNode:
        if hostname not in self.hosts:
            self.hosts[hostname] = HostNode(
                hostname=hostname,
                ip_address=ip_address,
                os_family=os_family,
                empirically_verified=empirically_verified,
            )
        else:
            h = self.hosts[hostname]
            if ip_address:
                h.ip_address = ip_address
            if os_family:
                h.os_family = os_family
            if empirically_verified:
                h.empirically_verified = True
        if hostname != self.root_asset:
            self.add_edge(
                f"host:{self.root_asset}",
                f"host:{hostname}",
                "HAS_SUBDOMAIN_HOST",
                empirically_verified=empirically_verified,
            )
        return self.hosts[hostname]

    def register_port_service(
        self,
        host: str,
        port: int,
        protocol: str = "tcp",
        service_name: str = "http",
        version: str = "",
        banner: str = "",
        empirically_verified: bool = True,
    ) -> PortServiceNode:
        self.register_host(host, empirically_verified=empirically_verified)
        if port not in self.hosts[host].open_ports:
            self.hosts[host].open_ports.append(port)
        node = PortServiceNode(
            host=host,
            port=int(port),
            protocol=protocol,
            service_name=service_name,
            version=version,
            banner=banner,
            empirically_verified=empirically_verified,
        )
        self.port_services[node.node_id] = node
        self.add_edge(
            f"host:{host}",
            f"port:{node.node_id}",
            "HAS_OPEN_PORT",
            empirically_verified=empirically_verified,
        )
        return node

    def register_cve_finding(
        self,
        finding_id: str,
        host: str,
        vuln_class: str,
        cve_id: str = "",
        severity: str = "High",
        confidence: float = 0.90,
        endpoint_or_port: str = "",
        empirically_verified: bool = True,
        evidence_ref: str = "",
        prerequisites: Optional[List[str]] = None,
    ) -> CVEFindingNode:
        self.register_host(host, empirically_verified=empirically_verified)
        ev_hash = hashlib.sha256((evidence_ref or finding_id).encode("utf-8")).hexdigest()[:16]
        node = CVEFindingNode(
            finding_id=finding_id,
            host=host,
            vuln_class=vuln_class,
            cve_id=cve_id,
            severity=severity,
            confidence=confidence,
            endpoint_or_port=endpoint_or_port,
            empirically_verified=empirically_verified,
            evidence_hash=ev_hash,
            prerequisites=list(prerequisites or []),
        )
        self.cve_findings[finding_id] = node
        source_ref = f"endpoint:{endpoint_or_port}" if endpoint_or_port else f"host:{host}"
        self.add_edge(
            source_ref,
            f"finding:{finding_id}",
            "CONFIRMED_FINDING" if empirically_verified else "CANDIDATE_HYPOTHESIS",
            empirically_verified=empirically_verified,
            evidence_ref=ev_hash,
        )
        return node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relation: str,
        empirically_verified: bool = True,
        evidence_ref: str = "",
    ) -> GraphEdge:
        for e in self.edges:
            if e.source_id == source_id and e.target_id == target_id and e.relation == relation:
                if empirically_verified:
                    e.empirically_verified = True
                if evidence_ref:
                    e.evidence_ref = evidence_ref
                return e
        edge = GraphEdge(
            source_id=source_id,
            target_id=target_id,
            relation=relation,
            empirically_verified=empirically_verified,
            evidence_ref=evidence_ref,
        )
        self.edges.append(edge)
        return edge

    def link_finding_evidence(self, finding_id: str, evidence_id: str, endpoint_key: str):
        if finding_id not in self.finding_links:
            self.finding_links[finding_id] = []
        self.finding_links[finding_id].append(evidence_id)
        if endpoint_key in self.endpoints:
            self.endpoints[endpoint_key].associated_findings.append(finding_id)

    def export_verified_facts_context(self, max_facts: int = 50) -> Dict[str, Any]:
        """
        Exports strictly empirically verified graph facts (Trinity pattern)
        to replace bloated raw text history and prevent LLM context collapse.
        """
        verified_hosts = [h.to_dict() for h in self.hosts.values() if h.empirically_verified]
        verified_ports = [p.to_dict() for p in self.port_services.values() if p.empirically_verified]
        verified_endpoints = [
            {
                "key": k,
                "path": ep.path,
                "method": ep.method,
                "parameters": ep.parameters,
                "associated_findings": ep.associated_findings,
            }
            for k, ep in self.endpoints.items()
            if ep.empirically_verified
        ]
        verified_findings = [f.to_dict() for f in self.cve_findings.values() if f.empirically_verified]
        verified_edges = [e.to_dict() for e in self.edges if e.empirically_verified][:max_facts]

        fact_lines: List[str] = []
        for h in verified_hosts[:15]:
            ports_str = ",".join(str(p) for p in h["open_ports"]) or "none"
            fact_lines.append(f"[FACT:HOST] {h['hostname']} (ports={ports_str})")
        for p in verified_ports[:15]:
            ver = f"/{p['version']}" if p["version"] else ""
            fact_lines.append(f"[FACT:PORT] {p['host']}:{p['port']} -> {p['service_name']}{ver}")
        for ep in verified_endpoints[:15]:
            params_str = ",".join(ep["parameters"][:6]) or "none"
            fact_lines.append(f"[FACT:ENDPOINT] {ep['method']} {ep['path']} (params={params_str})")
        for f in verified_findings[:15]:
            cve_tag = f" ({f['cve_id']})" if f["cve_id"] else ""
            fact_lines.append(
                f"[FACT:FINDING] {f['finding_id']}: {f['vuln_class']}{cve_tag} on {f['host']} "
                f"[severity={f['severity']}, confidence={f['confidence']:.2f}, evidence={f['evidence_hash']}]"
            )

        return {
            "root_asset": self.root_asset,
            "verified_hosts_count": len(verified_hosts),
            "verified_ports_count": len(verified_ports),
            "verified_endpoints_count": len(verified_endpoints),
            "verified_findings_count": len(verified_findings),
            "verified_edges_count": len(verified_edges),
            "verified_hosts": verified_hosts[:max_facts],
            "verified_ports": verified_ports[:max_facts],
            "verified_endpoints": verified_endpoints[:max_facts],
            "verified_findings": verified_findings[:max_facts],
            "verified_edges": verified_edges,
            "facts_prompt": "\n".join(fact_lines[:max_facts]) if fact_lines else f"[FACT:ROOT] {self.root_asset}",
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "root_asset": self.root_asset,
            "hosts": {k: v.to_dict() for k, v in self.hosts.items()},
            "port_services": {k: v.to_dict() for k, v in self.port_services.items()},
            "endpoints": {
                k: {
                    "path": ep.path,
                    "method": ep.method,
                    "parameters": ep.parameters,
                    "requires_auth": ep.requires_auth,
                    "linked_resources": ep.linked_resources,
                    "associated_findings": ep.associated_findings,
                    "empirically_verified": ep.empirically_verified,
                }
                for k, ep in self.endpoints.items()
            },
            "cve_findings": {k: v.to_dict() for k, v in self.cve_findings.items()},
            "edges": [e.to_dict() for e in self.edges],
            "finding_links": self.finding_links,
        }

    def save(self, filepath: Optional[str] = None) -> str:
        target_path = Path(filepath) if filepath else self.default_storage_path()
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return str(target_path)

    def load(self, filepath: Optional[str] = None) -> bool:
        target_path = Path(filepath) if filepath else self.default_storage_path()
        if not target_path.exists():
            return False
        try:
            data = json.loads(target_path.read_text(encoding="utf-8"))
            self.root_asset = data.get("root_asset", self.root_asset)
            for k, h in data.get("hosts", {}).items():
                self.hosts[k] = HostNode(
                    hostname=h["hostname"],
                    ip_address=h.get("ip_address", ""),
                    os_family=h.get("os_family", ""),
                    empirically_verified=h.get("empirically_verified", True),
                    open_ports=list(h.get("open_ports", [])),
                    discovered_at=h.get("discovered_at", time.time()),
                )
            for k, p in data.get("port_services", {}).items():
                self.port_services[k] = PortServiceNode(
                    host=p["host"],
                    port=int(p["port"]),
                    protocol=p.get("protocol", "tcp"),
                    service_name=p.get("service_name", "http"),
                    version=p.get("version", ""),
                    banner=p.get("banner", ""),
                    empirically_verified=p.get("empirically_verified", True),
                )
            for k, ep in data.get("endpoints", {}).items():
                self.endpoints[k] = GraphEndpointNode(
                    path=ep["path"],
                    method=ep.get("method", "GET"),
                    parameters=list(ep.get("parameters", [])),
                    requires_auth=ep.get("requires_auth", False),
                    linked_resources=list(ep.get("linked_resources", [])),
                    associated_findings=list(ep.get("associated_findings", [])),
                    empirically_verified=ep.get("empirically_verified", True),
                )
            for k, f in data.get("cve_findings", {}).items():
                self.cve_findings[k] = CVEFindingNode(
                    finding_id=f["finding_id"],
                    host=f["host"],
                    vuln_class=f["vuln_class"],
                    cve_id=f.get("cve_id", ""),
                    severity=f.get("severity", "High"),
                    confidence=float(f.get("confidence", 0.9)),
                    endpoint_or_port=f.get("endpoint_or_port", ""),
                    empirically_verified=f.get("empirically_verified", True),
                    evidence_hash=f.get("evidence_hash", ""),
                    prerequisites=list(f.get("prerequisites", [])),
                )
            self.edges = [
                GraphEdge(
                    source_id=e["source"],
                    target_id=e["target"],
                    relation=e["relation"],
                    empirically_verified=e.get("empirically_verified", True),
                    evidence_ref=e.get("evidence_ref", ""),
                )
                for e in data.get("edges", [])
            ]
            self.finding_links = dict(data.get("finding_links", {}))
            return True
        except Exception:
            return False
