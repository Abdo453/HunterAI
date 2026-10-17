"""HostGraph — the network attack-surface graph (host ⇄ service ⇄ protocol).

A small, dependency-free store that the network pipeline and Evidence Court
read from. It can be projected into the platform Evidence Graph via
:meth:`HostGraph.to_evidence_nodes` so network entities become first-class
citizens alongside the existing URL/endpoint nodes.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from core.network_model.schemas import (
    HostRecord,
    NetworkEvidenceLevel,
    ServiceRecord,
    ServiceState,
)


class HostGraph:
    """In-memory network graph of hosts and their services."""

    def __init__(self) -> None:
        self._hosts: Dict[str, HostRecord] = {}
        # Endpoints explicitly skipped, with the causal reason (Negative Space).
        self.negative_space: List[Dict[str, Any]] = []

    # ── Host operations ──────────────────────────────────────────────────────
    def add_host(self, host: HostRecord) -> HostRecord:
        key = host.canonical_key
        if not key:
            return host
        existing = self._hosts.get(key)
        if existing is None:
            self._hosts[key] = host
            return host
        # Merge: keep the richest metadata, union hostnames/services.
        if not existing.address and host.address:
            existing.address = host.address
        if host.os_guess and not existing.os_guess:
            existing.os_guess = host.os_guess
        for name in host.hostnames:
            if name not in existing.hostnames:
                existing.hostnames.append(name)
        existing.tags = sorted(set(existing.tags) | set(host.tags))
        for svc in host.services:
            existing.add_service(svc)
        return existing

    def upsert_host(
        self,
        host: str,
        address: Optional[str] = None,
        hostnames: Optional[Iterable[str]] = None,
        os_guess: Optional[str] = None,
        source_tool: str = "",
    ) -> HostRecord:
        return self.add_host(
            HostRecord(
                host=host,
                address=address,
                hostnames=list(hostnames or []),
                os_guess=os_guess,
                source_tool=source_tool,
            )
        )

    def get_host(self, host: str) -> Optional[HostRecord]:
        key = (host or "").strip().lower()
        if key in self._hosts:
            return self._hosts[key]
        for record in self._hosts.values():
            if record.host.strip().lower() == key:
                return record
            if record.address and record.address.strip().lower() == key:
                return record
            if key in [h.lower() for h in record.hostnames]:
                return record
        return None

    # ── Service operations ───────────────────────────────────────────────────
    def add_service(self, service: ServiceRecord) -> ServiceRecord:
        host = self.get_host(service.host)
        if host is None:
            host = self.upsert_host(service.host, source_tool=service.source_tool)
        return host.add_service(service)

    def add_services(self, services: Iterable[ServiceRecord]) -> int:
        count = 0
        for svc in services:
            self.add_service(svc)
            count += 1
        return count

    def record_negative_space(self, host: str, port: Optional[int], reason: str) -> None:
        """Track an endpoint that was deliberately NOT tested and why."""
        self.negative_space.append(
            {"host": host, "port": port, "reason": reason}
        )

    # ── Queries ──────────────────────────────────────────────────────────────
    @property
    def hosts(self) -> List[HostRecord]:
        return list(self._hosts.values())

    def all_services(self) -> List[ServiceRecord]:
        out: List[ServiceRecord] = []
        for host in self._hosts.values():
            out.extend(host.services)
        return out

    def open_services(self) -> List[ServiceRecord]:
        return [s for s in self.all_services() if s.state == ServiceState.OPEN]

    def hosts_with_service(self, service_name: str) -> List[HostRecord]:
        wanted = (service_name or "").strip().lower()
        return [
            h for h in self._hosts.values()
            if any((s.service_name or "").strip().lower() == wanted for s in h.open_services)
        ]

    def high_value_services(self) -> List[ServiceRecord]:
        return [s for s in self.open_services() if s.is_high_value]

    def summary(self) -> Dict[str, Any]:
        services = self.all_services()
        open_services = [s for s in services if s.state == ServiceState.OPEN]
        service_names = sorted({(s.service_name or "unknown") for s in open_services})
        return {
            "hosts": len(self._hosts),
            "services": len(services),
            "open_services": len(open_services),
            "high_value_services": len(self.high_value_services()),
            "service_names": service_names,
            "negative_space": len(self.negative_space),
        }

    # ── Serialization / Evidence Graph projection ────────────────────────────
    def to_dict(self) -> Dict[str, Any]:
        return {
            "hosts": [h.to_dict() for h in self._hosts.values()],
            "negative_space": list(self.negative_space),
            "summary": self.summary(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HostGraph":
        graph = cls()
        for host_data in data.get("hosts", []) or []:
            services = [
                ServiceRecord(**{k: v for k, v in svc.items() if k in ServiceRecord.__dataclass_fields__})
                for svc in (host_data.get("services") or [])
            ]
            host_fields = {
                k: v for k, v in host_data.items()
                if k in HostRecord.__dataclass_fields__ and k != "services"
            }
            host = HostRecord(services=services, **host_fields)
            graph.add_host(host)
        graph.negative_space = list(data.get("negative_space", []) or [])
        return graph

    def to_evidence_nodes(self) -> List[Dict[str, Any]]:
        """Project hosts/services into generic Evidence Graph nodes + edges."""
        nodes: List[Dict[str, Any]] = []
        for host in self._hosts.values():
            nodes.append({
                "type": "host",
                "id": host.record_id,
                "label": host.address or host.host,
                "evidence_level": host.evidence_level or NetworkEvidenceLevel.E0,
                "attributes": {
                    "host": host.host,
                    "address": host.address,
                    "os_guess": host.os_guess,
                    "state": host.state,
                },
            })
            for svc in host.services:
                nodes.append({
                    "type": "service",
                    "id": svc.record_id,
                    "label": svc.canonical_key,
                    "evidence_level": svc.evidence_level or NetworkEvidenceLevel.E0,
                    "attributes": svc.to_dict(),
                })
                nodes.append({
                    "type": "edge",
                    "from": host.record_id,
                    "to": svc.record_id,
                    "relation": "exposes",
                })
        return nodes
