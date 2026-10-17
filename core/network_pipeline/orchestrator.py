"""Network Pipeline v1 — host-centric orchestration.

    discover ──► fingerprint ──► graph ──► route ──► (Evidence Court handoff)

Every stage is scope-gated through :class:`NetworkScopeGuard`. Endpoints the
guard denies are recorded in the Negative Space ledger with a causal reason —
never silently dropped, and never inferred as "secure".

The pipeline is intentionally tool-agnostic: discovery and fingerprinting are
injected as async callables so it can be unit-tested without any Kali binary,
and wired to real tools (masscan → nmap) via the provided factories.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Sequence

from core.network_model import HostGraph, NetworkFinding, ServiceRecord, ServiceState
from core.network_scope_guard import NetworkScopeGuard
from core.network_vuln_router import NetworkVulnRouter

log = logging.getLogger("network_pipeline")

DiscoverFn = Callable[..., Awaitable[List[ServiceRecord]]]
FingerprintFn = Callable[..., Awaitable[List[ServiceRecord]]]


@dataclass
class NetworkAssessment:
    """The complete, evidence-ready output of one network pipeline run."""

    target: str
    graph: HostGraph
    findings: List[NetworkFinding] = field(default_factory=list)
    stages: List[Dict[str, Any]] = field(default_factory=list)
    negative_space: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def stats(self) -> Dict[str, Any]:
        summary = self.graph.summary()
        return {
            "hosts": summary["hosts"],
            "open_services": summary["open_services"],
            "high_value_services": summary["high_value_services"],
            "candidate_findings": len(self.findings),
            "ad_candidate_findings": sum(
                1 for f in self.findings if f.service_name == "active-directory"
            ),
            "negative_space": len(self.negative_space),
            "confirmed_findings": sum(1 for f in self.findings if f.status == "confirmed"),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "graph": self.graph.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "stages": list(self.stages),
            "negative_space": list(self.negative_space),
            "stats": self.stats,
        }


class NetworkPipeline:
    """Deterministic host-centric network assessment pipeline."""

    def __init__(
        self,
        discover: Optional[DiscoverFn] = None,
        fingerprint: Optional[FingerprintFn] = None,
        router: Optional[NetworkVulnRouter] = None,
        scope_guard: Optional[NetworkScopeGuard] = None,
        graph: Optional[HostGraph] = None,
        enable_ad_planning: bool = True,
    ):
        self.discover = discover
        self.fingerprint = fingerprint
        self.router = router or NetworkVulnRouter()
        # Secure default: a bare guard is fail-closed.
        self.scope_guard = scope_guard if scope_guard is not None else NetworkScopeGuard()
        self.graph = graph or HostGraph()
        self.enable_ad_planning = enable_ad_planning
        self._negative_space: List[Dict[str, Any]] = []

    # ── public entry point ───────────────────────────────────────────────────
    async def run(
        self,
        targets: Sequence[str],
        ports: str = "1-65535",
        protocol: str = "tcp",
        rate: int = 1000,
    ) -> NetworkAssessment:
        targets = [t for t in (targets or []) if t and t.strip()]
        assessment = NetworkAssessment(
            target=",".join(targets),
            graph=self.graph,
        )
        self._negative_space = []

        discovered = await self._run_discovery(targets, ports, protocol, rate, assessment)
        allowed = self._gate_discovered(discovered, protocol)
        fingerprinted = await self._run_fingerprint(allowed, protocol, assessment)
        self._build_graph(fingerprinted, assessment)
        self._route(assessment)
        self._plan_ad(assessment)

        assessment.negative_space = list(self._negative_space)
        return assessment

    # ── stages ───────────────────────────────────────────────────────────────
    async def _run_discovery(
        self,
        targets: Sequence[str],
        ports: str,
        protocol: str,
        rate: int,
        assessment: NetworkAssessment,
    ) -> List[ServiceRecord]:
        stage = {"stage": "discovery", "tool": "masscan", "status": "ok",
                 "count": 0, "duration_sec": 0.0, "error": None}
        t0 = time.time()
        discovered: List[ServiceRecord] = []

        if self.discover is None:
            stage["status"] = "skipped"
            stage["duration_sec"] = round(time.time() - t0, 3)
            assessment.stages.append(stage)
            return discovered

        for target in targets:
            allowed, reason = self.scope_guard.check_host(target, protocol)
            if not allowed:
                self._negative_space.append({
                    "host": target, "port": None, "stage": "discovery",
                    "reason": "SKIPPED_SCOPE", "detail": reason,
                })
                continue
            try:
                services = await self.discover(target, ports=ports, rate=rate, protocol=protocol)
                discovered.extend(services or [])
            except Exception as e:  # a single target failing must not abort the run
                log.warning("discovery failed for %s: %s", target, e)
                stage["error"] = str(e)

        stage["count"] = len(discovered)
        stage["duration_sec"] = round(time.time() - t0, 3)
        assessment.stages.append(stage)
        return discovered

    def _gate_discovered(
        self, discovered: List[ServiceRecord], protocol: str
    ) -> List[ServiceRecord]:
        """Scope-gate every discovered endpoint; deny → Negative Space."""
        allowed: List[ServiceRecord] = []
        for svc in discovered:
            if svc.state != ServiceState.OPEN:
                continue
            ok, reason = self.scope_guard.check_endpoint(
                svc.host, svc.port, protocol=svc.protocol or protocol
            )
            if not ok:
                self._negative_space.append({
                    "host": svc.host, "port": svc.port, "stage": "discovery",
                    "reason": "SKIPPED_SCOPE", "detail": reason,
                })
                continue
            allowed.append(svc)
        return allowed

    async def _run_fingerprint(
        self,
        services: List[ServiceRecord],
        protocol: str,
        assessment: NetworkAssessment,
    ) -> List[ServiceRecord]:
        stage = {"stage": "fingerprint", "tool": "nmap", "status": "ok",
                 "count": 0, "duration_sec": 0.0, "error": None}
        t0 = time.time()

        if self.fingerprint is None or not services:
            stage["status"] = "skipped"
            stage["duration_sec"] = round(time.time() - t0, 3)
            assessment.stages.append(stage)
            return services

        by_host: Dict[str, List[int]] = {}
        for svc in services:
            by_host.setdefault(svc.host, []).append(svc.port)

        enriched: List[ServiceRecord] = []
        for host, ports in by_host.items():
            try:
                results = await self.fingerprint(host, sorted(set(ports)))
                enriched.extend(results or [])
            except Exception as e:
                log.warning("fingerprint failed for %s: %s", host, e)
                stage["error"] = str(e)
                # Fall back to the discovery records for this host.
                enriched.extend([s for s in services if s.host == host])

        stage["count"] = len(enriched)
        stage["duration_sec"] = round(time.time() - t0, 3)
        assessment.stages.append(stage)
        return enriched

    def _build_graph(
        self, services: List[ServiceRecord], assessment: NetworkAssessment
    ) -> None:
        stage = {"stage": "graph", "tool": "host_graph", "status": "ok",
                 "count": 0, "duration_sec": 0.0, "error": None}
        t0 = time.time()
        for svc in services:
            self.graph.add_service(svc)
        stage["count"] = len(self.graph.all_services())
        stage["duration_sec"] = round(time.time() - t0, 3)
        assessment.stages.append(stage)

    def _route(self, assessment: NetworkAssessment) -> None:
        stage = {"stage": "routing", "tool": "network_vuln_router", "status": "ok",
                 "count": 0, "duration_sec": 0.0, "error": None}
        t0 = time.time()
        assessment.findings = self.router.route_graph(self.graph)
        stage["count"] = len(assessment.findings)
        stage["duration_sec"] = round(time.time() - t0, 3)
        assessment.stages.append(stage)

    def _plan_ad(self, assessment: NetworkAssessment) -> None:
        """Optional AD stage: plan enumeration when the surface exposes a DC.

        Only runs when the discovered services actually reveal a Domain
        Controller (Kerberos/LDAP markers), so purely-web/host scans are
        unaffected.
        """
        stage = {"stage": "ad_planning", "tool": "ad_enum_planner", "status": "ok",
                 "count": 0, "duration_sec": 0.0, "error": None}
        t0 = time.time()

        if not self.enable_ad_planning:
            stage["status"] = "skipped"
            stage["duration_sec"] = round(time.time() - t0, 3)
            assessment.stages.append(stage)
            return

        from core.ad_model import ADEnumPlanner, ADGraph

        ad_graph = ADGraph.from_host_graph(self.graph)
        if not ad_graph.domain_controllers():
            stage["status"] = "skipped"
            stage["duration_sec"] = round(time.time() - t0, 3)
            assessment.stages.append(stage)
            return

        ad_findings = ADEnumPlanner().plan(ad_graph)
        assessment.findings.extend(ad_findings)
        stage["count"] = len(ad_findings)
        stage["duration_sec"] = round(time.time() - t0, 3)
        assessment.stages.append(stage)


# ── Factories that wire real Kali tools into the pipeline ────────────────────
def masscan_discovery(masscan_tools: Any) -> DiscoverFn:
    """Build a discovery callable from a :class:`tools.masscan_tools.MasscanTools`."""
    from core.masscan.analyzer import MasscanNormalizer

    async def _discover(target: str, ports: str = "1-65535", rate: int = 1000,
                        protocol: str = "tcp") -> List[ServiceRecord]:
        res = await masscan_tools.scan(target=target, ports=ports, rate=rate)
        records = MasscanNormalizer.normalize_batch(res.stdout)
        return [
            ServiceRecord(
                host=r.host, port=r.port, protocol=r.protocol, state=r.state,
                banner=r.banner, evidence_level=r.evidence_level, source_tool="masscan",
            )
            for r in records if r.state == ServiceState.OPEN
        ]

    return _discover


def nmap_fingerprint(nmap_tools: Any) -> FingerprintFn:
    """Build a fingerprint callable from a :class:`tools.nmap_tools.NmapTools`."""
    from core.nmap.analyzer import NmapNormalizer

    async def _fingerprint(host: str, ports: List[int]) -> List[ServiceRecord]:
        port_arg = ",".join(str(p) for p in ports) if ports else None
        res = await nmap_tools.scan(target=host, ports=port_arg)
        records = NmapNormalizer().normalize_batch(res.stdout)
        return [ServiceRecord.from_nmap_record(r) for r in records]

    return _fingerprint
