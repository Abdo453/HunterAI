"""NetworkVulnRouter — turns observed services into *candidate* exposures.

Rule-based and deterministic: given a :class:`ServiceRecord` (or a whole
:class:`HostGraph`) it yields :class:`NetworkFinding` objects with
``status="candidate"``. It never confirms anything — confirmation is the
Evidence Court's exclusive authority.
"""
from __future__ import annotations

import logging
from typing import Iterable, List, Optional

from core.network_model import HostGraph, NetworkFinding, ServiceRecord, ServiceState
from core.network_vuln_router.rules import (
    NETWORK_RULES, PROBE_BY_SERVICE, VulnRule,
)

log = logging.getLogger("network_vuln_router")

# Web services are handled by the web pipeline, not the network router.
WEB_SERVICES = {
    "http", "https", "http-alt", "https-alt", "http-proxy", "ssl/http", "ssl/https",
}

# Highest severity first so the most impactful candidate surfaces on top.
_SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


class NetworkVulnRouter:
    """Deterministic service→exposure routing (v1)."""

    def __init__(self, rules: Optional[List[VulnRule]] = None, skip_web: bool = True):
        self.rules = NETWORK_RULES if rules is None else rules
        self.skip_web = skip_web

    def route_service(self, service: ServiceRecord) -> List[NetworkFinding]:
        if service.state != ServiceState.OPEN:
            return []
        name = (service.service_name or "").strip().lower()
        if self.skip_web and name in WEB_SERVICES:
            return []

        findings: List[NetworkFinding] = []
        for rule in self.rules:
            if not rule.matches_port(service.port, service.protocol, name):
                continue
            if not rule.matches_version(
                service.service_product, service.service_version, service.banner
            ):
                continue
            findings.append(self._to_finding(rule, service))
        findings.sort(key=lambda f: _SEVERITY_RANK.get(f.severity, 0), reverse=True)
        return findings

    def route_graph(self, graph: HostGraph) -> List[NetworkFinding]:
        findings: List[NetworkFinding] = []
        seen: set = set()
        for service in graph.all_services():
            for finding in self.route_service(service):
                key = (finding.host, finding.port, finding.vuln_class, finding.title)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(finding)
        findings.sort(key=lambda f: _SEVERITY_RANK.get(f.severity, 0), reverse=True)
        return findings

    # ── internals ────────────────────────────────────────────────────────────
    def _to_finding(self, rule: VulnRule, service: ServiceRecord) -> NetworkFinding:
        name = (service.service_name or "").strip().lower()
        reproduction = self._format_repro(rule.reproduction, service, name, rule.rule_id)

        # Candidate confidence (capped well below any confirmation threshold).
        confidence = 0.35
        if service.service_name:
            confidence += 0.15
        if service.service_version:
            confidence += 0.10
        if service.banner:
            confidence += 0.10
        if rule.version_pattern is not None:
            confidence += 0.05  # heuristic version match
        confidence = round(min(confidence, 0.70), 2)

        return NetworkFinding(
            title=rule.title,
            host=service.host,
            port=service.port,
            protocol=service.protocol,
            service_name=service.service_name,
            vuln_class=rule.vuln_class,
            severity=rule.severity,
            confidence=confidence,
            evidence_level="E0",
            status="candidate",
            description=rule.description,
            reproduction_command=reproduction,
            remediation=rule.remediation,
            cwe=rule.cwe,
            references=list(rule.references),
            evidence_ids=[service.record_id],
        )

    @staticmethod
    def _format_repro(template: str, service: ServiceRecord, name: str, rule_id: str) -> str:
        probe = PROBE_BY_SERVICE.get(name, "banner")
        try:
            return template.format(host=service.host, port=service.port, probe=probe)
        except (KeyError, IndexError):
            # Unknown placeholder in a custom rule: return the raw template.
            log.warning("Rule %s reproduction template could not be formatted", rule_id)
            return template
