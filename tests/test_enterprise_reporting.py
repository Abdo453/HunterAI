"""
Enterprise Reporting, Mutator & Attack Graph Test Suite
======================================================
"""

import pytest
from core.reporting.enterprise_html_report import EnterpriseReportGenerator
from core.waf.adaptive_mutator import AdaptivePayloadMutator
from core.orchestration.mission_sync import MissionTopologySynchronizer


class TestEnterpriseReportGenerator:
    def test_generate_html_with_findings(self):
        findings = [
            {
                "title": "SQL Injection in category parameter",
                "type": "sqli",
                "param_name": "category",
                "severity": "Critical",
                "confidence": 0.98,
                "cwe": "CWE-89",
                "owasp_top10": "A03:2021 — Injection",
                "payload_used": "'+UNION+SELECT+BANNER,+NULL+FROM+v$version--",
                "evidence": "Oracle Database 19c Enterprise Edition Release",
                "remediation": "Use Prepared Statements with Parameterized Queries.",
                "evidence_sources": ["SQLiSkill/StateMachine"]
            }
        ]
        html_out = EnterpriseReportGenerator.generate_html(
            target_url="https://target.com/filter?category=gifts",
            findings=findings,
            mission_id="TEST-001"
        )
        assert "<!DOCTYPE html>" in html_out
        assert "SQL Injection in category parameter" in html_out
        assert "Oracle Database 19c" in html_out
        assert "CWE-89" in html_out
        assert "Critical" in html_out


class TestAdaptivePayloadMutator:
    def test_mutate_sqli_generates_variants(self):
        payload = "' UNION SELECT NULL,NULL--"
        variants = AdaptivePayloadMutator.mutate_sqli(payload)
        assert len(variants) >= 4
        assert any("/**/" in v for v in variants)  # Whitespace substitution

    def test_mutate_xss_generates_variants(self):
        payload = "<script>alert(1)</script>"
        variants = AdaptivePayloadMutator.mutate_xss(payload)
        assert len(variants) >= 2


class TestMissionTopologySynchronizer:
    def test_add_nodes_and_export_cytoscape(self):
        sync = MissionTopologySynchronizer("https://example.com")
        ep_id = sync.add_endpoint("https://example.com/api/products", "GET")
        p_id = sync.add_parameter(ep_id, "search", "query")
        v_id = sync.add_vulnerability(p_id, "Reflected XSS", "High")

        cyto = sync.to_cytoscape_json()
        assert cyto["node_count"] == 4  # target + ep + param + vuln
        assert cyto["edge_count"] == 3
        assert len(cyto["elements"]) == 7
