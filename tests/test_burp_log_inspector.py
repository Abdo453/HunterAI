"""
Tests for BurpLogInspectorSkill & Deep Burp Suite Log Analysis.
Hermetic offline tests verifying XML, JSON, HAR parsing, secret scanning,
parameter classification, BOLA/BFLA differential detection, and CLI integration.
"""
from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path

import pytest

from core.engine.omni_hunter_engine import AssessmentConfig, OmniHunterEngine
from core.workspace_manager import WorkspaceManager
from pentest import cmd_burp_logs
from skills.base_skill import SkillContext
from skills.burp.burp_log_inspector.skill import BurpLogInspectorSkill
from tools.tool_manager import ToolManager


# ── Fixtures & Sample Payloads ────────────────────────────────────────────────

SAMPLE_BURP_XML = """<?xml version="1.0"?>
<items burpVersion="2023.12.1" exportTime="Wed Nov 04 14:00:00 UTC 2026">
  <item>
    <time>Wed Nov 04 14:00:01 UTC 2026</time>
    <url>https://target-burp.com/api/v2/orders?order_id=ORD-9988</url>
    <host ip="104.21.55.2">target-burp.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <method>GET</method>
    <path>/api/v2/orders</path>
    <extension>null</extension>
    <request base64="true">R0VUIC9hcGkvdjIvb3JkZXJzP29yZGVyX2lkPU9SRC05OTg4IEhUVFAvMS4xDQpIb3N0OiB0YXJnZXQtYnVycC5jb20NCkF1dGhvcml6YXRpb246IEJlYXJlciBleUpoYkdjaU9pSnViMjVsSW4wLmV5SnpkV0lpT2lJeE1ERWlmUS4NCg0K</request>
    <status>200</status>
    <responselength>450</responselength>
    <mimetype>JSON</mimetype>
    <response base64="true">SFRUUC8xLjEgMjAwIE9LDQpDb250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL2pzb24NCkFjY2Vzcy1Db250cm9sLUFsbG93LU9yaWdpbjogKg0KQWNjZXNzLUNvbnRyb2wtQWxsb3ctQ3JlZGVudGlhbHM6IHRydWUNCg0KeyJvcmRlcl9pZCI6ICJPUkQtOTk4OCIsICJzdGF0dXMiOiAiQ09NUExFVEVEIiwgImN1c3RvbWVyX2lkIjogNDAyfQ==</response>
    <comment>Captured customer order interaction</comment>
  </item>
  <item>
    <time>Wed Nov 04 14:00:02 UTC 2026</time>
    <url>https://target-burp.com/api/v2/render?template=../../etc/passwd&amp;callback=https://internal-oast.net</url>
    <host ip="104.21.55.2">target-burp.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <method>GET</method>
    <path>/api/v2/render</path>
    <extension>null</extension>
    <request base64="true">R0VUIC9hcGkvdjIvcmVuZGVyP3RlbXBsYXRlPS4uLy4uL2V0Yy9wYXNzd2QmY2FsbGJhY2s9aHR0cHM6Ly9pbnRlcm5hbC1vYXN0Lm5ldCBIVFRQLzEuMQ0KSG9zdDogdGFyZ2V0LWJ1cnAuY29tDQoNCg==</request>
    <status>500</status>
    <responselength>820</responselength>
    <mimetype>HTML</mimetype>
    <response base64="true">SFRUUC8xLjEgNTAwIEludGVybmFsIFNlcnZlciBFcnJvcg0KQ29udGVudC1UeXBlOiB0ZXh0L2h0bWwNCg0KPGgxPldob29wcyEgVGhlcmUgd2FzIGFuIGVycm9yPC9oMT48cHJlPlBvc3RncmVTUUwgU1FMc3RhdGUgNDIwMDAgRVJST1I6IHN5bnRheCBlcnJvcg0KU1RSSVBFX0tFWT1za19saXZlXzEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNA0KPC9wcmU+</response>
    <comment>Error rendering template</comment>
  </item>
</items>
"""

SAMPLE_BURP_JSON = [
    {
        "url": "https://json-target.com/api/users?user_id=505",
        "method": "GET",
        "target_host": "json-target.com",
        "status_code": 200,
        "req_headers": {"Authorization": "Bearer session-alpha-12345"},
        "resp_headers": {"Content-Type": "application/json"},
        "resp_body": '{"user_id": 505, "email": "dev@internal.net", "secret": "AKIA1122334455667788"}',
    },
    {
        "url": "https://json-target.com/admin/delete",
        "method": "POST",
        "target_host": "json-target.com",
        "status_code": 200,
        "req_headers": {},
        "req_body": '{"role": "superuser", "confirm": true}',
        "resp_headers": {"Content-Type": "application/json"},
        "resp_body": '{"deleted": true, "cluster_ip": "10.0.4.15"}',
    },
]


# ── Unit Tests ────────────────────────────────────────────────────────────────

def test_burp_log_inspector_parses_xml(tmp_path):
    """Verify BurpLogInspectorSkill successfully ingests and parses Burp XML exports."""
    xml_file = tmp_path / "burp_export.xml"
    xml_file.write_text(SAMPLE_BURP_XML, encoding="utf-8")

    skill = BurpLogInspectorSkill()
    interactions = skill._parse_burp_xml(SAMPLE_BURP_XML)

    assert len(interactions) == 2
    it0 = interactions[0]
    assert it0.url == "https://target-burp.com/api/v2/orders?order_id=ORD-9988"
    assert it0.method == "GET"
    assert it0.query_params.get("order_id") == "ORD-9988"
    assert it0.status_code == 200
    assert "Authorization" in it0.req_headers
    assert "ORD-9988" in it0.resp_body

    it1 = interactions[1]
    assert it1.status_code == 500
    assert "template" in it1.query_params
    assert "sk_live_" in it1.resp_body
    assert "PostgreSQL" in it1.resp_body


def test_burp_log_inspector_secrets_and_db_errors(tmp_path):
    """Verify detection of Stripe keys, PostgreSQL errors, and stack traces."""
    skill = BurpLogInspectorSkill()
    interactions = skill._parse_burp_xml(SAMPLE_BURP_XML)

    findings = skill._inspect_secrets_and_leaks(interactions)
    assert len(findings) >= 2

    # Verify Stripe Live Secret Key detection
    stripe_finding = next((f for f in findings if "Stripe Live Secret Key" in f["title"]), None)
    assert stripe_finding is not None
    assert stripe_finding["severity"] == "Critical"
    assert "sk_live_" in stripe_finding["evidence"]

    # Verify Database Error detection
    db_finding = next((f for f in findings if "PostgreSQL Error Signature" in f["title"]), None)
    assert db_finding is not None
    assert db_finding["vuln_type"] == "sql_injection_indicator"


def test_burp_log_inspector_parameter_classification():
    """Verify parameters are classified into IDOR, Path Traversal, SSRF, and Mass Assignment."""
    skill = BurpLogInspectorSkill()
    interactions = skill._parse_burp_xml(SAMPLE_BURP_XML)

    param_findings, scored = skill._inspect_parameters(interactions)
    assert len(param_findings) >= 2

    # Verify IDOR candidate
    idor = next((f for f in param_findings if "order_id" in f["title"]), None)
    assert idor is not None
    assert idor["vuln_type"] == "idor"

    # Verify LFI/Path traversal candidate
    lfi = next((f for f in param_findings if "template" in f["title"]), None)
    assert lfi is not None
    assert lfi["vuln_type"] == "path_traversal"


def test_burp_log_inspector_json_and_auth_differentials(tmp_path):
    """Verify JSON ingestion, AWS key detection, and unauthenticated admin endpoint exposure."""
    skill = BurpLogInspectorSkill()
    interactions = skill._parse_burp_json(SAMPLE_BURP_JSON)
    assert len(interactions) == 2

    secret_findings = skill._inspect_secrets_and_leaks(interactions)
    aws_finding = next((f for f in secret_findings if "AWS Access Key" in f["title"]), None)
    assert aws_finding is not None
    assert aws_finding["severity"] == "High"

    ip_finding = next((f for f in secret_findings if "10.0.4.15" in f["title"]), None)
    assert ip_finding is not None

    auth_findings = skill._inspect_authorization_differentials(interactions)
    admin_finding = next((f for f in auth_findings if "Unauthenticated Administrative" in f["title"]), None)
    assert admin_finding is not None
    assert admin_finding["severity"] == "Critical"


@pytest.mark.asyncio
async def test_burp_log_inspector_full_skill_execution(tmp_path):
    """Verify end-to-end execute() generating JSON and Markdown artifacts."""
    xml_file = tmp_path / "burp_export.xml"
    xml_file.write_text(SAMPLE_BURP_XML, encoding="utf-8")

    ws = WorkspaceManager(str(tmp_path / "workspaces"))
    ctx = SkillContext(
        target="https://target-burp.com",
        session_id="BURP-TEST-SESS",
        workspace=ws,
        tool_manager=ToolManager(),
        extra={"log_file": str(xml_file), "min_risk_score": 5.0},
    )

    skill = BurpLogInspectorSkill()
    res = await skill.execute(ctx)

    assert res.success is True
    assert len(res.findings) >= 3
    assert "burp_log_findings.json" in res.output_files
    assert "burp_attack_surface.json" in res.output_files
    assert "burp_log_analysis_report.md" in res.output_files

    # Verify report content
    report_path = Path(res.output_files["burp_log_analysis_report.md"])
    assert report_path.exists()
    content = report_path.read_text(encoding="utf-8")
    assert "Burp Suite Deep Log & History Inspection Dossier" in content
    assert "target-burp.com" in content
    assert "Top Prioritized Testing Candidates" in content


def test_burp_logs_cli_command(tmp_path, capsys):
    """Verify 'pentest burp-logs' CLI command works cleanly."""
    xml_file = tmp_path / "burp_export.xml"
    xml_file.write_text(SAMPLE_BURP_XML, encoding="utf-8")

    args = argparse.Namespace(
        source=str(xml_file),
        target="https://target-burp.com",
        port=8085,
        min_risk=5.0,
        output_dir=str(tmp_path / "reports"),
    )

    exit_code = cmd_burp_logs(args)
    assert exit_code == 0

    captured = capsys.readouterr().out
    assert "PROFESSIONAL BURP SUITE LOG & TRAFFIC INSPECTOR" in captured
    assert "Discovered Endpoints:" in captured
    assert "IDENTIFIED SECURITY SIGNALS" in captured
    assert "Reports & Artifacts Written:" in captured


def test_omni_hunter_integrates_burp_file(tmp_path):
    """Verify OmniHunterEngine executes BurpLogInspector when burp_log_file is provided."""
    xml_file = tmp_path / "burp_export.xml"
    xml_file.write_text(SAMPLE_BURP_XML, encoding="utf-8")

    config = AssessmentConfig(
        target_url="https://target-burp.com",
        scope_domains=["target-burp.com"],
        burp_log_file=str(xml_file),
        coverage_threshold=0.01,
        max_cycles=3,
        force_tool_fallback=True,
        snapshot_dir=str(tmp_path / "snapshots"),
        engagement_id="ENG-BURP-INSP",
    )

    engine = OmniHunterEngine(config)
    result = engine.run()

    # Discovered endpoints from burp XML should be ingested into surface
    assert any("/api/v2/orders" in ep for ep in engine.surface["endpoints"])
    assert len(engine.confirmed_findings) > 0
