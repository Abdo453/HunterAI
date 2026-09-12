import os
import json
import pytest
from pathlib import Path
from core.exporters import export_interactive_dashboard, export_csv, export_html, export_json
from core.session_manager import SessionManager, Finding, PentestSession


def test_interactive_dashboard_export(tmp_path):
    report_file = tmp_path / "dashboard.html"
    scan_result = {
        "duration": 42.5,
        "mode": "full",
        "objective_result": {"status": "COMPLETE"},
        "findings": [
            {
                "severity": "Critical",
                "lifecycle_verdict": "CONFIRMED",
                "title": "SQL Injection in User Search",
                "param_name": "query",
                "tool": "SQLiSkill",
                "payload_used": "' UNION SELECT @@version, 2--",
                "evidence": "Extracted DBMS: PostgreSQL 15.2",
                "remediation": "Use parameterized queries."
            },
            {
                "severity": "High",
                "lifecycle_verdict": "UNVERIFIED_SIGNAL",
                "title": "Potential DOM XSS in modal",
                "param_name": "modal",
                "tool": "XSSSkill",
                "evidence": "Reflection detected in client-side script"
            }
        ],
        "code_intelligence": {
            "manifest": {
                "technologies": ["Next.js", "React", "Cloudflare"],
                "js_analyzed": 5,
                "endpoints_discovered": 12,
                "secrets_discovered": 1
            },
            "endpoints": [
                {
                    "url_or_path": "/api/v1/user/profile",
                    "method": "GET",
                    "parameters": ["id", "token"],
                    "auth_required": True,
                    "discovered_in": "app.bundle.js"
                },
                {
                    "url_or_path": "/api/v1/auth/login",
                    "method": "POST",
                    "parameters": ["username", "password"],
                    "auth_required": False,
                    "discovered_in": "login.bundle.js"
                }
            ],
            "secrets": [
                {
                    "secret_type": "AWS_ACCESS_KEY",
                    "status": "VALIDATED",
                    "entropy": 4.12,
                    "location": "main-chunk.js:142",
                    "candidate_value": "AKIAJ2X7XYZ9EXAMPLE"
                }
            ]
        }
    }

    export_interactive_dashboard("https://target.local", scan_result, str(report_file))

    assert report_file.exists()
    content = report_file.read_text(encoding="utf-8")
    assert "HunterAI Security Dashboard" in content
    assert "https://target.local" in content
    assert "SQL Injection in User Search" in content
    assert "CONFIRMED" in content
    assert "/api/v1/user/profile" in content
    assert "Next.js" in content
    assert "FIREWALLED" in content


def test_session_manager(tmp_path):
    mgr = SessionManager(sessions_dir=str(tmp_path))
    session = mgr.create_session("https://bancoplata.mx", mode="full")
    assert session.id is not None
    assert session.status == "running"

    # Add finding
    f = Finding(
        id="find-01",
        title="IDOR in Account Lookup",
        description="Cross-tenant access allowed",
        severity="High",
        cvss_score=8.5,
        tool="IDORSkill",
        evidence="Account 1002 accessed by user 1001",
        recommendation="Verify tenant ownership"
    )
    mgr.add_finding(session, f)
    mgr.add_tool_result(session, agent="VulnerabilityEngine", tool="IDORSkill", output="Success", duration=2.1)
    mgr.complete(session)

    # Reload
    loaded = mgr.load(session.id)
    assert loaded is not None
    assert loaded.status == "completed"
    assert len(loaded.findings) == 1
    assert loaded.findings[0].title == "IDOR in Account Lookup"
    assert len(loaded.tools_run) == 1

    # List all
    all_sessions = mgr.list_all()
    assert len(all_sessions) == 1
    assert all_sessions[0]["id"] == session.id