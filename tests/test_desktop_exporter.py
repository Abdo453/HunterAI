"""
Hermetic Test Suite for Target Desktop Exporter
===============================================
Validates:
1. Cross-platform Desktop directory resolution (Kali Linux /home/kali/Desktop, Windows, and custom overrides)
2. Target name sanitization from URLs, ports, and queries
3. Complete target workspace creation (reports/, scripts/, recon/, findings/)
4. Automated report and executable script exports
5. Reconnaissance surface dumps (subdomains, live hosts, open ports, endpoints)
6. Full assessment synchronization and SUMMARY.md master index generation
"""
from dataclasses import dataclass
import json
import os
from pathlib import Path
import tempfile
import pytest

from core.reporting.desktop_exporter import TargetDesktopExporter


@pytest.fixture
def mock_desktop(monkeypatch):
    """Provides a temporary simulated Desktop environment."""
    with tempfile.TemporaryDirectory() as tmpdir:
        desktop_path = Path(tmpdir) / "Desktop"
        desktop_path.mkdir(parents=True, exist_ok=True)
        monkeypatch.setenv("TARGET_DESKTOP_DIR", str(desktop_path))
        yield desktop_path


def test_clean_target_name():
    """Verifies target string sanitization."""
    # 1. Full HTTPS URL with port and path
    assert TargetDesktopExporter.clean_target_name("https://app.target.com:8443/login?q=1") == "app.target.com"
    # 2. Standard domain
    assert TargetDesktopExporter.clean_target_name("api.securesite.org") == "api.securesite.org"
    # 3. IP address
    assert TargetDesktopExporter.clean_target_name("http://10.10.253.8:8080/dashboard") == "10.10.253.8"
    # 4. Dirty characters
    assert TargetDesktopExporter.clean_target_name("bad/domain:name?test*") == "bad"


def test_get_desktop_dir(mock_desktop):
    """Verifies Desktop path resolution with environment override."""
    resolved = TargetDesktopExporter.get_desktop_dir()
    assert resolved.resolve() == mock_desktop.resolve()
    assert resolved.exists()


def test_target_workspace_structure(mock_desktop):
    """Verifies that the target workspace and all required subdirectories are created."""
    target = "https://vulnerable-store.com/catalog"
    ws = TargetDesktopExporter.get_target_workspace(target)

    assert ws["root"] == mock_desktop / "vulnerable-store.com"
    assert ws["root"].is_dir()
    assert ws["reports"].is_dir()
    assert ws["scripts"].is_dir()
    assert ws["recon"].is_dir()
    assert ws["findings"].is_dir()


def test_export_report_and_script(mock_desktop):
    """Verifies saving reports and executable verification scripts."""
    target = "vulnerable-store.com"

    # Export Report
    report_file = TargetDesktopExporter.export_report(
        target=target,
        content="# Executive Assessment Dossier\nAll systems tested.",
        filename="MASTER_REPORT.md",
    )
    assert report_file.is_file()
    assert "All systems tested" in report_file.read_text(encoding="utf-8")
    assert report_file.parent.name == "reports"

    # Export Script
    script_file = TargetDesktopExporter.export_script(
        target=target,
        content="#!/usr/bin/env python3\nprint('Testing IDOR exploit')",
        filename="test_idor.py",
    )
    assert script_file.is_file()
    assert "Testing IDOR exploit" in script_file.read_text(encoding="utf-8")
    assert script_file.parent.name == "scripts"


def test_export_recon_surface(mock_desktop):
    """Verifies dumping discovered reconnaissance assets into recon/."""
    target = "target-domain.com"
    surface_data = {
        "domains": ["api.target-domain.com", "admin.target-domain.com", "dev.target-domain.com"],
        "live_hosts": ["https://api.target-domain.com", "https://admin.target-domain.com"],
        "endpoints": ["/api/v1/users", "/api/v1/auth", "/admin/metrics"],
        "open_ports": [80, 443, 8443],
    }

    recon_files = TargetDesktopExporter.export_recon_surface(target, surface_data)
    assert "subdomains" in recon_files
    assert "live_hosts" in recon_files
    assert "endpoints" in recon_files
    assert "open_ports" in recon_files
    assert "overview" in recon_files

    # Verify content
    sub_text = recon_files["subdomains"].read_text(encoding="utf-8")
    assert "api.target-domain.com" in sub_text
    assert "admin.target-domain.com" in sub_text

    ep_text = recon_files["endpoints"].read_text(encoding="utf-8")
    assert "/api/v1/users" in ep_text


def test_sync_assessment_full(mock_desktop):
    """Verifies complete end-to-end synchronization with findings, scripts, and SUMMARY.md."""
    target = "https://shop.example-target.com"

    # Mock assessment result
    @dataclass
    class MockResult:
        target: str = "https://shop.example-target.com"
        engagement_id: str = "ENG-TEST1234"
        coverage_pct: float = 92.5
        duration_secs: float = 45.2
        confirmed_findings: list = None

    result = MockResult(
        confirmed_findings=[
            {
                "title": "SQL Injection in User Profile",
                "vuln_class": "SQLI",
                "confidence": 0.95,
                "verdict": "CONFIRMED",
                "evidence": "Observed SQL syntax error and sleep delay in 'id' parameter.",
                "poc_code": "import httpx\nprint('Exploiting SQLi')",
            },
            {
                "title": "IDOR in Orders API",
                "vuln_class": "IDOR",
                "confidence": 0.90,
                "verdict": "CONFIRMED",
                "evidence": "User A accessed User B order receipts.",
            }
        ]
    )

    # Mock engine with surface
    class MockEngine:
        surface = {
            "domains": ["shop.example-target.com", "api.shop.example-target.com"],
            "live_hosts": ["https://shop.example-target.com"],
            "endpoints": ["/api/order/10", "/profile"],
            "open_ports": [443],
        }

    engine = MockEngine()

    # Create dummy master report
    temp_report = mock_desktop / "MASTER_TEMP_REPORT.md"
    temp_report.write_text("# Master Dossier Content", encoding="utf-8")

    sync_stats = TargetDesktopExporter.sync_assessment(
        target=target,
        result=result,
        engine=engine,
        master_report_path=temp_report,
    )

    assert sync_stats["reports_count"] == 1
    assert sync_stats["findings_count"] == 2
    assert sync_stats["scripts_count"] == 2

    target_ws = mock_desktop / "shop.example-target.com"
    summary_file = target_ws / "SUMMARY.md"
    assert summary_file.is_file()

    summary_text = summary_file.read_text(encoding="utf-8")
    assert "shop.example-target.com" in summary_text
    assert "ENG-TEST1234" in summary_text
    assert "SQL Injection in User Profile" in summary_text
    assert "IDOR in Orders API" in summary_text
    assert "92.5%" in summary_text

    # Verify generated scripts in scripts/
    scripts_dir = target_ws / "scripts"
    py_scripts = list(scripts_dir.glob("*.py"))
    assert len(py_scripts) == 2
    assert any("sqli" in s.name.lower() for s in py_scripts)
    assert any("idor" in s.name.lower() for s in py_scripts)
