"""Tests for FIX 5: BurpIssueExporter initialization, persistence, and backwards compatibility."""
from __future__ import annotations

from enum import Enum
import json
from pathlib import Path

from core.burp_gateway.issue_exporter import BurpIssueExporter


class _DummyVerdict(str, Enum):
    CONFIRMED = "CONFIRMED"


def test_init_default_creates_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    exporter = BurpIssueExporter()

    expected_dir = Path("data/exports/burp_issues")
    assert exporter.output_dir == expected_dir
    assert (tmp_path / expected_dir).is_dir()


def test_init_with_custom_str_and_path(tmp_path):
    str_dir = tmp_path / "nested" / "str_exports"
    exporter_str = BurpIssueExporter(str(str_dir))
    assert exporter_str.output_dir == str_dir
    assert str_dir.is_dir()

    path_dir = tmp_path / "nested" / "path_exports"
    exporter_path = BurpIssueExporter(output_dir=path_dir)
    assert exporter_path.output_dir == path_dir
    assert path_dir.is_dir()


def test_export_finding_persists_individual_and_index_json(tmp_path):
    export_dir = tmp_path / "burp_issues"
    exporter = BurpIssueExporter(output_dir=export_dir)

    finding = {
        "finding_id": "FND-001",
        "title": "Reflected XSS in search parameter",
        "type": "xss",
        "severity": "High",
        "lifecycle_verdict": "CONFIRMED",
        "endpoint": "https://app.example.com/search?q=1",
        "payload_used": "<svg onload=alert(1)>",
        "evidence": "Payload executed in DOM.",
        "remediation": "Context-encode HTML output.",
        "raw_request": "GET /search?q=%3Csvg%3E HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
        "raw_response": "HTTP/1.1 200 OK\r\n\r\n<svg onload=alert(1)>",
    }

    result = exporter.export_finding(finding)

    assert result["issue_name"] == "[HunterAI] Reflected XSS in search parameter"
    assert result["severity"] == "High"
    assert result["confidence"] == "Certain"
    assert result["host"] == "app.example.com"
    assert result["port"] == 443
    assert result["protocol"] == "https"
    assert len(result["http_messages"]) == 1

    saved_file = Path(result["export_path"])
    assert saved_file.parent == export_dir
    assert saved_file.name == "FND-001.json"
    assert saved_file.exists()

    persisted_issue = json.loads(saved_file.read_text(encoding="utf-8"))
    assert persisted_issue["issue_name"] == result["issue_name"]
    assert "export_path" not in persisted_issue

    index_file = export_dir / "issues.json"
    assert index_file.exists()
    index_data = json.loads(index_file.read_text(encoding="utf-8"))
    assert isinstance(index_data, list)
    assert len(index_data) == 1
    assert index_data[0]["issue_name"] == result["issue_name"]


def test_export_finding_appends_across_instances_and_normalizes_brain_fields(tmp_path):
    export_dir = tmp_path / "burp_issues"
    exporter1 = BurpIssueExporter(output_dir=export_dir)
    exporter1.export_finding({
        "title": "SQL Injection in id",
        "type": "sqli",
        "severity": "CRITICAL",
        "lifecycle_verdict": _DummyVerdict.CONFIRMED,
        "url": "https://api.example.com:8443/items?id=1",
        "evidence": "Arithmetic delta confirmed.",
    })

    exporter2 = BurpIssueExporter(output_dir=export_dir)
    second = exporter2.export_finding({
        "id": "../../issues",
        "title": "SSRF in webhook",
        "severity": "Medium",
        "endpoint": "http://internal.example.com/hook",
    })

    second_path = Path(second["export_path"])
    assert second_path.parent == export_dir
    assert second_path.name == "finding_issues.json"
    assert second_path.exists()

    index_data = json.loads((export_dir / "issues.json").read_text(encoding="utf-8"))
    assert len(index_data) == 2
    assert index_data[0]["severity"] == "High"
    assert index_data[0]["host"] == "api.example.com"
    assert index_data[0]["port"] == 8443
    assert index_data[0]["confidence"] == "Certain"
    assert "CONFIRMED" in index_data[0]["issue_detail"]
    assert index_data[1]["issue_name"] == "[HunterAI] SSRF in webhook"


def test_export_finding_without_output_dir_does_not_write_to_disk():
    exporter = BurpIssueExporter(output_dir=None)
    assert exporter.output_dir is None

    result = exporter.export_finding({
        "title": "Open Redirect",
        "severity": "Low",
        "endpoint": "https://example.com/login",
    })

    assert result["issue_name"] == "[HunterAI] Open Redirect"
    assert result["severity"] == "Low"
    assert "export_path" not in result
    assert len(exporter.exported_issues) == 1


def test_backwards_compatibility_classmethods():
    finding = {
        "title": "Command Injection",
        "type": "cmd_injection",
        "severity": "Critical",
        "lifecycle_verdict": "CONFIRMED",
        "endpoint": "https://api.target.com/ping",
        "payload_used": "; id",
        "evidence": "uid=0(root)",
        "remediation": "Disable shell execution.",
        "raw_request": "GET /ping HTTP/1.1\r\nHost: api.target.com\r\n\r\n",
        "raw_response": "HTTP/1.1 200 OK\r\n\r\nuid=0(root)",
    }

    single = BurpIssueExporter.format_finding_for_burp(finding)
    assert single["issue_name"] == "[HunterAI] Command Injection"
    assert single["severity"] == "High"
    assert single["confidence"] == "Certain"
    assert single["host"] == "api.target.com"

    batch = BurpIssueExporter.export_all([finding])
    assert batch == [single]
