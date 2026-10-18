"""
Tests for the unified `hunter skills` CLI command (cli/hunter_cli.py).
=====================================================================
"""
from __future__ import annotations

import json

import pytest

from cli.hunter_cli import main

NEW_SKILLS = {"ssh_audit", "tls_audit", "smb_enum", "waf_detection"}


def test_skills_list_json(capsys):
    main(["skills", "list", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["total"] >= 22
    names = {s["name"] for s in data["skills"]}
    assert NEW_SKILLS.issubset(names)


def test_skills_list_category_filter(capsys):
    main(["skills", "list", "--category", "analysis", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["skills"], "expected at least one analysis skill"
    assert all(s["category"] == "analysis" for s in data["skills"])
    assert "ssh_audit" in {s["name"] for s in data["skills"]}
    assert "waf_detection" not in {s["name"] for s in data["skills"]}


def test_skills_show_json_with_contract(capsys):
    main(["skills", "show", "waf_detection", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["metadata"]["name"] == "waf_detection"
    assert data["metadata"]["category"] == "recon"
    assert data["contract"]["risk_level"] == "low"


def test_skills_show_missing_exits_nonzero(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["skills", "show", "no_such_skill_xyz"])
    assert exc.value.code != 0
    out = capsys.readouterr().out
    assert "not found" in out.lower()


def test_skills_graph_json(capsys):
    main(["skills", "graph", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert "ssh_audit" in data
    assert "smb_enum" in data
    # خدمة تدقيق الخدمات تُفتح بواسطة port_scan
    assert {"ssh_audit", "tls_audit", "smb_enum"}.issubset(set(data["port_scan"]["next_skills"]))
    # كشف WAF يُفتح بواسطة tech_detection
    assert "waf_detection" in data["tech_detection"]["next_skills"]
