"""
Tests for Unified Skills Matrix and Viewer.
Hermetic offline tests verifying skill collection across directory, hunter, and kali layers.
"""
import pytest
from fastapi.testclient import TestClient

from core.skills.skill_matrix_viewer import SkillMatrixViewer
from ui.web.app import app


def test_skill_matrix_summary_stats():
    """Verify statistics aggregates across all 3 skill layers."""
    stats = SkillMatrixViewer.get_summary_stats()
    assert stats["total_skills"] >= 100
    assert stats["directory_skills_count"] >= 40
    assert stats["hunter_vuln_skills_count"] >= 25
    assert stats["kali_tool_skills_count"] >= 60


def test_skill_matrix_list_and_filters():
    """Verify listing and category filtering."""
    all_skills = SkillMatrixViewer.list_all_skills()
    assert len(all_skills) >= 100

    recon_skills = SkillMatrixViewer.list_all_skills(category="recon")
    assert len(recon_skills) > 0
    assert all("recon" in s.get("category", "").lower() for s in recon_skills)

    kali_skills = SkillMatrixViewer.list_all_skills(layer="kali_arsenal")
    assert len(kali_skills) >= 60
    assert all(s.get("layer") == "kali_arsenal" for s in kali_skills)


def test_get_skill_details():
    """Verify finding specific skill by name."""
    sqli = SkillMatrixViewer.get_skill_details("sqli_hunter")
    assert sqli is not None
    assert sqli["name"] == "sqli_hunter"
    assert sqli["category"] == "web"

    nmap = SkillMatrixViewer.get_skill_details("nmap")
    assert nmap is not None
    assert nmap["binary"] == "nmap"

    missing = SkillMatrixViewer.get_skill_details("non_existent_skill_xyz")
    assert missing is None


def test_web_ui_skills_catalog_endpoint():
    """Verify GET /api/skills/catalog returns full skills payload."""
    client = TestClient(app)
    response = client.get("/api/skills/catalog")
    assert response.status_code == 200
    data = response.json()
    assert "summary" in data
    assert "skills" in data
    assert data["summary"]["total_skills"] >= 100
    assert len(data["skills"]) >= 100
