"""
Hermetic Test Suite for Agentic Bug Hunter (ABH) Integration
============================================================
Validates:
1. Skills Library: All 19 skills archived in skills_library/agentic-bug-hunter/skills/.
2. OpenCode Deployment: All 19 skills present in .opencode/skills/abh-* with valid SKILL.md.
3. OpenCode Manifest: MANIFEST.json tracks 217 skills with agentic-bug-hunter pack.
4. Slash Commands: All 43 commands archived in commands/.
5. Bughunter Tools: Core Python scanner tools import and run without syntax errors.
6. ABH Bridge: ABHToolBridge evaluates 7-question gate and provides tool interfaces.
7. SkillMatrixViewer: Successfully aggregates the new layer into platform totals.
"""
from __future__ import annotations

import json
import os
import pytest
from core.skills.skill_matrix_viewer import SkillMatrixViewer
from hunter_ai.tools.abh_bridge import ABHToolBridge

EXPECTED_19_SKILLS = [
    "agentic-app-audit",
    "argus",
    "bb-methodology",
    "bug-bounty",
    "cicd-security",
    "client-reverse",
    "cloud-pentest",
    "credential-attack",
    "graphql-audit",
    "llm-redteam",
    "mcp-server-audit",
    "meme-coin-audit",
    "mobile-pentest",
    "report-writing",
    "security-arsenal",
    "triage-validation",
    "web2-recon",
    "web2-vuln-classes",
    "web3-audit",
]


class TestAgenticBugHunterIngestion:
    """Verifies complete ingestion of Agentic Bug Hunter skills and tools."""

    def test_skills_library_inventory(self):
        base_dir = "skills_library/agentic-bug-hunter/skills"
        assert os.path.exists(base_dir), f"Directory {base_dir} missing"
        skills = os.listdir(base_dir)
        for s in EXPECTED_19_SKILLS:
            assert s in skills, f"Missing skill in skills_library: {s}"
            skill_md = os.path.join(base_dir, s, "SKILL.md")
            assert os.path.isfile(skill_md), f"SKILL.md missing for {s}"

    def test_opencode_skills_deployment(self):
        opencode_dir = ".opencode/skills"
        assert os.path.exists(opencode_dir)
        for s in EXPECTED_19_SKILLS:
            abh_name = f"abh-{s}"
            skill_path = os.path.join(opencode_dir, abh_name)
            assert os.path.exists(skill_path), f"Missing OpenCode skill dir: {abh_name}"
            skill_md = os.path.join(skill_path, "SKILL.md")
            assert os.path.isfile(skill_md), f"Missing SKILL.md in {abh_name}"
            with open(skill_md, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            assert f"name: {abh_name}" in content, f"Name mismatch in {skill_md}"

    def test_opencode_manifest_integrity(self):
        manifest_path = ".opencode/skills/MANIFEST.json"
        assert os.path.isfile(manifest_path)
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        assert manifest.get("count") >= 217
        skills = manifest.get("skills", [])
        abh_entries = [s for s in skills if s.get("pack") == "agentic-bug-hunter"]
        assert len(abh_entries) == 19

        abh_names = {s["name"] for s in abh_entries}
        for expected in EXPECTED_19_SKILLS:
            assert f"abh-{expected}" in abh_names

    def test_commands_inventory(self):
        cmds_dir = "commands"
        assert os.path.exists(cmds_dir)
        files = os.listdir(cmds_dir)
        assert len(files) >= 43
        assert "cors.md" in files
        assert "crlf.md" in files
        assert "autopilot.md" in files
        assert "recon.md" in files
        assert "hunt.md" in files
        assert "validate.md" in files

    def test_bughunter_tools_importable(self):
        import bughunter
        from bughunter.tools import cors_scanner, crlf_scanner, jwt_scanner, nosqli_scanner
        assert hasattr(cors_scanner, "scan")
        assert hasattr(crlf_scanner, "scan")
        assert hasattr(jwt_scanner, "analyze")
        assert hasattr(nosqli_scanner, "scan_login")

    def test_abh_bridge_execution(self):
        # 1. 7-Question Gate Pass
        pass_res = ABHToolBridge.evaluate_7question_gate(
            target="https://target.com/api",
            vuln_class="IDOR",
            impact_statement="Direct unauthorized access to customer records",
            in_scope=True,
            is_reproducible=True,
        )
        assert pass_res["pass_gate"] is True
        assert pass_res["verdict"] == "PASSED"

        # 2. 7-Question Gate Kill
        kill_res = ABHToolBridge.evaluate_7question_gate(
            target="https://target.com",
            vuln_class="missing_dmarc",
            impact_statement="DMARC missing",
            in_scope=True,
            is_reproducible=True,
        )
        assert kill_res["pass_gate"] is False
        assert kill_res["verdict"] == "KILLED"

    def test_skill_matrix_viewer_aggregates_abh(self):
        stats = SkillMatrixViewer.get_summary_stats()
        assert stats["total_skills"] >= 169
        assert stats["agentic_bug_hunter_skills_count"] == 19

        abh_skills = SkillMatrixViewer.get_agentic_bug_hunter_skills()
        assert len(abh_skills) == 19
        for s in abh_skills:
            assert s["name"].startswith("abh-")
            assert s["layer"] == "agentic_bug_hunter"
            assert s["category"] == "bug_hunter"
