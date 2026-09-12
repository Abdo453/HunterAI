"""
Unit & Integration Tests for BugBountySkills Ported Architecture:
- Master System Prompts Orchestrator
- Multi-Cloud Metadata Matrix
- Operational Security Checklists Engine
- Cloud & API Surface Audit Skills
"""
from __future__ import annotations

import pytest

from core.cloud_metadata_matrix import CloudMetadataMatrix
from core.master_prompts import MasterPromptOrchestrator
from core.security_checklists import SecurityChecklistEngine
from core.skill_registry import SkillRegistry


def test_master_prompts_orchestrator():
    recon_prompt = MasterPromptOrchestrator.get_prompt("recon_mode")
    assert "RECON MODE" in recon_prompt
    assert "subdomain" in recon_prompt.lower()

    api_prompt = MasterPromptOrchestrator.get_prompt("api_security_mode")
    assert "API & GRAPHQL" in api_prompt
    assert "introspection" in api_prompt.lower()

    cloud_prompt = MasterPromptOrchestrator.get_prompt("cloud_metadata_mode")
    assert "CLOUD INFRASTRUCTURE" in cloud_prompt
    assert "IMDSv2" in cloud_prompt

    modes = MasterPromptOrchestrator.list_available_modes()
    assert len(modes) >= 6
    assert "source_audit_mode" in modes


def test_cloud_metadata_matrix():
    aws_prof = CloudMetadataMatrix.get_profile("aws_imdsv1")
    assert aws_prof is not None
    assert "169.254.169.254" in aws_prof.endpoint_url
    assert "iam/security-credentials/" in aws_prof.sensitive_paths

    gcp_prof = CloudMetadataMatrix.get_profile("gcp_metadata")
    assert gcp_prof is not None
    assert "metadata.google.internal" in gcp_prof.endpoint_url
    assert "Metadata-Flavor" in gcp_prof.required_headers

    all_profs = CloudMetadataMatrix.list_all_profiles()
    assert len(all_profs) >= 6


def test_security_checklists_engine():
    categories = SecurityChecklistEngine.list_all_categories()
    assert len(categories) >= 4
    assert "web_security" in categories
    assert "api_security" in categories
    assert "ai_llm_security" in categories

    web_cl = SecurityChecklistEngine.get_checklist("web_security")
    assert web_cl is not None
    assert len(web_cl.items) >= 3
    assert any("IDOR" in item.title for item in web_cl.items)

    md_summary = SecurityChecklistEngine.export_markdown_summary()
    assert "# 📋 Unified Security & Bug Bounty Checklists" in md_summary
    assert "WEB-01" in md_summary


def test_new_skills_discovery():
    registry = SkillRegistry()
    registry.discover(force=True)

    all_names = registry.list_names()
    assert "cloud_metadata_audit" in all_names
    assert "api_surface_audit" in all_names

    cloud_skill = registry.instantiate("cloud_metadata_audit")
    assert cloud_skill is not None
    assert cloud_skill.category == "analysis"

    api_skill = registry.instantiate("api_surface_audit")
    assert api_skill is not None
    assert api_skill.category == "analysis"
