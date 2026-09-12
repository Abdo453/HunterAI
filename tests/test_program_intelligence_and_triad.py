"""
Unit and Integration Tests for:
1. Program Intelligence & Security.txt Parser (BBP vs VDP, Platform vs Self-Hosted, Public vs Private)
2. Local Triad Agent (WhiteRabbitNeo, xploiter/pentester, Qwen 2.5 Coder)
3. End-to-end Orchestrator integration with Program Classification and Reporting
"""
import os
import json
import pytest
import asyncio
from unittest.mock import AsyncMock, patch

from hunter_ai.pipeline.schemas import (
    ProgramType,
    ProgramPlatform,
    ProgramVisibility,
    ProgramMetadata,
)
from core.program_intelligence import SecurityTxtParser, ProgramIntelligence
from hunter_ai.brain.local_triad_agent import (
    LocalTriadAgent,
    MODEL_OFFENSIVE,
    MODEL_RECON,
    MODEL_CODE,
)
from hunter_ai.pipeline.pipeline_orchestrator import HunterPipelineOrchestrator


# ── 1. SECURITY.TXT & PROGRAM INTELLIGENCE TESTS ─────────────────────────────

def test_security_txt_parser_hackerone_bbp():
    """Verify parsing a platform-hosted Bug Bounty Program (HackerOne) with rewards"""
    sample_security_txt = """
    Contact: https://hackerone.com/target_corp
    Policy: https://hackerone.com/target_corp
    Acknowledgments: https://hackerone.com/target_corp/thanks
    Preferred-Languages: en
    # We offer cash bounties and rewards for critical findings
    """
    meta = SecurityTxtParser.parse(sample_security_txt, "https://target.com/.well-known/security.txt")
    assert meta.security_txt_found is True
    assert meta.platform == ProgramPlatform.HACKERONE
    assert meta.program_type == ProgramType.BBP
    assert meta.bounty_eligible is True
    assert "hackerone.com/target_corp" in meta.policy_url


def test_security_txt_parser_self_hosted_vdp():
    """Verify parsing a self-hosted Vulnerability Disclosure Program with email and HoF"""
    sample_security_txt = """
    Contact: mailto:security@company.org
    Policy: https://company.org/responsible-disclosure
    Acknowledgments: https://company.org/hall-of-fame
    Encryption: https://company.org/pgp-key.asc
    """
    meta = SecurityTxtParser.parse(sample_security_txt, "https://company.org/security.txt")
    assert meta.security_txt_found is True
    assert meta.platform == ProgramPlatform.SELF_HOSTED
    assert meta.program_type == ProgramType.SELF_HOSTED_VDP
    assert meta.contact_email == "security@company.org"
    assert meta.pgp_key_url == "https://company.org/pgp-key.asc"
    assert meta.acknowledgments_url == "https://company.org/hall-of-fame"
    assert meta.bounty_eligible is False


def test_generate_hackerone_bounty_report():
    """Verify generation of HackerOne / Bugcrowd formatted submission with business impact and reproduction"""
    findings = [{
        "finding": "SQL Injection (UNION / Extraction) on 'category'",
        "vuln_type": "SQLi",
        "endpoint": "https://target.com/products",
        "parameter": "category",
        "severity": "Critical",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "reproduction": {"curl_command": "curl -s 'https://target.com/products?category=1'"},
        "evidence": [{"description": "Database version extracted", "proof_snippet": "PostgreSQL 14.2"}],
        "remediation": "Use parameterized queries."
    }]
    meta = ProgramMetadata(program_type=ProgramType.BBP, platform=ProgramPlatform.HACKERONE)
    rep = ProgramIntelligence.generate_hackerone_report("target.com", findings, meta)

    assert "Bug Bounty Vulnerability Submission: target.com" in rep
    assert "Steps to Reproduce" in rep
    assert "Business Impact" in rep
    assert "CVSS v3.1" in rep
    assert "curl -s 'https://target.com/products?category=1'" in rep


def test_generate_vdp_email_template():
    """Verify generation of polite CVD email to security@company.com with Hall of Fame request"""
    findings = [{
        "finding": "Open Network Services",
        "vuln_type": "OpenPorts",
        "endpoint": "target.org",
        "severity": "Info"
    }]
    email = ProgramIntelligence.generate_vdp_email_template(
        "target.org",
        "security@target.org",
        findings,
        acknowledgments_url="https://target.org/hof"
    )
    assert "To: security@target.org" in email
    assert "Coordinated Vulnerability Disclosure (CVD)" in email
    assert "Hall of Fame" in email
    assert "https://target.org/hof" in email


# ── 2. LOCAL TRIAD AGENT ROUTING TESTS ────────────────────────────────────────

@pytest.mark.asyncio
async def test_local_triad_agent_routing():
    """Verify that user prompts route to the exact designated specialist among the 3 models"""
    agent = LocalTriadAgent()

    # Mock _query_ollama to avoid calling real model during fast unit test
    agent._query_ollama = AsyncMock(return_value="Mocked AI response")

    # 1. Code / JS -> Qwen 2.5 Coder
    res_code = await agent.process_prompt("Write a javascript regex parser to extract api tokens from bundle.js")
    assert res_code["assigned_model"] == MODEL_CODE
    assert "Qwen 2.5 Coder" in res_code["role"]

    # 2. Exploit / Bypass -> WhiteRabbitNeo
    res_off = await agent.process_prompt("How to bypass a WAF blocking single quotes in an SQL injection payload?")
    assert res_off["assigned_model"] == MODEL_OFFENSIVE
    assert "WhiteRabbitNeo" in res_off["role"]

    # 3. Recon / Checklist -> xploiter/pentester
    res_recon = await agent.process_prompt("Found subdomains and open ports 80 and 443. What is the first checklist to triage?")
    assert res_recon["assigned_model"] == MODEL_RECON
    assert "xploiter/pentester" in res_recon["role"]


# ── 3. ORCHESTRATOR INTEGRATION TEST ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_orchestrator_program_metadata_and_reports():
    """Verify orchestrator discovers program metadata, saves it in 00_scope, and writes VDP/BBP deliverables"""
    orch = HunterPipelineOrchestrator(
        target="scanme.nmap.org",
        profile="passive",
        authorized=False,
        workflow="recon"
    )
    res = await orch.run()
    assert res["status"] == "completed"

    # Check 00_scope/program_metadata.json
    prog_meta_file = os.path.join(orch.artifact_root, "00_scope", "program_metadata.json")
    assert os.path.exists(prog_meta_file)
    with open(prog_meta_file, "r", encoding="utf-8") as f:
        meta_data = json.load(f)
    assert "program_type" in meta_data
    assert "platform" in meta_data

    # Check 14_reports has vdp disclosure template
    vdp_file = os.path.join(orch.artifact_root, "14_reports", "vdp_disclosure_email.txt")
    assert os.path.exists(vdp_file)
    with open(vdp_file, "r", encoding="utf-8") as f:
        vdp_content = f.read()
    assert "Subject: [Security Vulnerability Report]" in vdp_content
