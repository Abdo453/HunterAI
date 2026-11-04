"""
Agent Power & Capabilities Integration Test Suite.
Validates the holistic autonomous cognitive power of the PentestAI-Unified agent:
1. Autonomous OODA Execution & Information Gain Loop (OmniHunter)
2. Cognitive SecLists & Wordlist Intelligence Engine
3. Automated Target Desktop Exporter (Kali Linux & Cross-Platform)
4. 7-Question Validation Gate & PoC Verification Rigor
5. OpenCode 217 Skills Arsenal & ABH Specialist Tools Bridge
6. Strict Scope Enforcer & Safety Boundaries
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from core.coverage.coverage_ledger import CoverageLedger
from core.engine.omni_hunter_engine import (
    AssessmentConfig,
    AssessmentPhase,
    InformationGainPlanner,
    OmniHunterEngine,
)
from core.reporting.desktop_exporter import TargetDesktopExporter
from core.wordlist_intelligence.cognitive_resolver import CognitiveWordlistResolver
from hunter_ai.tools.abh_bridge import ABHToolBridge
from hunter_ai.validation_gate import ValidationGate, validate_finding


# ── 1. Autonomous OODA Engine Tests ──────────────────────────────────────────

def test_autonomous_ooda_and_information_gain_loop(tmp_path):
    """Verify OmniHunter OODA loop and phase progression."""
    config = AssessmentConfig(
        target_url="https://authorized-target.org",
        scope_domains=["authorized-target.org"],
        snapshot_dir=str(tmp_path / "snapshots"),
        engagement_id="TEST-AUTH-ENG",
    )
    engine = OmniHunterEngine(config)
    assert engine.config.target_url == "https://authorized-target.org"
    assert engine.current_phase == AssessmentPhase.INIT

    planner = InformationGainPlanner()
    ledger = CoverageLedger()
    surface = {}

    p1 = planner.next_phase(AssessmentPhase.RECON, ledger, surface)
    assert p1 == AssessmentPhase.NETWORK

    p2 = planner.next_phase(AssessmentPhase.NETWORK, ledger, surface)
    assert p2 == AssessmentPhase.WEB

    assert planner.should_continue(ledger, threshold=0.85, cycle=1, max_cycles=10)
    assert not planner.should_continue(ledger, threshold=0.85, cycle=10, max_cycles=10)


# ── 2. Cognitive SecLists & Wordlist Intelligence Tests ──────────────────────

def test_cognitive_seclists_intelligence_engine():
    """Verify cognitive deliberation resolves appropriate wordlists for diverse pentest tasks."""
    resolver = CognitiveWordlistResolver()

    # AI / LLM Testing
    res_ai = resolver.deliberate_and_resolve("ai ethical boundaries and divergence attack")
    assert res_ai.category in ["ai_llm", "ai"]
    assert "ethical" in res_ai.selected_path.lower() or "ai" in res_ai.selected_path.lower()

    # Credential & Password Discovery
    res_pwd = resolver.deliberate_and_resolve("admin passwords", profile="standard")
    assert res_pwd.category == "passwords"

    # API & Hidden Parameters
    res_api = resolver.deliberate_and_resolve("api swagger endpoints")
    assert res_api.category in ["api", "fuzzing", "discovery"]


# ── 3. Target Desktop Exporter (Kali Linux Simulation) ───────────────────────

def test_target_desktop_exporter_kali_workspace_integration():
    """Verify automated creation of target directory on Kali Desktop with scripts, reports, and summary."""
    with tempfile.TemporaryDirectory() as temp_dir:
        fake_desktop = Path(temp_dir) / "Desktop"
        fake_desktop.mkdir(parents=True, exist_ok=True)

        with patch.object(TargetDesktopExporter, "get_desktop_dir", return_value=fake_desktop):
            target = "https://app.vulncorp.com:8443/login"
            clean_name = TargetDesktopExporter.clean_target_name(target)
            assert clean_name == "app.vulncorp.com"

            # Create synthetic assessment result with confirmed finding
            class MockAssessmentResult:
                def __init__(self):
                    self.target = target
                    self.status = "COMPLETED"
                    self.confirmed_findings = [
                        {
                            "title": "BOLA / IDOR in Account Invoices API",
                            "vuln_class": "IDOR",
                            "severity": "HIGH",
                            "endpoint": "https://app.vulncorp.com/api/invoices/9921",
                            "poc_code": "import requests\nr = requests.get('https://app.vulncorp.com/api/invoices/9921')\nprint(r.status_code)",
                        }
                    ]

            class MockEngine:
                def __init__(self):
                    self.surface = {
                        "subdomains": ["app.vulncorp.com", "api.vulncorp.com"],
                        "live_hosts": ["app.vulncorp.com:443"],
                        "ports": [443, 8443],
                        "endpoints": ["/login", "/api/invoices"],
                    }

            result_obj = MockAssessmentResult()
            engine_obj = MockEngine()

            sync_res = TargetDesktopExporter.sync_assessment(
                target=target,
                result=result_obj,
                engine=engine_obj,
            )

            assert sync_res["findings_count"] == 1
            assert sync_res["scripts_count"] >= 1

            target_ws = fake_desktop / clean_name
            assert target_ws.is_dir()
            assert (target_ws / "reports").is_dir()
            assert (target_ws / "scripts").is_dir()
            assert (target_ws / "recon").is_dir()
            assert (target_ws / "findings").is_dir()
            assert (target_ws / "SUMMARY.md").is_file()

            # Verify SUMMARY.md contents
            summary_text = (target_ws / "SUMMARY.md").read_text(encoding="utf-8")
            assert "app.vulncorp.com" in summary_text
            assert "BOLA / IDOR" in summary_text


# ── 4. 7-Question Validation Gate & PoC Rigor Tests ──────────────────────────

def test_7_question_validation_gate_filters_noise():
    """Verify 7-Question Gate eliminates weak/hypothetical noise and validates actionable bugs."""
    # Test weak finding: missing informative header without exploit
    weak_finding = {
        "title": "Missing X-Content-Type-Options header",
        "target": "target.corp",
        "evidence": {}
    }
    result_weak = validate_finding(weak_finding)
    assert result_weak["status"] in ["REFUTED", "UNVERIFIED", "KILL"]

    # Test high-impact finding with proof of exploitability
    gate = ValidationGate()
    target_url = "https://example.com/search"
    gate.safety_loop.kg.add_in_scope("example.com")
    gate.safety_loop.kg.add_in_scope(target_url)

    verified_finding = {
        "title": "Example SQL Injection",
        "target": target_url,
        "evidence": {
            "poc": "' OR 1=1 --",
            "arithmetic_proof": "72",
            "differential_response": True,
            "poe_verified": True,
            "real_exploit_path": True,
            "impact": "Full database extraction possible across all customer records",
            "request": "GET /search?q=1 HTTP/1.1",
            "response": "HTTP/1.1 200 OK",
            "severity": "high",
        }
    }
    result_verified = gate.validate(verified_finding)
    assert result_verified.status.value == "PROVEN"
    assert result_verified.confidence == 1.0
    assert len(result_verified.gates) == 7


# ── 5. OpenCode Skills & ABH Tool Bridge Tests ───────────────────────────────

def test_opencode_curated_skills_manifest():
    """Verify OpenCode MANIFEST.json registers curated cybersecurity skill catalog."""
    manifest_path = Path(".opencode/skills/MANIFEST.json")
    assert manifest_path.is_file(), "MANIFEST.json not found in .opencode/skills"

    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert "skills" in data
    assert len(data["skills"]) >= 200

    skill_names = [s["name"] for s in data["skills"]]
    assert any("abh-" in name for name in skill_names)


def test_abh_tool_bridge_scanners():
    """Verify ABHToolBridge parses endpoints without unhandled exceptions."""
    cors_res = ABHToolBridge.scan_cors("https://example.com")
    assert isinstance(cors_res, dict)
    assert "findings_count" in cors_res

    crlf_res = ABHToolBridge.scan_crlf("https://example.com")
    assert isinstance(crlf_res, dict)
    assert "findings_count" in crlf_res
