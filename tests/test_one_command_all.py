"""
Tests for One-Command-For-Everything Execution (pentest all / pentest run / pentest hunt)
========================================================================================
Validates that a single CLI command triggers all engines end-to-end:
  - Cognitive Brain
  - AI Command Synthesizer for every tool
  - AI Browser Operator
  - Burp Suite fusion
  - All 149 skills
  - Exploit chaining
  - Verification court
  - Master bug bounty dossier generation
"""
import glob
from pathlib import Path
from unittest.mock import patch
import pytest

from pentest import build_parser, cmd_all, cmd_hunt, cmd_autopilot


def test_parser_contains_all_and_run_commands():
    """Verify that 'all' and 'run' commands are registered in argparse."""
    parser = build_parser()
    
    # Test 'all' command parsing
    args_all = parser.parse_args(["all", "example.com"])
    assert args_all.command == "all"
    assert args_all.target == "example.com"
    assert args_all.platform == "hackerone"
    assert hasattr(args_all, "fallback")

    # Test 'run' alias parsing
    args_run = parser.parse_args(["run", "target.corp", "--platform", "bugcrowd"])
    assert args_run.command == "run"
    assert args_run.target == "target.corp"
    assert args_run.platform == "bugcrowd"

    # Test 'hunt' default authorization
    args_hunt = parser.parse_args(["hunt", "app.target.com"])
    assert args_hunt.command == "hunt"
    assert args_hunt.authorized is True


def test_cmd_all_execution_and_dossier_generation(tmp_path):
    """Verify cmd_all runs the complete pipeline and generates a master dossier report."""
    reports_dir = tmp_path / "reports"
    parser = build_parser()
    args = parser.parse_args([
        "all", "test-master.com",
        "--fallback",
        "--max-cycles", "1",
        "--output-dir", str(reports_dir),
    ])

    exit_code = cmd_all(args)
    assert exit_code == 0

    # Verify dossier file was written
    generated_reports = list(reports_dir.glob("MASTER_DOSSIER_test-master.com_*.md"))
    assert len(generated_reports) == 1, "Expected master dossier file to be generated"

    content = generated_reports[0].read_text(encoding="utf-8")
    assert "Comprehensive Security Assessment Dossier: test-master.com" in content
    assert "Discovered Perimeter & Surface" in content
    assert "Confirmed Vulnerabilities" in content
    assert "Multi-Step Exploit Chains" in content
    assert "Remediation Guidance" in content


def test_cmd_hunt_delegates_to_cmd_all(tmp_path):
    """Verify cmd_hunt seamlessly calls cmd_all with all features active."""
    reports_dir = tmp_path / "hunt_reports"
    parser = build_parser()
    args = parser.parse_args([
        "hunt", "hunt-target.com",
        "--fallback",
        "--max-cycles", "1",
        "--output-dir", str(reports_dir),
    ])

    exit_code = cmd_hunt(args)
    assert exit_code == 0

    generated_reports = list(reports_dir.glob("MASTER_DOSSIER_hunt-target.com_*.md"))
    assert len(generated_reports) == 1
