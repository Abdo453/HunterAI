"""
Tests for Native Kali Linux Enhancements
=========================================
Validates:
  1. Auto-Resolution of Kali Wordlists (/usr/share/... vs fallback)
  2. Upstream Proxy Injection (Burp Suite 127.0.0.1:8080)
  3. Multi-Target File & Comma List Support
  4. Engagement Checkpoint Resumption (--resume)
  5. POSIX Privilege Adaptation (Root vs Non-Root Nmap)
"""
import os
from pathlib import Path
from unittest.mock import patch
import pytest

from core.arsenal.ai_command_synthesizer import (
    AIToolCommandSynthesizer,
    TargetContext,
    resolve_kali_wordlist,
    resolve_kali_params_wordlist,
    is_root_privileged,
)
from core.arsenal.kali_catalog import get_tool_definition
from core.engine.omni_hunter_engine import AssessmentConfig, OmniHunterEngine, AssessmentPhase
from pentest import build_parser, cmd_all


# ── 1. Kali Wordlist Auto-Resolver Tests ──────────────────────────────────────

def test_resolve_kali_wordlist_returns_existing_file():
    """Verify resolve_kali_wordlist always returns a valid, readable wordlist file."""
    wl = resolve_kali_wordlist()
    assert wl is not None
    p = Path(wl)
    assert p.is_file(), f"Expected valid wordlist file at {wl}"
    content = p.read_text(encoding="utf-8")
    assert len(content.strip()) > 0


def test_ffuf_uses_resolved_wordlist():
    """Verify ffuf command synthesis uses the resolved wordlist instead of hardcoded missing path."""
    ffuf_def = get_tool_definition("ffuf")
    ctx = TargetContext(target="https://kali-test.com")
    synth = AIToolCommandSynthesizer.synthesize_sync(ffuf_def, ctx)

    assert "-w" in synth.args
    w_idx = synth.args.index("-w")
    wordlist_used = synth.args[w_idx + 1]
    assert Path(wordlist_used).is_file(), f"Wordlist used does not exist: {wordlist_used}"


# ── 2. Upstream Burp Proxy Injection Tests ───────────────────────────────────

def test_proxy_injection_across_tools():
    """Verify upstream proxy is properly injected into Nuclei, Ffuf, SQLmap, and Httpx."""
    proxy_url = "http://127.0.0.1:8080"
    ctx = TargetContext(target="https://kali-test.com", proxy=proxy_url)

    # Nuclei: -proxy
    nuclei_def = get_tool_definition("nuclei")
    res_nuclei = AIToolCommandSynthesizer.synthesize_sync(nuclei_def, ctx)
    assert "-proxy" in res_nuclei.args
    assert proxy_url in res_nuclei.args

    # Ffuf: -x
    ffuf_def = get_tool_definition("ffuf")
    res_ffuf = AIToolCommandSynthesizer.synthesize_sync(ffuf_def, ctx)
    assert "-x" in res_ffuf.args
    assert proxy_url in res_ffuf.args

    # SQLmap: --proxy=
    sqlmap_def = get_tool_definition("sqlmap")
    res_sqlmap = AIToolCommandSynthesizer.synthesize_sync(sqlmap_def, ctx)
    assert any(f"--proxy={proxy_url}" in a for a in res_sqlmap.args)

    # Httpx: -http-proxy
    httpx_def = get_tool_definition("httpx")
    res_httpx = AIToolCommandSynthesizer.synthesize_sync(httpx_def, ctx)
    assert "-http-proxy" in res_httpx.args
    assert proxy_url in res_httpx.args


# ── 3. Multi-Target File & Comma Parsing Tests ────────────────────────────────

def test_multi_target_file_execution(tmp_path):
    """Verify cmd_all reads targets from a file and produces a multi-target dossier."""
    targets_file = tmp_path / "targets.txt"
    targets_file.write_text("site-one.internal\nsite-two.internal\n", encoding="utf-8")

    reports_dir = tmp_path / "reports"
    parser = build_parser()
    args = parser.parse_args([
        "all", str(targets_file),
        "--fallback",
        "--max-cycles", "1",
        "--output-dir", str(reports_dir),
    ])

    exit_code = cmd_all(args)
    assert exit_code == 0

    # Verify multi-target dossier was created
    multi_dossiers = list(reports_dir.glob("MASTER_MULTI_TARGET_DOSSIER_*.md"))
    assert len(multi_dossiers) == 1
    content = multi_dossiers[0].read_text(encoding="utf-8")
    assert "Targets Assessed" in content and "2" in content
    assert "site-one.internal" in content
    assert "site-two.internal" in content


# ── 4. Engagement Checkpoint Resumption Tests ─────────────────────────────────

def test_omni_hunter_resumes_from_snapshot(tmp_path):
    """Verify OmniHunterEngine restores state when resume_engagement_id is provided."""
    snapshots_dir = tmp_path / "snapshots"
    snapshots_dir.mkdir(parents=True, exist_ok=True)

    # Create engine and save checkpoint
    cfg_initial = AssessmentConfig(
        target_url="https://resume-test.com",
        scope_domains=["resume-test.com"],
        engagement_id="ENG-CHECKPOINT-1",
        snapshot_dir=str(snapshots_dir),
        force_tool_fallback=True,
    )
    engine_initial = OmniHunterEngine(cfg_initial)
    engine_initial.surface["domains"].append("sub.resume-test.com")
    engine_initial.surface["open_ports"].append("resume-test.com:443")
    engine_initial.confirmed_findings.append({
        "vuln_class": "XSS",
        "title": "Confirmed Test XSS",
        "target": "https://resume-test.com/search",
    })
    engine_initial._save_checkpoint()

    # Now create new engine with resume_engagement_id
    cfg_resume = AssessmentConfig(
        target_url="https://resume-test.com",
        scope_domains=["resume-test.com"],
        resume_engagement_id="ENG-CHECKPOINT-1",
        snapshot_dir=str(snapshots_dir),
        force_tool_fallback=True,
    )
    engine_resumed = OmniHunterEngine(cfg_resume)

    # Verify state was restored
    assert "sub.resume-test.com" in engine_resumed.surface["domains"]
    assert "resume-test.com:443" in engine_resumed.surface["open_ports"]
    assert len(engine_resumed.confirmed_findings) == 1
    assert engine_resumed.confirmed_findings[0]["title"] == "Confirmed Test XSS"


# ── 5. Privilege-Aware Scanning Tests ─────────────────────────────────────────

def test_nmap_privilege_awareness():
    """Verify Nmap uses -sT when simulated as non-root on POSIX."""
    nmap_def = get_tool_definition("nmap")
    ctx = TargetContext(target="kali-host.corp")

    with patch("core.arsenal.ai_command_synthesizer.is_root_privileged", return_value=False):
        with patch("os.geteuid", create=True, return_value=1000):
            res_non_root = AIToolCommandSynthesizer.synthesize_sync(nmap_def, ctx)
            assert "-sT" in res_non_root.args

    with patch("core.arsenal.ai_command_synthesizer.is_root_privileged", return_value=True):
        with patch("os.geteuid", create=True, return_value=0):
            res_root = AIToolCommandSynthesizer.synthesize_sync(nmap_def, ctx)
            assert "-sS" in res_root.args
