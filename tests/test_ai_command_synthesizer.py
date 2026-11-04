"""
HunterAI Tool Command Synthesizer Tests
========================================
Validates AI-driven dynamic CLI command generation across:
  - WAF Profile Adaptation (Cloudflare, Akamai, AWS WAF evasion)
  - Tech Stack Tailoring (PHP, WordPress, Node.js, Spring)
  - Port Surface Tailoring (Targeted vs Standard scans)
  - Strict Safety Invariants (Blacklisted dangerous flags removal)
  - DynamicToolAgent integration
"""
import pytest
from core.arsenal.ai_command_synthesizer import (
    AIToolCommandSynthesizer,
    SynthesizedCommand,
    TargetContext,
)
from core.arsenal.kali_catalog import ToolCategory, get_tool_definition
from core.arsenal.tool_agent_factory import DynamicToolAgent, ToolAgentFactory
from core.engine.real_tool_adapter import RealToolAdapter


# ── 1. TargetContext & Dataclass Tests ────────────────────────────────────────

def test_target_context_properties():
    """Verify clean_host, is_url, and has_waf properties."""
    ctx_url = TargetContext(target="https://api.staging.corp.com:8443/v1/auth", waf_name="Cloudflare")
    assert ctx_url.clean_host == "api.staging.corp.com"
    assert ctx_url.is_url is True
    assert ctx_url.has_waf is True

    ctx_host = TargetContext(target="target.internal", waf_name=None)
    assert ctx_host.clean_host == "target.internal"
    assert ctx_host.is_url is False
    assert ctx_host.has_waf is False


def test_synthesized_command_serialization():
    """Verify SynthesizedCommand converts cleanly to dictionary."""
    synth = SynthesizedCommand(
        tool_name="test_tool",
        binary_name="test_bin",
        args=["-a", "-b"],
        command_line="test_bin -a -b",
        ai_reasoning="Reasoning test",
        evasion_strategy="Evasion test",
        context_signals_used=["Signal1"],
        risk_level="low",
        is_safe=True,
    )
    d = synth.to_dict()
    assert d["tool_name"] == "test_tool"
    assert d["command_line"] == "test_bin -a -b"
    assert d["is_safe"] is True


# ── 2. Nmap & Port Scanner Synthesis ──────────────────────────────────────────

def test_nmap_waf_and_port_adaptation():
    """Verify Nmap applies polite timing and targeted ports when WAF and ports are known."""
    nmap_def = get_tool_definition("nmap")
    assert nmap_def is not None

    # Context with WAF and confirmed ports
    ctx = TargetContext(
        target="scanner.target.com",
        waf_name="Cloudflare",
        open_ports=[80, 443, 8080],
    )
    synth = AIToolCommandSynthesizer.synthesize_sync(nmap_def, ctx)
    assert synth.is_safe is True
    assert "-p" in synth.args
    assert "80,443,8080" in synth.args
    assert "-T2" in synth.args  # Polite timing for WAF
    assert "--randomize-hosts" in synth.args
    assert "Cloudflare" in synth.evasion_strategy


def test_nmap_baseline_without_waf():
    """Verify standard aggressive timing when no WAF is present."""
    nmap_def = get_tool_definition("nmap")
    ctx = TargetContext(target="scanner.target.com")
    synth = AIToolCommandSynthesizer.synthesize_sync(nmap_def, ctx)
    assert "-T4" in synth.args
    assert "-Pn" in synth.args


# ── 3. Nuclei Vulnerability Scanner Synthesis ─────────────────────────────────

def test_nuclei_tech_stack_wordpress_php():
    """Verify Nuclei selects WordPress and PHP templates based on tech stack."""
    nuclei_def = get_tool_definition("nuclei")
    assert nuclei_def is not None

    ctx = TargetContext(
        target="https://blog.target.com",
        tech_stack=["WordPress", "PHP"],
        waf_name="Cloudflare",
    )
    synth = AIToolCommandSynthesizer.synthesize_sync(nuclei_def, ctx)
    assert "-tags" in synth.args
    idx = synth.args.index("-tags")
    tags_arg = synth.args[idx + 1]
    assert "wordpress" in tags_arg
    assert "php" in tags_arg
    # WAF rate throttling
    assert "-rate-limit" in synth.args
    assert "15" in synth.args
    assert "X-Forwarded-For: 127.0.0.1" in synth.command_line


def test_nuclei_tech_stack_nodejs_spring():
    """Verify Nuclei selects Node and Spring templates."""
    nuclei_def = get_tool_definition("nuclei")
    ctx = TargetContext(
        target="https://api.target.com",
        tech_stack=["Node.js", "Spring"],
    )
    synth = AIToolCommandSynthesizer.synthesize_sync(nuclei_def, ctx)
    idx = synth.args.index("-tags")
    tags_arg = synth.args[idx + 1]
    assert "nodejs" in tags_arg or "spring" in tags_arg


# ── 4. Ffuf & Directory Fuzzing Synthesis ─────────────────────────────────────

def test_ffuf_extension_and_rate_adaptation():
    """Verify Ffuf tailors extensions to PHP backend and throttles for Akamai WAF."""
    ffuf_def = get_tool_definition("ffuf")
    assert ffuf_def is not None

    ctx = TargetContext(
        target="https://target.com",
        tech_stack=["PHP", "Laravel"],
        waf_name="Akamai",
    )
    synth = AIToolCommandSynthesizer.synthesize_sync(ffuf_def, ctx)
    assert "-e" in synth.args
    idx = synth.args.index("-e")
    assert ".php" in synth.args[idx + 1]
    assert "-rate" in synth.args
    assert "12" in synth.args  # Throttled rate for WAF
    assert "-p" in synth.args  # Delay flag


# ── 5. SQLmap & Dalfox Synthesis ──────────────────────────────────────────────

def test_sqlmap_dbms_and_tamper_adaptation():
    """Verify SQLmap selects correct DBMS and tamper evasion scripts for WAF."""
    sqlmap_def = get_tool_definition("sqlmap")
    assert sqlmap_def is not None

    ctx = TargetContext(
        target="https://target.com/item.php?id=1",
        tech_stack=["MySQL", "PHP"],
        waf_name="AWS WAF",
    )
    synth = AIToolCommandSynthesizer.synthesize_sync(sqlmap_def, ctx)
    assert "--dbms" in synth.args
    assert "mysql" in synth.args
    assert any("--tamper=" in a for a in synth.args)
    assert "--delay=1" in synth.args


def test_dalfox_waf_evasion():
    """Verify Dalfox includes WAF evasion flags when WAF is present."""
    dalfox_def = get_tool_definition("dalfox")
    assert dalfox_def is not None

    ctx = TargetContext(
        target="https://target.com/search?q=test",
        waf_name="Cloudflare",
    )
    synth = AIToolCommandSynthesizer.synthesize_sync(dalfox_def, ctx)
    assert "--waf-evasion" in synth.args
    assert "--delay" in synth.args


# ── 6. Safety Invariant Tests ────────────────────────────────────────────────

def test_safety_filter_removes_dangerous_flags():
    """Verify that dangerous destructive flags and injection tokens are removed."""
    nmap_def = get_tool_definition("nmap")
    raw_args = ["-p", "80", "--os-shell", "; rm -rf /", "-sV", "--sql-shell"]
    clean = AIToolCommandSynthesizer._sanitize_args(nmap_def, raw_args, "target.com")

    assert "--os-shell" not in clean
    assert "--sql-shell" not in clean
    assert "; rm -rf /" not in clean
    assert "-p" in clean
    assert "-sV" in clean


# ── 7. DynamicToolAgent Integration Tests ─────────────────────────────────────

def test_dynamic_tool_agent_synthesizes_command():
    """Verify DynamicToolAgent calls command synthesizer and attaches result to structured_data."""
    adapter = RealToolAdapter(force_fallback=True)
    factory = ToolAgentFactory(adapter=adapter)

    agent = factory.get_agent("nuclei")
    assert agent is not None

    ctx = TargetContext(
        target="https://portal.example.com",
        tech_stack=["WordPress", "PHP"],
        waf_name="Cloudflare",
    )

    res = agent.execute(target="https://portal.example.com", context=ctx, deliberate=False)
    assert res.success is True
    assert "ai_command_synthesis" in res.structured_data
    synth_data = res.structured_data["ai_command_synthesis"]
    assert synth_data["tool_name"] == "nuclei"
    assert "wordpress" in synth_data["command_line"]
    assert "15" in synth_data["command_line"]
