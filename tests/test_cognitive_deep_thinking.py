"""
Tests for Cognitive Deep Thinking & Autonomous Reasoning Architecture.
Verifies Claude Extended Thinking & DeepSeek-R1 integration into agent execution loops,
multi-hypothesis generation, Pre-Tool and Post-Tool reflections, and Aha-moment self-correction.
"""
import pytest

from core.arsenal import ToolAgentFactory
from core.cognitive.claude_thinking_protocol import ThinkingMode
from core.cognitive.cognitive_deliberator import (
    CognitiveDeliberator,
    PreToolDeliberation,
    PostToolReflection,
    StrategicDeliberation,
)
from core.engine.omni_hunter_engine import AssessmentConfig, OmniHunterEngine
from core.engine.real_tool_adapter import RealToolAdapter


# ── 1. Cognitive Deliberator Unit Tests ───────────────────────────────────────

def test_deliberate_strategy_generates_competing_hypotheses():
    """Verify that strategic deliberation evaluates complexity and generates competing hypotheses."""
    deliberator = CognitiveDeliberator(thinking_mode=ThinkingMode.ADAPTIVE)
    delib = deliberator.deliberate_strategy(
        target="api.target.com",
        objective="Analyze authentication flow for BOLA / IDOR vulnerabilities",
        surface={"endpoints": ["/api/v1/user/10", "/api/v1/user/20"], "domains": ["api.target.com"]},
        stakes="high",
    )

    assert isinstance(delib, StrategicDeliberation)
    assert delib.complexity_score > 0.0
    assert len(delib.hypotheses) >= 2  # Anti-Premature Closure
    assert "api.target.com" in delib.inner_monologue
    assert delib.estimated_budget_tokens >= 1024

    # Check hypothesis structure
    h1 = delib.hypotheses[0]
    assert "hypothesis_id" in h1
    assert "statement" in h1
    assert "refutation_criteria" in h1


def test_deliberate_pre_tool_tailors_to_security_categories():
    """Verify pre-tool tactical reflection generates appropriate hypotheses for tool types."""
    deliberator = CognitiveDeliberator()

    # 1. Recon tool
    d_recon = deliberator.deliberate_pre_tool("subfinder", "example.com", "recon")
    assert "subdomains" in d_recon.hypothesis_tested.lower()
    assert d_recon.falsification_indicator != ""

    # 2. Port scanner
    d_port = deliberator.deliberate_pre_tool("nmap", "192.168.1.1", "port_scan")
    assert "port" in d_port.hypothesis_tested.lower()

    # 3. SQLi exploitation tool
    d_sqli = deliberator.deliberate_pre_tool("sqlmap", "http://example.com/item?id=1", "exploitation")
    assert "database" in d_sqli.hypothesis_tested.lower() or "sql" in d_sqli.hypothesis_tested.lower()


def test_reflect_post_tool_detects_waf_and_triggers_aha_moment():
    """Verify post-tool reflection flags perimeter WAF defenses and triggers self-correction."""
    deliberator = CognitiveDeliberator()

    # Case A: Normal success
    ref_ok = deliberator.reflect_post_tool(
        tool_name="katana",
        target="http://example.com",
        exit_code=0,
        stdout="https://example.com/login\nhttps://example.com/api",
        stderr="",
    )
    assert ref_ok.verdict == "CONFIRMED"
    assert ref_ok.confidence_posterior > 0.70
    assert not ref_ok.waf_or_deception_detected

    # Case B: WAF Block (DeepSeek Aha Moment)
    ref_waf = deliberator.reflect_post_tool(
        tool_name="ffuf",
        target="http://example.com/admin",
        exit_code=0,
        stdout="403 Forbidden - Cloudflare Security Check",
        stderr="",
    )
    assert ref_waf.waf_or_deception_detected
    assert ref_waf.verdict == "ANOMALOUS"
    assert ref_waf.aha_moment is not None
    assert "waf" in ref_waf.aha_moment.lower() or "perimeter" in ref_waf.aha_moment.lower()

    # Case C: Hard failure / timeout
    ref_fail = deliberator.reflect_post_tool(
        tool_name="subfinder",
        target="example.com",
        exit_code=-1,
        stdout="",
        stderr="TimeoutExpired: 60s",
    )
    assert ref_fail.verdict == "REFUTED"
    assert ref_fail.aha_moment is not None


def test_formatting_traces_are_terminal_safe():
    """Verify formatted traces contain clean readable representations."""
    deliberator = CognitiveDeliberator()
    delib = deliberator.deliberate_strategy("example.com", "Scan ports")
    trace_strat = deliberator.format_strategic_trace(delib)
    assert "[COGNITIVE REASONING ENGINE]" in trace_strat

    pre = deliberator.deliberate_pre_tool("nmap", "example.com")
    trace_pre = deliberator.format_pre_tool_trace(pre)
    assert "[PRE-TOOL THINKING]" in trace_pre

    post = deliberator.reflect_post_tool("nmap", "example.com", 0, "80/tcp open", "")
    trace_post = deliberator.format_post_tool_trace(post)
    assert "[POST-TOOL REFLECTION]" in trace_post


# ── 2. Dynamic Tool Agent Integration ────────────────────────────────────────

def test_dynamic_tool_agent_attaches_cognitive_deliberation():
    """Verify DynamicToolAgent populates cognitive deliberation in structured results."""
    adapter = RealToolAdapter(force_fallback=True)
    factory = ToolAgentFactory(adapter=adapter)
    agent = factory.get_agent("katana")

    res = agent.execute(
        target="https://example.com",
        deliberate=True,
        verbose_thinking=False,
    )

    assert res.success
    assert "cognitive_deliberation" in res.structured_data
    delib_info = res.structured_data["cognitive_deliberation"]
    assert "hypothesis_tested" in delib_info
    assert "verdict" in delib_info
    assert delib_info["verdict"] == "CONFIRMED"
    assert delib_info["confidence_posterior"] >= 0.80


# ── 3. OmniHunter Autonomous Engine Deliberation ──────────────────────────────

def test_omni_hunter_runs_with_cognitive_deliberation():
    """Verify OmniHunter assessment loop executes with deliberate strategy enabled."""
    config = AssessmentConfig(
        target_url="https://test.corp",
        scope_domains=["test.corp"],
        coverage_threshold=0.99,
        max_cycles=3,
        force_tool_fallback=True,
        enable_thinking=False,  # test execution without stdout spam
        authorized_by="Unit Test Operator",
    )
    engine = OmniHunterEngine(config)
    assert engine.deliberator is not None

    result = engine.run()
    assert result.phase_reached is not None
    assert result.engagement_id.startswith("ENG-")
