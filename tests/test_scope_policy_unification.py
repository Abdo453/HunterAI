"""LEDGER-017 / LEDGER-018 — Scope & Policy unification (M2).

Acceptance:
  * "open by default = rejected": a default PolicyEngine, a bare
    Security-Intelligence ScopeGuard and a bare NetworkScopeGuard all DENY.
  * every ambiguous encoding of a forbidden destination (loopback / cloud
    metadata / RFC1918) is blocked by the single reference engine.
"""
from __future__ import annotations

import pytest

from core.gateway.policy_engine import PolicyEngine
from core.gateway.schemas import ActionProposal
from core.network_scope_guard import NetworkScopeGuard
from core.scope_engine import ScopePolicy, StrictScopeEngine
from core.scope_guard import ScopeGuard as LegacyScopeGuard
from agents.security_intelligence.scope_guard import ScopeGuard as SiScopeGuard
from agents.security_intelligence.schemas import ScopeRule


def _proposal(target="https://anything.example/path", tool="nmap", action="CLI_TOOL"):
    return ActionProposal(target=target, tool_name=tool, action_type=action, command_args="-sV")


def test_policy_engine_default_is_fail_closed():
    verdict = PolicyEngine().evaluate_proposal(_proposal())
    assert verdict.allowed is False
    assert verdict.status == "BLOCKED_SCOPE"


def test_policy_engine_full_permissions_is_explicit_optin():
    engine = PolicyEngine(full_permissions=True)
    verdict = engine.evaluate_proposal(_proposal(target="https://api.target.local/x"))
    assert verdict.allowed is True


def test_policy_engine_enable_full_permissions_is_explicit():
    engine = PolicyEngine()
    assert engine.evaluate_proposal(_proposal()).allowed is False
    engine.enable_full_permissions()
    assert engine.evaluate_proposal(_proposal(target="https://api.target.local/x")).allowed is True


def test_policy_engine_honours_injected_scope_guard():
    guard = SiScopeGuard(ScopeRule(
        target="api.target.local",
        allowed_domains=["api.target.local"],
        allow_active_tests=True,
    ))
    engine = PolicyEngine(scope_guard=guard)
    assert engine.evaluate_proposal(_proposal(target="https://api.target.local/x")).allowed is True
    assert engine.evaluate_proposal(_proposal(target="https://evil.example/x")).status == "BLOCKED_SCOPE"


def test_security_intelligence_scope_guard_default_is_fail_closed():
    assert SiScopeGuard().evaluate_scope_decision("api.target.local").allowed is False


@pytest.mark.parametrize("host", [
    "127.0.0.1", "127.1", "2130706433", "0x7f000001", "0177.0.0.1", "0x7f.1",
    "::1", "::ffff:127.0.0.1", "[::1]",
    "169.254.169.254", "metadata.google.internal", "instance-data",
    "10.0.0.5", "192.168.1.3", "172.16.9.9", "100.64.0.9",
])
def test_reference_engine_blocks_forbidden_destination_encodings(host):
    engine = StrictScopeEngine(ScopePolicy(allowed_targets=["example.com"]))
    allowed, reason = engine.is_allowed(host)
    assert allowed is False, host
    assert "INVARIANT" in reason


def test_reference_engine_allows_authorised_public_target():
    engine = StrictScopeEngine(ScopePolicy(allowed_targets=["example.com", "*.example.com"]))
    assert engine.is_allowed("api.example.com")[0] is True
    assert engine.is_allowed("evil.example.net")[0] is False


def test_legacy_scope_guard_delegates_to_reference_invariants():
    guard = LegacyScopeGuard(in_scope=["example.com"])
    for host in ("127.0.0.1", "2130706433", "::ffff:127.0.0.1", "169.254.169.254"):
        assert guard.is_in_scope(host)[0] is False, host
    assert guard.is_in_scope("api.example.com")[0] is True
    # Explicit literal-IP lab override is preserved.
    assert LegacyScopeGuard(in_scope=["127.0.0.1"]).is_in_scope("127.0.0.1")[0] is True


def test_network_scope_guard_default_is_fail_closed():
    assert NetworkScopeGuard().check_url("https://example.com/")[0] is False
