"""
Integration tests for Defense-in-Depth Scope Guard & Multi-Mode Policy
"""
import pytest
from agents.security_intelligence.scope_guard import ScopeGuard
from agents.security_intelligence.schemas import ScopeRule, ScopeMode


def test_scope_guard_multi_mode_decisions():
    rule = ScopeRule(
        target="authorized.org",
        allowed_domains=["authorized.org", "api.authorized.org"],
        excluded_paths=["/admin/delete", "/api/reset"],
        allow_active_tests=True
    )
    guard = ScopeGuard(rule)

    # 1. Passive in-scope
    dec_passive = guard.evaluate_scope_decision("https://api.authorized.org/users", action="passive_analysis")
    assert dec_passive.allowed is True
    assert dec_passive.mode == ScopeMode.PASSIVE

    # 2. Active in-scope
    dec_active = guard.evaluate_scope_decision("https://api.authorized.org/users", action="active_probe_smartpoc")
    assert dec_active.allowed is True
    assert dec_active.mode == ScopeMode.ACTIVE

    # 3. Excluded path (Blocked)
    dec_excluded = guard.evaluate_scope_decision("https://api.authorized.org/admin/delete", action="passive_analysis")
    assert dec_excluded.allowed is False
    assert dec_excluded.mode == ScopeMode.BLOCKED

    # 4. Out-of-scope domain (Blocked)
    dec_out = guard.evaluate_scope_decision("https://unauthorized-domain.com/login", action="active_probe")
    assert dec_out.allowed is False
    assert dec_out.mode == ScopeMode.BLOCKED

    # 5. Theoretical explanation on out-of-scope (Allowed as THEORETICAL)
    dec_theory = guard.evaluate_scope_decision("https://unauthorized-domain.com/login", action="theory_explanation")
    assert dec_theory.allowed is True
    assert dec_theory.mode == ScopeMode.THEORETICAL


def test_scope_guard_url_normalization():
    rule = ScopeRule(
        target="target.local",
        allowed_domains=["target.local", "api.target.local"],
        excluded_paths=["/admin/delete", "/system/reset"],
        allow_active_tests=True
    )
    guard = ScopeGuard(rule)

    # 1. Case insensitivity
    dec_case = guard.evaluate_scope_decision("HTTPS://API.TARGET.LOCAL/USERS", action="passive")
    assert dec_case.allowed is True
    assert dec_case.mode == ScopeMode.PASSIVE

    # 2. Port numbers in URL
    dec_port = guard.evaluate_scope_decision("https://api.target.local:8443/profile", action="passive")
    assert dec_port.allowed is True

    dec_port_raw = guard.evaluate_scope_decision("api.target.local:8080/items", action="passive")
    assert dec_port_raw.allowed is True

    # 3. Path traversal attempting to hit excluded path
    dec_traversal = guard.evaluate_scope_decision("https://api.target.local/public/../../admin/delete", action="passive")
    assert dec_traversal.allowed is False
    assert dec_traversal.mode == ScopeMode.BLOCKED

    # 4. URL percent-encoding attempting to hide excluded path
    dec_encoded = guard.evaluate_scope_decision("https://api.target.local/%61%64%6d%69%6e/%64%65%6c%65%74%65", action="passive")
    assert dec_encoded.allowed is False
    assert dec_encoded.mode == ScopeMode.BLOCKED

    # 5. Target with missing scheme
    dec_no_scheme = guard.evaluate_scope_decision("api.target.local/dashboard", action="passive")
    assert dec_no_scheme.allowed is True

