"""Regression tests for the policy-gate destination invariant bypass.

Defect (found by live experiment before the fix):
    A ``TERMINAL_COMMAND`` whose destination lives inside the command string
    was classified as a target-less "local exec" and skipped scope validation
    entirely, so ``curl http://169.254.169.254/latest/meta-data/`` was ALLOWED
    even though cloud metadata is a declared inviolable invariant.

These tests pin the fixed behaviour and must stay green.
"""
from __future__ import annotations

import pytest

from core.control_plane.policy_gate import (
    ActionCategory,
    ActionRequest,
    PolicyGate,
    extract_candidate_destinations,
)
from core.scope_engine import ScopePolicy, StrictScopeEngine


@pytest.fixture()
def gate() -> PolicyGate:
    engine = StrictScopeEngine(ScopePolicy(allowed_targets=["example.com"]))
    return PolicyGate(scope_policy=engine.policy, authorized=True, allow_destructive=False)


def _cmd(gate: PolicyGate, command: str):
    return gate.evaluate(
        ActionRequest(
            category=ActionCategory.TERMINAL_COMMAND,
            target="local_terminal",
            command=command,
        )
    )


class TestDestinationExtraction:
    def test_extracts_url_host_stripping_userinfo_and_port(self):
        hosts = extract_candidate_destinations(
            "curl http://user:pw@169.254.169.254:80/latest/meta-data/"
        )
        assert "169.254.169.254" in hosts

    def test_extracts_bare_ipv4(self):
        assert "8.8.8.8" in extract_candidate_destinations("nmap -sV 8.8.8.8")

    def test_extracts_known_metadata_hostname(self):
        hosts = extract_candidate_destinations("curl http://metadata.google.internal/computeMetadata/v1/")
        assert "metadata.google.internal" in hosts

    def test_does_not_treat_filesystem_paths_as_hosts(self):
        assert extract_candidate_destinations("cat /etc/passwd && ls -la /var/log") == []

    def test_does_not_match_version_like_numbers(self):
        # "1.24.0" must not be mistaken for an IPv4 address.
        assert extract_candidate_destinations("nginx/1.24.0 --version") == []

    def test_sentinels_are_returned_but_filtered_by_the_gate(self):
        assert extract_candidate_destinations("local_terminal") == []


class TestInviolableDestinationsInsideCommands:
    def test_cloud_metadata_via_terminal_command_is_denied(self, gate):
        decision = _cmd(gate, "curl http://169.254.169.254/latest/meta-data/")
        assert decision.allowed is False
        assert "169.254" in decision.reason

    def test_metadata_hostname_via_terminal_command_is_denied(self, gate):
        decision = _cmd(gate, "curl http://metadata.google.internal/computeMetadata/v1/")
        assert decision.allowed is False

    def test_loopback_via_terminal_command_is_denied(self, gate):
        decision = _cmd(gate, "curl http://127.0.0.1:8085/health")
        assert decision.allowed is False

    def test_loopback_hostname_via_terminal_command_is_denied(self, gate):
        decision = _cmd(gate, "wget http://localhost/admin")
        assert decision.allowed is False

    def test_reserved_range_via_terminal_command_is_denied(self, gate):
        decision = _cmd(gate, "ping 240.0.0.1")
        assert decision.allowed is False


class TestExistingBehaviourPreserved:
    def test_destructive_command_still_denied(self, gate):
        decision = _cmd(gate, "rm -rf / --no-preserve-root")
        assert decision.allowed is False
        assert "Destructive" in decision.reason or "INVARIANT" in decision.reason

    def test_harmless_local_command_still_allowed(self, gate):
        decision = _cmd(gate, "ls -la /tmp && cat /etc/hostname")
        assert decision.allowed is True

    def test_in_scope_http_request_still_allowed(self, gate):
        decision = gate.evaluate(
            ActionRequest(category=ActionCategory.HTTP_REQUEST, target="http://example.com/")
        )
        assert decision.allowed is True

    def test_out_of_scope_http_request_still_denied(self, gate):
        decision = gate.evaluate(
            ActionRequest(category=ActionCategory.HTTP_REQUEST, target="http://evil.example.net/")
        )
        assert decision.allowed is False
        assert "OUT OF SCOPE" in decision.reason.upper() or "outside authorized scope" in decision.reason


class TestScopeFileLoading:
    def test_from_file_missing_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            StrictScopeEngine.from_file(tmp_path / "nope.json")

    def test_from_file_json(self, tmp_path):
        p = tmp_path / "scope.json"
        p.write_text('{"allowed_targets": ["example.com"], "rate_limit_rps": 3.5}', encoding="utf-8")
        engine = StrictScopeEngine.from_file(p)
        assert engine.policy.rate_limit_rps == 3.5
        assert engine.is_allowed("example.com")[0] is True

    def test_from_file_yaml_with_nested_scope_key(self, tmp_path):
        p = tmp_path / "scope.yaml"
        p.write_text("scope:\n  allowed_targets:\n    - example.com\n", encoding="utf-8")
        engine = StrictScopeEngine.from_file(p)
        assert engine.is_allowed("example.com")[0] is True

    def test_from_file_directory_raises(self, tmp_path):
        with pytest.raises(ValueError):
            StrictScopeEngine.from_file(tmp_path)
