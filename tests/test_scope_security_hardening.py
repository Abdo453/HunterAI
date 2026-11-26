"""Security hardening regression tests for scope guard, scope engine, SSRF helpers, and governance mode."""

from __future__ import annotations

import socket
import pytest

from core.scope_engine import ScopePolicy, StrictScopeEngine, validate_http_url_target
from core.scope_guard import ScopeGuard
from core.security_mode import set_unrestricted, unrestricted_mode, web_governance_enforced


class TestScopeGuardHardening:
    def test_169_254_metadata_never_overridable_even_in_in_scope(self, monkeypatch):
        monkeypatch.setenv("HUNTER_UNRESTRICTED", "0")
        guard = ScopeGuard(
            in_scope=["169.254.169.254", "169.254.0.0/16", "127.0.0.1", "example.com"]
        )
        ok_meta, reason_meta = guard.is_in_scope("169.254.169.254")
        assert ok_meta is False
        assert "169.254" in reason_meta

        ok_other_ll, _ = guard.is_in_scope("http://169.254.1.10/health")
        assert ok_other_ll is False

        ok_mapped, _ = guard.is_in_scope("http://[::ffff:169.254.169.254]/latest/meta-data/")
        assert ok_mapped is False

        # Explicit 127.0.0.1 lab override continues working while metadata stays blocked
        ok_loopback, _ = guard.is_in_scope("http://127.0.0.1:8080/api")
        assert ok_loopback is True

        ok_domain, _ = guard.is_in_scope("https://example.com/v1")
        assert ok_domain is True

    def test_ipv6_cidr_allow_and_out_of_scope_block(self, monkeypatch):
        monkeypatch.setenv("HUNTER_UNRESTRICTED", "0")
        guard = ScopeGuard(
            in_scope=["2001:db8:abcd::/48"],
            out_of_scope=["2001:db8:abcd:dead::/64"],
        )
        ok_in, _ = guard.is_in_scope("https://[2001:db8:abcd:1::42]:8443/api")
        assert ok_in is True

        ok_excluded, _ = guard.is_in_scope("[2001:db8:abcd:dead::5]")
        assert ok_excluded is False

        ok_outside, _ = guard.is_in_scope("2001:db8:9999::1")
        assert ok_outside is False

    def test_fail_closed_behavior_on_empty_in_scope(self, monkeypatch):
        monkeypatch.setenv("HUNTER_UNRESTRICTED", "0")
        permissive_guard = ScopeGuard(in_scope=[])
        ok_perm, _ = permissive_guard.is_in_scope("https://example.com")
        assert ok_perm is True

        strict_guard = ScopeGuard(in_scope=[], fail_closed=True)
        ok_strict, reason_strict = strict_guard.is_in_scope("https://example.com")
        assert ok_strict is False
        assert "fail-closed" in reason_strict.lower()


class TestScopeEnginePathNormalizationAndSSRF:
    @pytest.mark.parametrize(
        "url",
        [
            "https://example.com/api/../logout",
            "https://example.com/%6cogout",
            "https://example.com/v1/%2e%2e/reset-db",
            "https://example.com/%256cogout",
            "example.com/app/../delete_account",
        ],
    )
    def test_excluded_paths_normalized_against_encoding_and_traversal(self, monkeypatch, url):
        monkeypatch.setenv("HUNTER_UNRESTRICTED", "0")
        engine = StrictScopeEngine(ScopePolicy(allowed_targets=["example.com"]))
        ok, reason = engine.is_allowed(url)
        assert ok is False, f"Expected {url!r} to be blocked by excluded_paths normalization"
        assert "excluded" in reason.lower()

    def test_safe_paths_still_allowed(self, monkeypatch):
        monkeypatch.setenv("HUNTER_UNRESTRICTED", "0")
        engine = StrictScopeEngine(ScopePolicy(allowed_targets=["example.com"]))
        ok, _ = engine.is_allowed("https://example.com/api/v1/users/profile")
        assert ok is True

    @pytest.mark.parametrize(
        "url",
        [
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/_INFO",
            "ftp://example.com/archive.tar.gz",
            "javascript:alert(1)",
            "//evil.example.com/ssrf",
            "https://example.com\\@169.254.169.254/",
        ],
    )
    def test_validate_http_url_target_blocks_non_http_schemes_even_when_unrestricted(self, monkeypatch, url):
        monkeypatch.setenv("HUNTER_UNRESTRICTED", "1")
        ok, _ = validate_http_url_target(url, resolve_dns=False)
        assert ok is False

    @pytest.mark.parametrize(
        "url",
        [
            "http://169.254.169.254/latest/meta-data/",
            "http://[::ffff:169.254.169.254]/latest/meta-data/",
            "http://2852039166/latest/meta-data/",
            "http://0xa9fea9fe/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://100.100.100.200/latest/meta-data/",
            "http://10.0.0.1/admin",
            "http://172.16.10.2/",
            "http://192.168.1.1/",
            "http://0.0.0.0:8000/",
            "http://127.0.0.1:8000/",
            "http://[::1]:8000/",
            "http://localhost:8000/",
            "http://2130706433:8000/",
        ],
    )
    def test_validate_http_url_target_blocks_metadata_and_internal_ips(self, monkeypatch, url):
        monkeypatch.setenv("HUNTER_UNRESTRICTED", "1")
        ok, _ = validate_http_url_target(
            url,
            in_scope=["169.254.169.254", "169.254.0.0/16", "10.0.0.0/8", "127.0.0.1", "localhost"],
            allow_loopback=False,
            resolve_dns=False,
        )
        assert ok is False, f"Expected internal/metadata URL {url!r} to be blocked"

    def test_validate_http_url_target_lab_loopback_requires_allow_flag_and_explicit_allowlist(self, monkeypatch):
        monkeypatch.setenv("HUNTER_UNRESTRICTED", "1")
        # allow_loopback=True WITHOUT loopback in in_scope -> still blocked
        ok_no_allowlist, _ = validate_http_url_target(
            "http://127.0.0.1:8080/api",
            in_scope=["example.com"],
            allow_loopback=True,
            resolve_dns=False,
        )
        assert ok_no_allowlist is False

        ok_empty_allowlist, _ = validate_http_url_target(
            "http://127.0.0.1:8080/api",
            in_scope=None,
            allow_loopback=True,
            resolve_dns=False,
        )
        assert ok_empty_allowlist is False

        # allow_loopback=True WITH explicit loopback entry -> allowed
        ok_lab, _ = validate_http_url_target(
            "http://127.0.0.1:8080/api",
            in_scope=["127.0.0.1"],
            allow_loopback=True,
            resolve_dns=False,
        )
        assert ok_lab is True

        # 169.254.0.0/16 stays blocked even when allow_loopback=True and in in_scope
        ok_meta, _ = validate_http_url_target(
            "http://169.254.169.254/latest/meta-data/",
            in_scope=["127.0.0.1", "169.254.169.254"],
            allow_loopback=True,
            resolve_dns=False,
        )
        assert ok_meta is False

    def test_validate_http_url_target_blocks_dns_rebind_to_inviolable_or_loopback(self, monkeypatch):
        monkeypatch.setenv("HUNTER_UNRESTRICTED", "1")

        def fake_getaddrinfo_meta(host, port, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", port))]

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo_meta)
        ok_meta, reason_meta = validate_http_url_target(
            "https://rebind.example.com/callback",
            in_scope=["*.example.com", "127.0.0.1"],
            allow_loopback=True,
            resolve_dns=True,
        )
        assert ok_meta is False
        assert "169.254" in reason_meta

        def fake_getaddrinfo_loopback(host, port, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo_loopback)
        ok_rebind_lb, _ = validate_http_url_target(
            "https://rebind.example.com/callback",
            in_scope=["*.example.com", "127.0.0.1"],
            allow_loopback=True,
            resolve_dns=True,
        )
        assert ok_rebind_lb is False

        def fake_getaddrinfo_public(host, port, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo_public)
        ok_pub, _ = validate_http_url_target(
            "https://api.example.com/v1/health",
            in_scope=["*.example.com"],
            resolve_dns=True,
        )
        assert ok_pub is True


class TestSecurityModeWebGovernance:
    def test_web_governance_enforced_by_default_even_when_cli_unrestricted(self, monkeypatch):
        monkeypatch.delenv("HUNTER_WEB_UNRESTRICTED", raising=False)
        monkeypatch.delenv("HUNTER_UNRESTRICTED", raising=False)
        assert unrestricted_mode() is True
        assert web_governance_enforced() is True

        set_unrestricted(True)
        assert unrestricted_mode() is True
        assert web_governance_enforced() is True

    @pytest.mark.parametrize("truthy", ["1", "true", "TRUE", "yes", "on"])
    def test_web_governance_respects_explicit_hunter_web_unrestricted(self, monkeypatch, truthy):
        monkeypatch.setenv("HUNTER_WEB_UNRESTRICTED", truthy)
        assert web_governance_enforced() is False

    @pytest.mark.parametrize("falsy", ["0", "false", "no", "off", ""])
    def test_web_governance_stays_enforced_for_falsy_or_empty(self, monkeypatch, falsy):
        monkeypatch.setenv("HUNTER_WEB_UNRESTRICTED", falsy)
        assert web_governance_enforced() is True

    def test_strict_scope_adapter_lab_overrides_and_non_overridable_metadata(self, monkeypatch):
        from core.copilot_service import evaluate_action_policy

        monkeypatch.setenv("HUNTER_UNRESTRICTED", "0")
        monkeypatch.delenv("HUNTER_WEB_UNRESTRICTED", raising=False)
        monkeypatch.delenv("HUNTER_ALLOW_LOCALHOST_SCOPE", raising=False)
        monkeypatch.delenv("HUNTER_ALLOW_PRIVATE_LAB_SCOPE", raising=False)

        # Default denies localhost & private IP even when present in in_scope
        assert evaluate_action_policy(action_type="CLI_TOOL", target="http://localhost:3000", in_scope=["localhost"])["allowed"] is False
        assert evaluate_action_policy(action_type="CLI_TOOL", target="http://192.168.1.50:8080", in_scope=["192.168.1.50"])["allowed"] is False

        # HUNTER_ALLOW_LOCALHOST_SCOPE=1 allows explicit localhost, keeps metadata blocked
        monkeypatch.setenv("HUNTER_ALLOW_LOCALHOST_SCOPE", "1")
        assert evaluate_action_policy(action_type="CLI_TOOL", target="http://localhost:3000", in_scope=["localhost"])["allowed"] is True
        assert evaluate_action_policy(action_type="CLI_TOOL", target="http://metadata.google.internal/", in_scope=["metadata.google.internal", "localhost"])["allowed"] is False

        # HUNTER_ALLOW_PRIVATE_LAB_SCOPE=1 allows explicit RFC1918 IP/CIDR, keeps metadata & unscoped private IPs blocked
        monkeypatch.setenv("HUNTER_ALLOW_PRIVATE_LAB_SCOPE", "1")
        assert evaluate_action_policy(action_type="CLI_TOOL", target="http://10.10.10.5:8080", in_scope=["10.10.10.0/24"])["allowed"] is True
        assert evaluate_action_policy(action_type="CLI_TOOL", target="http://192.168.1.99:8080", in_scope=["10.10.10.0/24"])["allowed"] is False
        assert evaluate_action_policy(action_type="CLI_TOOL", target="http://100.100.100.200/latest", in_scope=["100.64.0.0/10"])["allowed"] is False
        assert evaluate_action_policy(action_type="CLI_TOOL", target="fd00:ec2::254", in_scope=["fd00:ec2::254"])["allowed"] is False
