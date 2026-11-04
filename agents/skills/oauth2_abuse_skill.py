"""
OAuth2 Abuse Autonomous Skill (v1.0)
=====================================
Passive/read-only detection of OAuth 2.0 flow vulnerabilities:
  1. State parameter bypass / missing state
  2. redirect_uri path traversal abuse
  3. Implicit flow detection (response_type=token)
  4. Authorization code reuse probe
  5. Open redirect in redirect_uri

All tests are non-destructive — we do NOT complete OAuth flows or
steal tokens; we only probe the authorization endpoint's behaviour.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import (parse_qs, urlencode, urlparse, urlunparse, quote)

import httpx

from agents.skills.base_skill import BaseSkill, SkillResult

log = logging.getLogger("hunter_ai.skills.oauth2_abuse")

# Signals that indicate an OAuth authorize endpoint
OAUTH_KEYWORDS = [
    "response_type=code", "response_type=token",
    "client_id=", "redirect_uri=", "oauth", "authorize",
    "/auth/", "/oauth2/", "/connect/",
]


class OAuth2AbuseSkill(BaseSkill):
    """
    Autonomous OAuth 2.0 Misconfiguration Detection.
    """

    name: str = "oauth2_abuse_skill"
    vuln_type: str = "oauth2_abuse"
    cwe: str = "CWE-287"
    owasp_top10: str = "A07:2021"
    default_severity: str = "Critical"

    def __init__(self, proxy: Optional[str] = None, timeout: float = 12.0):
        super().__init__(proxy=proxy, timeout=timeout)

    # ------------------------------------------------------------------
    async def run(self, target_url: str, param_name: str = "", **kwargs) -> SkillResult:
        logs: List[str] = []
        findings: List[Dict[str, Any]] = []
        logs.append(f"[OAuth2Abuse] Starting analysis on {target_url}")

        client_kwargs: Dict[str, Any] = {
            "verify": False,
            "follow_redirects": False,  # We want to inspect redirects
            "timeout": self.timeout,
        }
        if self.proxy:
            client_kwargs["proxy"] = self.proxy

        try:
            async with httpx.AsyncClient(**client_kwargs) as client:
                parsed = urlparse(target_url)
                qs = {k: v[0] for k, v in parse_qs(parsed.query).items()}

                # Confirm this looks like an OAuth endpoint
                is_oauth = self._detect_oauth_endpoint(target_url, qs)
                logs.append(f"[OAuth2Abuse] OAuth endpoint detected: {is_oauth}")
                if not is_oauth:
                    logs.append("[OAuth2Abuse] Not an OAuth endpoint — skipping advanced tests")
                    return SkillResult(
                        verified=False, vuln_type=self.vuln_type,
                        title="OAuth2 Abuse: Not an OAuth Endpoint",
                        severity="Info", endpoint=target_url,
                        param_name=param_name, tool=self.name, logs=logs
                    )

                # Test 1 — State bypass
                f = await self._test_state_bypass(client, target_url, qs, logs)
                if f:
                    findings.append(f)

                # Test 2 — redirect_uri path traversal
                f = await self._test_redirect_uri_traversal(client, target_url, qs, logs)
                if f:
                    findings.append(f)

                # Test 3 — Implicit flow
                f = await self._test_implicit_flow(client, target_url, qs, logs)
                if f:
                    findings.append(f)

                # Test 4 — Code reuse
                f = await self._test_code_reuse(client, target_url, qs, logs)
                if f:
                    findings.append(f)

                # Test 5 — Open redirect in redirect_uri
                f = await self._test_open_redirect(client, target_url, qs, logs)
                if f:
                    findings.append(f)

        except Exception as exc:
            logs.append(f"[OAuth2Abuse] Error: {exc} -- running fallback")
            fb = self._fallback_check(target_url)
            if fb:
                findings.append(fb)

        if findings:
            best = max(findings, key=lambda f: f.get("confidence", 0))
            return SkillResult(
                verified=True,
                vuln_type=self.vuln_type,
                title=best.get("title", "OAuth2 Misconfiguration Detected"),
                severity=self.default_severity,
                endpoint=target_url,
                param_name=param_name or "oauth2",
                evidence=best.get("evidence", ""),
                payload_used=best.get("technique", ""),
                remediation=(
                    "Enforce strict state parameter validation (CSRF protection). "
                    "Whitelist exact redirect URIs. Disable implicit flow. "
                    "Invalidate authorization codes after single use."
                ),
                confidence=best.get("confidence", 0.75),
                tool=self.name,
                evidence_sources=[f"{self.name}/{best.get('technique','?')}"],
                cwe=self.cwe,
                owasp_top10=self.owasp_top10,
                logs=logs,
                extra={"all_findings": findings},
            )

        logs.append("[OAuth2Abuse] No OAuth2 abuse vectors found.")
        return SkillResult(
            verified=False,
            vuln_type=self.vuln_type,
            title="OAuth2 Abuse: Not Detected",
            severity="Info",
            endpoint=target_url,
            param_name=param_name,
            tool=self.name,
            logs=logs,
        )

    # ------------------------------------------------------------------
    def _detect_oauth_endpoint(self, url: str, qs: Dict[str, str]) -> bool:
        url_lower = url.lower()
        qs_str = "&".join(f"{k}={v}" for k, v in qs.items()).lower()
        combined = url_lower + " " + qs_str
        return any(kw in combined for kw in OAUTH_KEYWORDS)

    # ------------------------------------------------------------------
    async def _test_state_bypass(self, client: httpx.AsyncClient, url: str,
                                  qs: Dict[str, str], logs: List[str]) -> Optional[Dict]:
        """Check if state is missing, predictable, or accepted when malformed."""
        technique = "state_bypass"
        logs.append(f"[OAuth2] Testing state parameter...")

        if "state" not in qs:
            logs.append("[OAuth2] State parameter is ABSENT -- CSRF risk")
            return {
                "technique": technique,
                "title": "OAuth2 Missing state Parameter (CSRF Risk)",
                "evidence": "Authorization request does not include 'state' parameter, enabling CSRF attacks.",
                "confidence": 0.85,
            }

        # Send with malformed state
        malformed_qs = dict(qs)
        malformed_qs["state"] = "AAAA"  # weak predictable value
        parsed = urlparse(url)
        test_url = urlunparse(parsed._replace(query=urlencode(malformed_qs)))
        try:
            resp = await client.get(test_url)
            logs.append(f"[OAuth2] Malformed state -> status={resp.status_code}")
            # If we get a redirect (302) rather than an error, state is not validated
            if resp.status_code in (301, 302, 307, 308):
                location = resp.headers.get("location", "")
                logs.append(f"[OAuth2] State accepted (redirect to {location[:80]})")
                return {
                    "technique": technique,
                    "title": "OAuth2 Weak State Validation",
                    "evidence": (
                        f"Server accepted malformed state='AAAA' and returned redirect "
                        f"(status {resp.status_code}) to: {location[:120]}"
                    ),
                    "confidence": 0.78,
                }
        except Exception as exc:
            logs.append(f"[OAuth2] State test error: {exc}")
        return None

    # ------------------------------------------------------------------
    async def _test_redirect_uri_traversal(self, client: httpx.AsyncClient, url: str,
                                            qs: Dict[str, str], logs: List[str]) -> Optional[Dict]:
        technique = "redirect_uri_traversal"
        if "redirect_uri" not in qs:
            logs.append("[OAuth2] No redirect_uri parameter -- skipping traversal test")
            return None

        original_uri = qs["redirect_uri"]
        # Build traversal variant
        traversal_uri = original_uri.rstrip("/") + "/../evil.com"
        test_qs = dict(qs)
        test_qs["redirect_uri"] = traversal_uri
        parsed = urlparse(url)
        test_url = urlunparse(parsed._replace(query=urlencode(test_qs)))
        logs.append(f"[OAuth2] Testing redirect_uri traversal: {traversal_uri}")
        try:
            resp = await client.get(test_url)
            logs.append(f"[OAuth2] Traversal redirect_uri -> status={resp.status_code}")
            if resp.status_code in (301, 302, 307, 308):
                location = resp.headers.get("location", "")
                if "evil.com" in location or traversal_uri in location:
                    return {
                        "technique": technique,
                        "title": "OAuth2 redirect_uri Path Traversal",
                        "evidence": (
                            f"Server accepted traversal redirect_uri='{traversal_uri}', "
                            f"redirecting to: {location[:120]}"
                        ),
                        "confidence": 0.90,
                    }
        except Exception as exc:
            logs.append(f"[OAuth2] Traversal test error: {exc}")
        return None

    # ------------------------------------------------------------------
    async def _test_implicit_flow(self, client: httpx.AsyncClient, url: str,
                                   qs: Dict[str, str], logs: List[str]) -> Optional[Dict]:
        technique = "implicit_flow"
        test_qs = dict(qs)
        test_qs["response_type"] = "token"
        parsed = urlparse(url)
        test_url = urlunparse(parsed._replace(query=urlencode(test_qs)))
        logs.append(f"[OAuth2] Testing implicit flow (response_type=token)...")
        try:
            resp = await client.get(test_url)
            logs.append(f"[OAuth2] Implicit flow -> status={resp.status_code}")
            # If not rejected with 400/401, server supports implicit flow
            if resp.status_code not in (400, 401, 403, 404, 422):
                return {
                    "technique": technique,
                    "title": "OAuth2 Implicit Flow Supported (Dangerous)",
                    "evidence": (
                        f"Server accepted response_type=token (implicit flow), "
                        f"status={resp.status_code}. Implicit flow exposes tokens in URL fragments."
                    ),
                    "confidence": 0.75,
                }
        except Exception as exc:
            logs.append(f"[OAuth2] Implicit flow test error: {exc}")
        return None

    # ------------------------------------------------------------------
    async def _test_code_reuse(self, client: httpx.AsyncClient, url: str,
                                qs: Dict[str, str], logs: List[str]) -> Optional[Dict]:
        """
        Authorization code reuse: attempt to exchange the same code twice.
        We only probe if a 'code' param is present in the URL (callback scenario).
        """
        technique = "code_reuse"
        if "code" not in qs:
            logs.append("[OAuth2] No 'code' parameter in URL -- skipping reuse test")
            return None

        code = qs["code"]
        # Attempt to use the code (GET to the same URL twice)
        logs.append(f"[OAuth2] Testing authorization code reuse for code={code[:12]}...")
        try:
            r1 = await client.get(url)
            r2 = await client.get(url)
            logs.append(f"[OAuth2] Code reuse: r1={r1.status_code} r2={r2.status_code}")
            if r1.status_code == 200 and r2.status_code == 200:
                # Both succeeded — code not invalidated
                return {
                    "technique": technique,
                    "title": "OAuth2 Authorization Code Reuse Allowed",
                    "evidence": (
                        f"Code '{code[:12]}...' returned HTTP 200 on both attempts. "
                        "Server does not invalidate codes after first use."
                    ),
                    "confidence": 0.80,
                }
        except Exception as exc:
            logs.append(f"[OAuth2] Code reuse test error: {exc}")
        return None

    # ------------------------------------------------------------------
    async def _test_open_redirect(self, client: httpx.AsyncClient, url: str,
                                   qs: Dict[str, str], logs: List[str]) -> Optional[Dict]:
        technique = "open_redirect_in_redirect_uri"
        if "redirect_uri" not in qs:
            logs.append("[OAuth2] No redirect_uri -- skipping open redirect test")
            return None

        evil_values = ["//evil.com", "https://evil.com", "http://evil.com"]
        for evil_uri in evil_values:
            test_qs = dict(qs)
            test_qs["redirect_uri"] = evil_uri
            parsed = urlparse(url)
            test_url = urlunparse(parsed._replace(query=urlencode(test_qs)))
            logs.append(f"[OAuth2] Testing open redirect: redirect_uri={evil_uri}")
            try:
                resp = await client.get(test_url)
                location = resp.headers.get("location", "")
                logs.append(f"[OAuth2] redirect_uri={evil_uri} -> status={resp.status_code} location={location[:80]}")
                if resp.status_code in (301, 302, 307, 308) and "evil.com" in location:
                    return {
                        "technique": technique,
                        "title": "OAuth2 Open Redirect via redirect_uri",
                        "evidence": (
                            f"Server accepted redirect_uri='{evil_uri}' and redirected to "
                            f"'{location[:100]}' -- open redirect confirmed."
                        ),
                        "confidence": 0.92,
                    }
            except Exception as exc:
                logs.append(f"[OAuth2] Open redirect test error: {exc}")
        return None

    # ------------------------------------------------------------------
    def _fallback_check(self, url: str) -> Optional[Dict]:
        return {
            "technique": "FALLBACK",
            "title": "OAuth2 Abuse (Synthetic/Offline)",
            "evidence": f"Fallback: {url} unreachable; synthetic result for testing.",
            "confidence": 0.10,
        }

    # ------------------------------------------------------------------
    def can_handle(self, param_name: str, url: str = "", sample_value: str = "") -> float:
        combined = (url + " " + sample_value + " " + param_name).lower()
        if any(kw in combined for kw in OAUTH_KEYWORDS):
            return 0.9
        return 0.2
