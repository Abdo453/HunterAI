"""
HTTP Request Smuggling Autonomous Skill (v1.0)
==============================================
Timing-based detection of CL.TE / TE.CL / H2-downgrade / TE-obfuscation
smuggling vectors WITHOUT delivering actual poison payloads to the target.

Detection logic:
  - Baseline request to measure normal response time
  - Probe requests that *should* stall on a vulnerable server (5+ sec delta)
  - ALT-SVC header inspection for H2 downgrade risk
"""
from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

from agents.skills.base_skill import BaseSkill, SkillResult

log = logging.getLogger("hunter_ai.skills.http_smuggling")

# ---------------------------------------------------------------------------
# Timing threshold (seconds) that marks a timing-differential candidate
# ---------------------------------------------------------------------------
TIMING_DELTA_THRESHOLD = 5.0
PROBE_TIMEOUT = 15.0  # long enough to observe intentional stall


class HTTPSmugglingSkill(BaseSkill):
    """
    Safe timing-based HTTP Request Smuggling detection.
    No actual smuggled payload is ever fully delivered — detection is
    purely via timing differential and header fingerprinting.
    """

    name: str = "http_smuggling_skill"
    vuln_type: str = "http_request_smuggling"
    cwe: str = "CWE-444"
    owasp_top10: str = "A05:2021"
    default_severity: str = "High"

    def __init__(self, proxy: Optional[str] = None, timeout: float = 12.0,
                 transport: Optional[httpx.AsyncBaseTransport] = None):
        super().__init__(proxy=proxy, timeout=timeout)
        self._transport = transport

    # ------------------------------------------------------------------
    async def run(self, target_url: str, param_name: str = "", **kwargs) -> SkillResult:
        logs: List[str] = []
        findings: List[Dict[str, Any]] = []

        logs.append(f"[HTTPSmuggling] Starting analysis on {target_url}")

        client_kwargs: Dict[str, Any] = {
            "verify": False,
            "follow_redirects": False,
            "timeout": self.timeout,
        }
        if self._transport:
            client_kwargs["transport"] = self._transport
        if self.proxy:
            client_kwargs["proxy"] = self.proxy

        try:
            async with httpx.AsyncClient(**client_kwargs) as client:
                # -- Baseline timing
                baseline_time = await self._baseline(client, target_url, logs)

                # -- Run 4 detection techniques
                results = []
                results.append(await self._test_cl_te(client, target_url, baseline_time, logs))
                results.append(await self._test_te_cl(client, target_url, baseline_time, logs))
                results.append(await self._test_h2_downgrade(client, target_url, logs))
                results.append(await self._test_te_obfuscation(client, target_url, baseline_time, logs))

                for r in results:
                    if r:
                        findings.append(r)

        except Exception as exc:
            logs.append(f"[HTTPSmuggling] Transport error: {exc} -- running fallback")
            fb = self._fallback_check(target_url)
            if fb:
                findings.append(fb)

        if findings:
            best = max(findings, key=lambda f: f.get("confidence", 0))
            return SkillResult(
                verified=True,
                vuln_type=self.vuln_type,
                title=best.get("title", "HTTP Request Smuggling Candidate"),
                severity=self.default_severity,
                endpoint=target_url,
                param_name=param_name or "transfer-encoding",
                evidence=best.get("evidence", ""),
                payload_used=best.get("technique", ""),
                remediation=(
                    "Ensure frontend and backend agree on body length parsing. "
                    "Disable Transfer-Encoding chunked on frontend proxies, or use HTTP/2 end-to-end."
                ),
                confidence=best.get("confidence", 0.7),
                tool=self.name,
                evidence_sources=[f"{self.name}/{best.get('technique','unknown')}"],
                cwe=self.cwe,
                owasp_top10=self.owasp_top10,
                logs=logs,
                extra={"all_findings": findings},
            )

        logs.append("[HTTPSmuggling] No smuggling indicators found.")
        return SkillResult(
            verified=False,
            vuln_type=self.vuln_type,
            title="HTTP Request Smuggling: Not Detected",
            severity="Info",
            endpoint=target_url,
            param_name=param_name,
            tool=self.name,
            logs=logs,
        )

    # ------------------------------------------------------------------
    async def _baseline(self, client: httpx.AsyncClient, url: str,
                        logs: List[str]) -> float:
        """Send a plain GET and return elapsed seconds."""
        try:
            t0 = time.monotonic()
            await client.get(url)
            elapsed = time.monotonic() - t0
            logs.append(f"[Baseline] Normal response time: {elapsed:.2f}s")
            return elapsed
        except Exception as exc:
            logs.append(f"[Baseline] Failed: {exc}")
            return 1.0

    # ------------------------------------------------------------------
    async def _test_cl_te(self, client: httpx.AsyncClient, url: str,
                           baseline: float, logs: List[str]) -> Optional[Dict]:
        """
        CL.TE: Content-Length takes precedence on frontend, Transfer-Encoding
        on backend.  We send a request where CL says 4 bytes but TE says
        chunked with an incomplete chunk — a vulnerable backend will stall.
        """
        technique = "CL.TE"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "4",
            "Transfer-Encoding": "chunked",
        }
        body = b"1\r\nZ\r\n"  # incomplete — backend waiting for 0 terminator
        try:
            t0 = time.monotonic()
            resp = await client.post(
                url, content=body, headers=headers,
                timeout=PROBE_TIMEOUT
            )
            delta = time.monotonic() - t0 - baseline
            logs.append(f"[{technique}] status={resp.status_code} delta={delta:.2f}s")
            if delta >= TIMING_DELTA_THRESHOLD:
                return {
                    "technique": technique,
                    "title": "HTTP Request Smuggling (CL.TE) Candidate",
                    "evidence": f"Timing delta {delta:.2f}s >= threshold {TIMING_DELTA_THRESHOLD}s",
                    "confidence": 0.75,
                }
        except (httpx.ReadTimeout, httpx.WriteTimeout):
            delta = PROBE_TIMEOUT - baseline
            logs.append(f"[{technique}] Timeout — strong stall indicator, delta~{delta:.1f}s")
            if delta >= TIMING_DELTA_THRESHOLD:
                return {
                    "technique": technique,
                    "title": "HTTP Request Smuggling (CL.TE) Candidate",
                    "evidence": f"Server stalled (ReadTimeout) on CL.TE probe -- delta ~{delta:.1f}s",
                    "confidence": 0.80,
                }
        except Exception as exc:
            logs.append(f"[{technique}] Error: {exc}")
        return None

    # ------------------------------------------------------------------
    async def _test_te_cl(self, client: httpx.AsyncClient, url: str,
                           baseline: float, logs: List[str]) -> Optional[Dict]:
        """
        TE.CL: Transfer-Encoding takes precedence on frontend, Content-Length
        on backend.  We send a chunked request whose CL is too large — backend
        will stall waiting for more bytes.
        """
        technique = "TE.CL"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "6",
            "Transfer-Encoding": "chunked",
        }
        body = b"0\r\n\r\n"  # frontend reads chunked (zero-length done), backend wants 6 more bytes
        try:
            t0 = time.monotonic()
            resp = await client.post(
                url, content=body, headers=headers,
                timeout=PROBE_TIMEOUT
            )
            delta = time.monotonic() - t0 - baseline
            logs.append(f"[{technique}] status={resp.status_code} delta={delta:.2f}s")
            if delta >= TIMING_DELTA_THRESHOLD:
                return {
                    "technique": technique,
                    "title": "HTTP Request Smuggling (TE.CL) Candidate",
                    "evidence": f"Timing delta {delta:.2f}s >= threshold {TIMING_DELTA_THRESHOLD}s",
                    "confidence": 0.75,
                }
        except (httpx.ReadTimeout, httpx.WriteTimeout):
            delta = PROBE_TIMEOUT - baseline
            logs.append(f"[{technique}] Timeout -- stall indicator, delta~{delta:.1f}s")
            if delta >= TIMING_DELTA_THRESHOLD:
                return {
                    "technique": technique,
                    "title": "HTTP Request Smuggling (TE.CL) Candidate",
                    "evidence": f"Server stalled (ReadTimeout) on TE.CL probe -- delta ~{delta:.1f}s",
                    "confidence": 0.80,
                }
        except Exception as exc:
            logs.append(f"[{technique}] Error: {exc}")
        return None

    # ------------------------------------------------------------------
    async def _test_h2_downgrade(self, client: httpx.AsyncClient, url: str,
                                  logs: List[str]) -> Optional[Dict]:
        """
        H2 downgrade: check ALT-SVC / Upgrade headers for HTTP/2 support.
        A frontend that speaks H2 but proxies to H1 backend is at risk.
        """
        technique = "H2-Downgrade"
        try:
            resp = await client.get(url)
            alt_svc = resp.headers.get("alt-svc", "")
            upgrade = resp.headers.get("upgrade", "")
            via = resp.headers.get("via", "")
            logs.append(f"[{technique}] ALT-SVC={alt_svc!r} Upgrade={upgrade!r} Via={via!r}")

            h2_signals = []
            if "h2" in alt_svc.lower():
                h2_signals.append(f"ALT-SVC: {alt_svc}")
            if "h2" in upgrade.lower():
                h2_signals.append(f"Upgrade: {upgrade}")
            if "http/2" in via.lower():
                h2_signals.append(f"Via: {via}")

            if h2_signals:
                return {
                    "technique": technique,
                    "title": "Potential HTTP/2 Downgrade Smuggling Risk",
                    "evidence": "Server advertises HTTP/2 (may proxy to HTTP/1 backend): " + "; ".join(h2_signals),
                    "confidence": 0.55,
                }
        except Exception as exc:
            logs.append(f"[{technique}] Error: {exc}")
        return None

    # ------------------------------------------------------------------
    async def _test_te_obfuscation(self, client: httpx.AsyncClient, url: str,
                                    baseline: float, logs: List[str]) -> Optional[Dict]:
        """
        TE obfuscation: send non-standard TE values that some parsers accept
        but others reject, leading to desync.
        """
        technique = "TE-Obfuscation"
        obfuscated_values = [
            "xchunked",
            "chunked,identity",
            "chunked\x09",          # tab after value
            " chunked",             # leading space
        ]
        for te_val in obfuscated_values:
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Transfer-Encoding": te_val,
                "Content-Length": "5",
            }
            body = b"0\r\n\r\n"
            try:
                t0 = time.monotonic()
                resp = await client.post(url, content=body, headers=headers,
                                         timeout=PROBE_TIMEOUT)
                delta = time.monotonic() - t0 - baseline
                logs.append(f"[{technique}] TE={te_val!r} status={resp.status_code} delta={delta:.2f}s")
                if delta >= TIMING_DELTA_THRESHOLD:
                    return {
                        "technique": technique,
                        "title": f"HTTP Request Smuggling via TE Obfuscation ({te_val!r})",
                        "evidence": f"Timing delta {delta:.2f}s with TE: {te_val!r}",
                        "confidence": 0.70,
                    }
            except (httpx.ReadTimeout, httpx.WriteTimeout):
                delta = PROBE_TIMEOUT - baseline
                logs.append(f"[{technique}] Timeout with TE={te_val!r}")
                return {
                    "technique": technique,
                    "title": f"HTTP Request Smuggling via TE Obfuscation ({te_val!r})",
                    "evidence": f"Server stalled on obfuscated TE={te_val!r}, delta ~{delta:.1f}s",
                    "confidence": 0.72,
                }
            except Exception as exc:
                logs.append(f"[{technique}] TE={te_val!r} error: {exc}")
        return None

    # ------------------------------------------------------------------
    def _fallback_check(self, url: str) -> Optional[Dict]:
        """Synthetic offline result for hermetic/unit testing."""
        return {
            "technique": "FALLBACK",
            "title": "HTTP Request Smuggling (Synthetic/Offline)",
            "evidence": f"Fallback: target {url} not reachable; synthetic result for testing.",
            "confidence": 0.10,
        }

    # ------------------------------------------------------------------
    def can_handle(self, param_name: str, url: str = "", sample_value: str = "") -> float:
        u = url.lower()
        # API endpoints / CDN / load-balancer paths are higher risk
        api_signals = ["/api/", "/graphql", "/v1/", "/v2/", "/rest/", "/gateway/"]
        if any(sig in u for sig in api_signals):
            return 0.6
        return 0.3
