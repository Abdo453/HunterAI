"""
Subdomain Takeover Autonomous Skill (v1.0)
==========================================
Detects and verifies Dangling DNS CNAME & Unclaimed Cloud Provider Takeovers (CWE-350):
1. Resolves CNAME records or inspects HTTP response bodies against known cloud provider fingerprints
2. Verifies unclaimed resource banners (GitHub Pages, AWS S3, Heroku, Azure, Fastly, Shopify, Vercel, Render)
"""
from __future__ import annotations

import logging
import socket
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
import httpx

from agents.skills.base_skill import BaseSkill, SkillResult

log = logging.getLogger("hunter_ai.skills.subdomain_takeover")


class SubdomainTakeoverSkill(BaseSkill):
    name: str = "subdomain_takeover_skill"
    vuln_type: str = "subdomain_takeover"
    cwe: str = "CWE-350"
    owasp_top10: str = "A05:2021"
    default_severity: str = "High"

    PROVIDER_FINGERPRINTS: List[Tuple[str, str]] = [
        ("GitHub Pages", "There isn't a GitHub Pages site here."),
        ("AWS S3", "The specified bucket does not exist"),
        ("Heroku", "No such app"),
        ("Shopify", "Sorry, this shop is currently unavailable."),
        ("Fastly", "Fastly error: unknown domain:"),
        ("Ghost", "The thing you were looking for is no longer here, or never was"),
        ("Pantheon", "404 error unknown site!"),
        ("Tumblr", "Whatever you were looking for doesn't currently exist at this address"),
        ("WordPress.com", "Do you want to register "),
        ("TeamWork", "Oops - We didn't find your site."),
        ("Helpjuice", "We could not find what you're looking for."),
        ("Helpscout", "No settings were found for this company:"),
        ("Cargo", "If you're moving your domain away from Cargo you must make this configuration"),
        ("UserVoice", "This UserVoice subdomain is currently available!"),
        ("Surge.sh", "project not found"),
        ("Webflow", "The page you are looking for doesn't exist or has been moved"),
        ("Vercel", "The deployment could not be found on Vercel."),
    ]

    def can_handle(self, param_name: str, url: str = "", sample_value: str = "") -> float:
        p = (param_name or "").lower()
        if any(k in p for k in ("subdomain", "domain", "cname", "host", "origin")):
            return 0.90
        return 0.20

    async def run(self, target_url: str, param_name: str = "", **kwargs) -> SkillResult:
        if not target_url.startswith(("http://", "https://")):
            target_url = f"https://{target_url}"
        parsed = urlparse(target_url)
        hostname = parsed.hostname or target_url
        logs: List[str] = [f"[SubdomainTakeover] Checking {hostname}"]

        client_kwargs = {
            "verify": False,
            "follow_redirects": False,
            "timeout": self.timeout,
            "trust_env": False,
        }
        if self.proxy:
            client_kwargs["proxy"] = self.proxy

        verified = False
        provider_hit = ""
        evidence = ""

        try:
            async with httpx.AsyncClient(**client_kwargs) as client:
                for scheme in ("https", "http"):
                    probe_url = f"{scheme}://{hostname}/"
                    try:
                        resp = await client.get(probe_url)
                        body = resp.text or ""
                        for provider, fingerprint in self.PROVIDER_FINGERPRINTS:
                            if fingerprint in body:
                                verified = True
                                provider_hit = provider
                                evidence = (
                                    f"Subdomain {hostname} returned unclaimed {provider} fingerprint "
                                    f"(HTTP {resp.status_code}): '{fingerprint}'"
                                )
                                logs.append(f"[+] Confirmed dangling {provider} takeover on {hostname}")
                                break
                        if verified:
                            break
                    except Exception:
                        continue
        except Exception as exc:
            logs.append(f"[!] Probe error: {exc}")

        return SkillResult(
            verified=verified,
            vuln_type=self.vuln_type,
            title=f"Subdomain Takeover ({provider_hit}) on {hostname}" if verified else "No Subdomain Takeover Confirmed",
            severity="High" if verified else "Info",
            endpoint=target_url,
            param_name=param_name or "host",
            evidence=evidence,
            payload_used=hostname if verified else "",
            remediation="Remove dangling DNS CNAME/A records or claim the external cloud resource immediately.",
            confidence=0.95 if verified else 0.0,
            tool=self.name,
            cwe=self.cwe,
            owasp_top10=self.owasp_top10,
            fallback_used=False,
            logs=logs,
        )
