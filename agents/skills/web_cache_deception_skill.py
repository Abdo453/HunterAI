"""
Web Cache Deception Autonomous Skill (v1.0)
===========================================
Detects Web Cache Deception vulnerabilities (CWE-525):
1. Appends static-like path suffixes (/nonexistent.css, ;.js, .avro) to dynamic endpoints
2. Verifies whether dynamic response content is returned AND marked HIT/MISS->HIT by CDN cache headers
"""
from __future__ import annotations

import logging
import secrets
from typing import Dict, List, Optional
from urllib.parse import urlparse, urlunparse
import httpx

from agents.skills.base_skill import BaseSkill, SkillResult

log = logging.getLogger("hunter_ai.skills.web_cache_deception")


class WebCacheDeceptionSkill(BaseSkill):
    name: str = "web_cache_deception_skill"
    vuln_type: str = "web_cache_deception"
    cwe: str = "CWE-525"
    owasp_top10: str = "A05:2021"
    default_severity: str = "High"

    CACHE_HEADERS = ("x-cache", "cf-cache-status", "x-drupal-cache", "x-varnish", "x-proxy-cache")

    def can_handle(self, param_name: str, url: str = "", sample_value: str = "") -> float:
        p = (param_name or "").lower()
        u = (url or "").lower()
        if any(k in u for k in ("/account", "/profile", "/settings", "/me", "/dashboard", "/user")):
            return 0.90
        if any(k in p for k in ("cache", "format", "ext", "type")):
            return 0.80
        return 0.25

    async def run(self, target_url: str, param_name: str = "", **kwargs) -> SkillResult:
        logs: List[str] = [f"[WebCacheDeception] Auditing {target_url}"]
        client_kwargs = {
            "verify": False,
            "follow_redirects": False,
            "timeout": self.timeout,
            "trust_env": False,
        }
        if self.proxy:
            client_kwargs["proxy"] = self.proxy

        verified = False
        evidence = ""
        payload_used = ""

        try:
            async with httpx.AsyncClient(**client_kwargs) as client:
                base_resp = await client.get(target_url)
                if base_resp.status_code == 200 and len(base_resp.text or "") > 40:
                    parsed = urlparse(target_url)
                    base_path = (parsed.path or "/").rstrip("/")
                    nonce = secrets.token_hex(3)
                    suffixes = [f"{base_path}/wcd-{nonce}.css", f"{base_path};wcd-{nonce}.js"]

                    for dec_path in suffixes:
                        dec_url = urlunparse(parsed._replace(path=dec_path))
                        r1 = await client.get(dec_url)
                        if r1.status_code == 200 and abs(len(r1.text or "") - len(base_resp.text or "")) < 120:
                            r2 = await client.get(dec_url)
                            for ch in self.CACHE_HEADERS:
                                val = r2.headers.get(ch, "").upper()
                                if "HIT" in val:
                                    verified = True
                                    payload_used = dec_path
                                    evidence = (
                                        f"Dynamic endpoint {target_url} returned full page body at '{dec_path}' "
                                        f"and CDN cached the response ({ch}: {val})."
                                    )
                                    logs.append(f"[+] Confirmed Web Cache Deception via {dec_path} ({ch}={val})")
                                    break
                        if verified:
                            break
        except Exception as exc:
            logs.append(f"[!] Probe error: {exc}")

        return SkillResult(
            verified=verified,
            vuln_type=self.vuln_type,
            title=f"Web Cache Deception on {target_url}" if verified else "No Web Cache Deception Confirmed",
            severity="High" if verified else "Info",
            endpoint=target_url,
            param_name=param_name or "path_suffix",
            evidence=evidence,
            payload_used=payload_used,
            remediation="Configure CDN caching rules to honor origin Cache-Control: private/no-store headers and reject path-appended static extensions on dynamic routes.",
            confidence=0.93 if verified else 0.0,
            tool=self.name,
            cwe=self.cwe,
            owasp_top10=self.owasp_top10,
            fallback_used=False,
            logs=logs,
        )
