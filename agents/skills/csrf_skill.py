import re
import time
from typing import Optional, Dict, Any
import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from agents.skills.base_skill import BaseSkill, SkillResult

class CSRFSkill(BaseSkill):
    # Simple CSRF detection skill.
    # Heuristic: looks for common CSRF token parameter names ("csrf", "token", "authenticity_token")
    # and attempts to send a POST request without the token. If the request succeeds (status 200)
    # we flag a potential CSRF protection missing.
    name = "csrf_skill"
    vuln_type = "csrf"
    cwe = "CWE-352"
    owasp_top10 = "A05:2021"
    default_severity = "Medium"

    def __init__(self, proxy: Optional[str] = None, timeout: float = 12.0):
        super().__init__(proxy=proxy, timeout=timeout)
        self.token_keywords = ["csrf", "token", "authenticity_token"]

    async def run(self, target_url: str, param_name: str, **kwargs) -> SkillResult:
        if not any(kw in param_name.lower() for kw in self.token_keywords):
            return SkillResult(
                verified=False,
                vuln_type=self.vuln_type,
                title="Param not CSRF token",
                severity=self.default_severity,
                endpoint=target_url,
                param_name=param_name,
                evidence="",
            )
        async with httpx.AsyncClient(proxies=self.proxy, timeout=self.timeout, follow_redirects=True) as client:
            try:
                parsed = urlparse(target_url)
                qs = parse_qs(parsed.query)
                qs.pop(param_name, None)
                post_data = {k: v[0] for k, v in qs.items()}
                post_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
                resp = await client.post(post_url, data=post_data)
                if resp.status_code == 200:
                    return SkillResult(
                        verified=True,
                        vuln_type=self.vuln_type,
                        title="Potential CSRF vulnerability (token missing but request succeeded)",
                        severity=self.default_severity,
                        endpoint=target_url,
                        param_name=param_name,
                        evidence=resp.text[:200],
                    )
                else:
                    return SkillResult(
                        verified=False,
                        vuln_type=self.vuln_type,
                        title="CSRF token required (non‑200 response)",
                        severity=self.default_severity,
                        endpoint=target_url,
                        param_name=param_name,
                        evidence=resp.text[:200],
                    )
            except Exception as e:
                return SkillResult(
                    verified=False,
                    vuln_type=self.vuln_type,
                    title=str(e),
                    severity=self.default_severity,
                    endpoint=target_url,
                    param_name=param_name,
                    evidence="",
                )

    def can_handle(self, param_name: str, url: str = "", sample_value: str = "") -> float:
        return 0.9 if any(kw in param_name.lower() for kw in self.token_keywords) else 0.1
