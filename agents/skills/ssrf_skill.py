import re
import time
from typing import Optional, Dict, Any
import httpx
from urllib.parse import urlparse, parse_qs, urlunparse

from agents.skills.base_skill import BaseSkill, SkillResult
from enum import Enum

class SSRFState(Enum):
    INITIAL = "initial"
    COMPLETED = "completed"
    FAILED = "failed"


class SSRFSkill(BaseSkill):
    # Simple SSRF detection skill.
    # Heuristic: looks for parameter names that suggest a URL/host input ("url", "uri", "redirect", "dest", "target").
    # It attempts a GET request to the supplied value. If the request succeeds (status 200) and the
    # response appears to come from the internal network (e.g., contains "127.0.0.1" or a private IP range),
    # we flag a potential SSRF vulnerability.
    name = "ssrf_skill"
    vuln_type = "ssrf"
    cwe = "CWE-918"
    owasp_top10 = "A04:2021"
    default_severity = "High"

    def __init__(self, proxy: Optional[str] = None, timeout: float = 12.0):
        super().__init__(proxy=proxy, timeout=timeout)
        self.url_keywords = ["url", "uri", "redirect", "dest", "target"]

    async def run(self, target_url: str, param_name: str, **kwargs) -> SkillResult:
        # Skip if parameter does not look like a URL carrier
        if not any(kw in param_name.lower() for kw in self.url_keywords):
            return SkillResult(
                verified=False,
                vuln_type=self.vuln_type,
                title="Param not SSRF candidate",
                severity=self.default_severity,
                endpoint=target_url,
                param_name=param_name,
                evidence="",
            )
        async with httpx.AsyncClient(proxies=self.proxy, timeout=self.timeout, follow_redirects=True) as client:
            try:
                parsed = urlparse(target_url)
                qs = parse_qs(parsed.query)
                # Extract the payload value (if present) or use a placeholder test URL
                payload = qs.get(param_name, ["http://127.0.0.1"])[0]
                # Perform a GET request to the payload
                resp = await client.get(payload)
                # Simple internal‑network detection heuristics
                internal = any(private in resp.text for private in ["127.0.0.1", "10.", "192.168.", "172.16."])
                if resp.status_code == 200 and internal:
                    return SkillResult(
                        verified=True,
                        vuln_type=self.vuln_type,
                        title="Potential SSRF vulnerability (internal endpoint reachable)",
                        severity=self.default_severity,
                        endpoint=target_url,
                        param_name=param_name,
                        evidence=resp.text[:200],
                    )
                else:
                    return SkillResult(
                        verified=False,
                        vuln_type=self.vuln_type,
                        title="No SSRF evidence (request failed or external response)",
                        severity=self.default_severity,
                        endpoint=target_url,
                        param_name=param_name,
                        evidence=resp.text[:200] if resp else "",
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
        return 0.9 if any(kw in param_name.lower() for kw in self.url_keywords) else 0.1

# Additional symbols required by the test suite (minimal stubs)

class CloudProvider(Enum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    DIGITALOCEAN = "digitalocean"
    LOCAL_DAEMON = "local_daemon"

CLOUD_METADATA_MATRIX = {
    CloudProvider.AWS: {"metadata_url": "http://169.254.169.254/latest/meta-data/"},
    CloudProvider.GCP: {"metadata_url": "http://metadata.google.internal/"},
    CloudProvider.AZURE: {"metadata_url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01"},
    CloudProvider.DIGITALOCEAN: {"metadata_url": "http://169.254.169.254/metadata/v1/"},
    CloudProvider.LOCAL_DAEMON: {"metadata_url": "http://localhost/metadata"},
}

class SSRFFilterBypasser:
    @staticmethod
    def generate_localhost_variants(target_port: int = 80) -> list:
        port_explicit = f":{target_port}"
        return [
            "http://127.0.0.1",
            f"http://127.0.0.1{port_explicit}",
            "http://localhost",
            f"http://localhost{port_explicit}",
            "http://2130706433",
            "http://0x7f000001",
            "http://0177.0.0.1",
            "http://[::1]",
            "http://127.1",
            "http://127.0.1",
            "http://0.0.0.0",
        ]

    @staticmethod
    def generate_metadata_variants(base_url: str) -> list:
        parsed = urlparse(base_url)
        host = parsed.hostname or "169.254.169.254"
        nip_host = f"{host}.nip.io"
        nip_url = urlunparse((parsed.scheme, nip_host, parsed.path, parsed.params, parsed.query, parsed.fragment))
        return [
            base_url,
            base_url.replace("169.254.169.254", "2852039166"),
            base_url.replace("169.254.169.254", "0xa9fea9fe"),
            nip_url,
        ]

async def run_ssrf_skill(url: str, param_name: str, **kwargs) -> list:
    skill = SSRFSkill()
    result = await skill.run(url, param_name, **kwargs)
    if result.verified:
        return [{
            "type": "ssrf",
            "param_name": param_name,
            "title": result.title,
            "severity": result.severity,
            "evidence": result.evidence,
        }]
    return []
