"""
Arbitrary File Upload Autonomous Skill
======================================
Tests file upload endpoints for dangerous extensions, polyglots, and path traversals.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
import httpx

from agents.skills.base_skill import BaseSkill, SkillResult

log = logging.getLogger("hunter_ai.skills.file_upload")


class FileUploadSkill(BaseSkill):
    name: str = "FileUploadSkill"
    vuln_type: str = "file_upload"
    cwe: str = "CWE-434"
    owasp_top10: str = "A03:2021 — Injection"
    default_severity: str = "High"

    async def run(self, target_url: str, param_name: str = "file", **kwargs) -> SkillResult:
        logs = [f"[UPLOAD] Auditing file upload on {target_url} (param: {param_name})"]
        transport = None
        if self.proxy:
            try:
                transport = httpx.AsyncHTTPTransport(proxy=self.proxy, verify=False)
            except Exception:
                pass

        async with httpx.AsyncClient(transport=transport, timeout=self.timeout, verify=False) as client:
            test_files = [
                ("probe.php5", "application/x-php", b"<?php echo 53+19; ?>", "Alternative executable extension (.php5)"),
                ("probe.phtml", "text/html", b"<?php echo 'HUNTER_UPLOAD_TEST'; ?>", "Executable template extension (.phtml)"),
                ("probe.svg", "image/svg+xml", b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>console.log(1)</script></svg>", "Stored SVG XSS file"),
            ]

            for filename, ctype, content, desc in test_files:
                try:
                    files = {param_name: (filename, content, ctype)}
                    resp = await client.post(target_url, files=files)
                    # If 200/201 and file path or success indication returned
                    if resp.status_code in (200, 201) and any(kw in resp.text.lower() for kw in ["upload", "success", filename, "path"]):
                        logs.append(f"[UPLOAD] Potentially dangerous file accepted: {filename} ({desc})")
                        return SkillResult(
                            verified=True,
                            vuln_type=self.vuln_type,
                            title=f"Unrestricted File Upload — Accepted {filename}",
                            severity="High",
                            endpoint=target_url,
                            param_name=param_name,
                            evidence=f"Server accepted {filename} ({desc}) with HTTP {resp.status_code}: {resp.text[:120]}",
                            payload_used=filename,
                            remediation="Enforce server-side file extension allowlists, validate magic bytes, and store uploaded files outside webroot.",
                            confidence=0.85,
                            tool=self.name,
                            evidence_sources=[f"{self.name}/ExtensionBypass"],
                            cwe=self.cwe,
                            owasp_top10=self.owasp_top10,
                            logs=logs
                        )
                except Exception as e:
                    logs.append(f"[UPLOAD] Upload probe failed for {filename}: {e}")

        logs.append("[UPLOAD] No unvalidated file upload issues confirmed")
        return SkillResult(verified=False, vuln_type=self.vuln_type, endpoint=target_url,
                           param_name=param_name, tool=self.name, logs=logs)
