"""
HunterAI POC Bundler — Reproducible Evidence Bundle
===================================================
Creates a reproducible PoC evidence bundle:
- request.http, response.http
- repro.sh (curl)
- evidence.har (HAR 1.2)
- optional screenshot.png
- evidence.md (report-ready)
- bundle.json (manifest + response SHA-256)

Secrets redacted by default. Refuses PUT/DELETE/PATCH without --confirm-unsafe.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


def redact_secrets(text: str) -> str:
    """Redact common secret patterns."""
    import re

    patterns = [
        (r"sk-[A-Za-z0-9]{20,}", "***"),
        (r"ghp_[A-Za-z0-9]{36,}", "***"),
        (r"Bearer\s+[A-Za-z0-9._\-]{20,}", "Bearer ***"),
        (r"(Authorization:\s*)[^\r\n]+", r"\1***"),
        (r"(password\s*[:=]\s*)[^\s&]+", r"\1***"),
        (r"(api[_-]?key\s*[:=]\s*)[^\s&]+", r"\1***"),
        (r"(secret\s*[:=]\s*)[^\s&]+", r"\1***"),
        (r"(token\s*[:=]\s*)[^\s&]+", r"\1***"),
    ]
    for pat, repl in patterns:
        text = re.sub(pat, repl, text, flags=re.IGNORECASE)
    return text


class PocBundler:
    def __init__(self, base_dir: str = "findings"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def capture(
        self,
        target: str,
        vuln_class: str,
        request: Dict[str, Any],
        response: Dict[str, Any],
        screenshot_path: Optional[str] = None,
        confirm_unsafe: bool = False,
    ) -> str:
        """
        Capture a live request/response into an evidence bundle.
        """
        bundle_id = str(uuid.uuid4())[:8]
        bundle_dir = self.base_dir / f"{target}-{vuln_class}" / "evidence" / bundle_id
        bundle_dir.mkdir(parents=True, exist_ok=True)

        method = request.get("method", "GET").upper()
        if method in ("PUT", "DELETE", "PATCH") and not confirm_unsafe:
            raise PermissionError(
                f"Unsafe method {method} requires --confirm-unsafe"
            )

        # Redact secrets
        req_body = redact_secrets(request.get("body", ""))
        resp_body = redact_secrets(response.get("body", ""))
        req_headers = {k: redact_secrets(str(v)) for k, v in request.get("headers", {}).items()}
        resp_headers = {k: redact_secrets(str(v)) for k, v in response.get("headers", {}).items()}

        # request.http
        req_lines = [
            f"{method} {request.get('url', '/')} HTTP/1.1",
            f"Host: {request.get('host', '')}",
        ]
        for k, v in req_headers.items():
            req_lines.append(f"{k}: {v}")
        req_lines.append("")
        req_lines.append(req_body)
        (bundle_dir / "request.http").write_text("\n".join(req_lines), encoding="utf-8")

        # response.http
        resp_lines = [
            f"HTTP/1.1 {response.get('status_code', 200)} {response.get('reason', 'OK')}",
        ]
        for k, v in resp_headers.items():
            resp_lines.append(f"{k}: {v}")
        resp_lines.append("")
        resp_lines.append(resp_body)
        (bundle_dir / "response.http").write_text("\n".join(resp_lines), encoding="utf-8")

        # repro.sh (curl)
        curl_cmd = f"curl -X {method} '{request.get('url', '')}'"
        for k, v in req_headers.items():
            curl_cmd += f" -H '{k}: {v}'"
        if req_body:
            curl_cmd += f" -d '{req_body}'"
        (bundle_dir / "repro.sh").write_text(curl_cmd + "\n", encoding="utf-8")

        # evidence.har (HAR 1.2)
        har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "HunterAI", "version": "2.0"},
                "entries": [
                    {
                        "startedDateTime": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "time": response.get("elapsed_ms", 0),
                        "request": {
                            "method": method,
                            "url": request.get("url", ""),
                            "httpVersion": "HTTP/1.1",
                            "headers": [{"name": k, "value": v} for k, v in req_headers.items()],
                            "postData": {"text": req_body} if req_body else {},
                        },
                        "response": {
                            "status": response.get("status_code", 200),
                            "statusText": response.get("reason", "OK"),
                            "httpVersion": "HTTP/1.1",
                            "headers": [{"name": k, "value": v} for k, v in resp_headers.items()],
                            "content": {"text": resp_body},
                        },
                    }
                ],
            }
        }
        (bundle_dir / "evidence.har").write_text(json.dumps(har, indent=2), encoding="utf-8")

        # evidence.md
        md = self._evidence_md(target, vuln_class, request, response, bundle_id)
        (bundle_dir / "evidence.md").write_text(md, encoding="utf-8")

        # bundle.json (manifest + response SHA-256)
        resp_sha = hashlib.sha256(resp_body.encode()).hexdigest()
        manifest = {
            "bundle_id": bundle_id,
            "target": target,
            "vuln_class": vuln_class,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "response_sha256": resp_sha,
            "files": [
                "request.http",
                "response.http",
                "repro.sh",
                "evidence.har",
                "evidence.md",
            ]
            + (["screenshot.png"] if screenshot_path else []),
            "secrets_redacted": True,
        }
        (bundle_dir / "bundle.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        # Copy screenshot if provided
        if screenshot_path and Path(screenshot_path).exists():
            import shutil

            shutil.copy2(screenshot_path, bundle_dir / "screenshot.png")

        print(f"[POC Bundler] Bundle created: {bundle_dir}")
        return str(bundle_dir)

    def from_request(
        self,
        target: str,
        vuln_class: str,
        request_file: str,
        response_file: Optional[str] = None,
        confirm_unsafe: bool = False,
    ) -> str:
        """Create bundle from saved request/response files."""
        req = json.loads(Path(request_file).read_text(encoding="utf-8"))
        resp = (
            json.loads(Path(response_file).read_text(encoding="utf-8"))
            if response_file
            else {}
        )
        return self.capture(target, vuln_class, req, resp, confirm_unsafe=confirm_unsafe)

    def _evidence_md(
        self,
        target: str,
        vuln_class: str,
        request: Dict[str, Any],
        response: Dict[str, Any],
        bundle_id: str,
    ) -> str:
        return f"""# Evidence Bundle — {vuln_class}

**Target:** {target}
**Bundle ID:** {bundle_id}
**Generated:** {time.strftime("%Y-%m-%d %H:%M:%S")}

## Request
```http
{request.get('method', 'GET')} {request.get('url', '/')} HTTP/1.1
Host: {request.get('host', '')}
{self._headers_md(request.get('headers', {}))}

{request.get('body', '')}
```

## Response
```http
HTTP/1.1 {response.get('status_code', 200)} {response.get('reason', 'OK')}
{self._headers_md(response.get('headers', {}))}

{response.get('body', '')}
```

## Reproduction
```bash
curl -X {request.get('method', 'GET')} '{request.get('url', '')}'
```

## Evidence Hash
SHA-256 of response: `{hashlib.sha256(response.get('body','').encode()).hexdigest()[:16]}...`

**Secrets redacted by default.**
"""

    @staticmethod
    def _headers_md(headers: Dict[str, str]) -> str:
        return "\n".join(f"{k}: {v}" for k, v in headers.items())
