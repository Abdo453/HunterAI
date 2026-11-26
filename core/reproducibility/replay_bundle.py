"""
Reproducibility & Finding Replay Bundle Engine with Automatic Secret Redaction
Generates self-contained, parameterized replay artifacts allowing deterministic
re-testing with SHA-256 response integrity and differential invariant checks.
Redacts API keys, passwords, bearer tokens, and sensitive PII.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

# Patterns for automatic redaction of sensitive secrets and tokens
SECRET_PATTERNS = [
    (r"(?i)(['\"]?api[_-]?key['\"]?\s*[:=]\s*['\"]?)([a-zA-Z0-9_\-]{6,})(['\"]?)", r"\1[REDACTED_API_KEY]\3"),
    (r"(?i)(['\"]?password['\"]?\s*[:=]\s*['\"]?)([^'\"\s&]+)(['\"]?)", r"\1[REDACTED_PASSWORD]\3"),
    (r"(?i)(bearer\s+)([a-zA-Z0-9_\-\.]{8,})", r"\1[REDACTED_BEARER_TOKEN]"),
    (r"(?i)(['\"]?session(?:id)?['\"]?\s*[:=]\s*['\"]?)([a-zA-Z0-9_\-]{6,})(['\"]?)", r"\1[REDACTED_SESSION]\3"),
    (r"(?i)(['\"]?secret['\"]?\s*[:=]\s*['\"]?)([^'\"\s&]+)(['\"]?)", r"\1[REDACTED_SECRET]\3"),
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b", "[REDACTED_EMAIL]"),
]


def _parse_raw_http_request(raw_request: str, fallback_target: str) -> Dict[str, Any]:
    """Parse a raw HTTP/1.1 request string into structured method, url, headers, and body."""
    method = "GET"
    url = fallback_target
    headers: Dict[str, str] = {}
    body = ""

    if not raw_request or not raw_request.strip():
        return {"method": method, "url": url, "headers": headers, "body": body}

    sep = "\r\n\r\n" if "\r\n\r\n" in raw_request else ("\n\n" if "\n\n" in raw_request else None)
    head_part = raw_request.split(sep, 1)[0] if sep else raw_request
    body = raw_request.split(sep, 1)[1] if sep else ""
    lines = [ln.strip("\r") for ln in head_part.splitlines() if ln.strip()]

    if lines:
        parts = lines[0].split()
        if len(parts) >= 2 and parts[0].isalpha():
            method = parts[0].upper()
            req_target = parts[1]
            if req_target.startswith(("http://", "https://")):
                url = req_target
            elif fallback_target.startswith(("http://", "https://")):
                url = urljoin(fallback_target.rstrip("/") + "/", req_target.lstrip("/"))
            else:
                url = req_target
        for hdr_line in lines[1:]:
            if ":" in hdr_line:
                k, v = hdr_line.split(":", 1)
                k_clean = k.strip()
                if k_clean.lower() not in ("host", "content-length"):
                    headers[k_clean] = v.strip()
                elif k_clean.lower() == "host" and not url.startswith(("http://", "https://")):
                    scheme = "http" if v.strip().startswith(("127.0.0.1", "localhost")) else "https"
                    url = f"{scheme}://{v.strip()}/{url.lstrip('/')}"

    return {"method": method, "url": url, "headers": headers, "body": body}


def _extract_response_body(raw_response: str) -> str:
    if not raw_response:
        return ""
    for sep in ("\r\n\r\n", "\n\n"):
        if sep in raw_response:
            return raw_response.split(sep, 1)[1]
    return raw_response


def _render_replay_script(spec: Dict[str, Any]) -> str:
    """Render a real parameterized HTTP replay script using json.dumps (zero raw interpolation)."""
    encoded_spec = json.dumps(spec, indent=2, ensure_ascii=False)
    lines = [
        "#!/usr/bin/env python3",
        "# HunterAI Deterministic Parameterized Finding Replay Script",
        "from __future__ import annotations",
        "",
        "import hashlib",
        "import json",
        "import pathlib",
        "import sys",
        "from typing import Any, Callable, Dict, Optional",
        "",
        f"REPLAY_SPEC: Dict[str, Any] = json.loads({json.dumps(encoded_spec)})",
        "",
        "",
        "def _load_spec() -> Dict[str, Any]:",
        "    spec_file = pathlib.Path(__file__).with_name('replay_spec.json')",
        "    if spec_file.exists():",
        "        return json.loads(spec_file.read_text(encoding='utf-8'))",
        "    return dict(REPLAY_SPEC)",
        "",
        "",
        "def replay_test(",
        "    transport: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,",
        "    timeout: float = 10.0,",
        ") -> Dict[str, Any]:",
        "    \"\"\"Execute the parameterized HTTP probe and verify response hash + invariant.\"\"\"",
        "    spec = _load_spec()",
        "    req_cfg = spec.get('request', {})",
        "    method = str(req_cfg.get('method', 'GET')).upper()",
        "    url = str(req_cfg.get('url') or spec.get('target') or '')",
        "    headers = dict(req_cfg.get('headers') or {})",
        "    body = str(req_cfg.get('body') or '')",
        "",
        "    try:",
        "        if transport is not None:",
        "            resp = transport({'method': method, 'url': url, 'headers': headers, 'body': body})",
        "            status_code = int(resp.get('status_code', 0))",
        "            resp_body = str(resp.get('body', ''))",
        "            resp_headers = dict(resp.get('headers') or {})",
        "        else:",
        "            import httpx",
        "            with httpx.Client(timeout=timeout, verify=True, trust_env=False, follow_redirects=False) as client:",
        "                r = client.request(",
        "                    method=method,",
        "                    url=url,",
        "                    headers=headers,",
        "                    content=(body.encode('utf-8') if body and method not in ('GET', 'HEAD') else None),",
        "                )",
        "                status_code = r.status_code",
        "                resp_body = r.text",
        "                resp_headers = dict(r.headers)",
        "    except (OSError, TimeoutError) as exc:",
        "        return {'status': 'UNAVAILABLE', 'verdict': 'UNAVAILABLE', 'reproduced': False, 'error': str(exc)}",
        "    except Exception as exc:",
        "        return {'status': 'ERROR', 'verdict': 'ERROR', 'reproduced': False, 'error': str(exc)}",
        "",
        "    replayed_sha = hashlib.sha256(resp_body.encode('utf-8', errors='replace')).hexdigest()",
        "    expected_sha = str(spec.get('original_response_body_sha256') or '')",
        "    expected_token = str(spec.get('expected_token') or '')",
        "    baseline_body = str(spec.get('baseline_body') or '')",
        "    vuln_type = str(spec.get('vulnerability_type') or '')",
        "",
        "    verdict = 'UNVERIFIED'",
        "    proof_strength = 'NONE'",
        "    reproduced = False",
        "    try:",
        "        from core.evidence_court import CourtVerdict, EvidenceCourt, ProofPayload, ProofStrength",
        "        pp = ProofPayload(",
        "            response_text=resp_body,",
        "            baseline_text=baseline_body,",
        "            artifact_type=vuln_type or ('token' if expected_token else ''),",
        "            expected_token=expected_token,",
        "            probed_expression=str(spec.get('probed_expression') or ''),",
        "            expected_result=str(spec.get('expected_result') or ''),",
        "            metadata={'status_code': status_code, 'headers': resp_headers},",
        "        )",
        "        judgment = EvidenceCourt.adjudicate(",
        "            target_url=url,",
        "            parameter=str(spec.get('parameter') or ''),",
        "            vuln_class=vuln_type,",
        "            verifier_result={'reproduced': True, 'status_code': status_code},",
        "            proof_payload=pp,",
        "            allow_declared_proof=False,",
        "        )",
        "        verdict = judgment.canonical_verdict.value",
        "        proof_strength = judgment.proof_strength",
        "        reproduced = judgment.verdict == CourtVerdict.CONFIRMED and judgment.proof_strength == ProofStrength.DERIVED.value",
        "    except Exception:",
        "        if expected_token and expected_token in resp_body and expected_token not in baseline_body:",
        "            verdict = 'CONFIRMED'",
        "            proof_strength = 'DERIVED'",
        "            reproduced = True",
        "        elif expected_sha and replayed_sha == expected_sha and resp_body:",
        "            verdict = 'CANDIDATE'",
        "        else:",
        "            verdict = 'REJECTED'",
        "",
        "    return {",
        "        'finding_id': spec.get('finding_id', ''),",
        "        'state_hash': spec.get('state_hash', ''),",
        "        'status': 'OK',",
        "        'verdict': verdict,",
        "        'proof_strength': proof_strength,",
        "        'reproduced': reproduced,",
        "        'status_code': status_code,",
        "        'response_sha256': replayed_sha,",
        "        'original_response_body_sha256': expected_sha,",
        "        'sha_match': bool(expected_sha) and (replayed_sha == expected_sha),",
        "    }",
        "",
        "",
        "if __name__ == '__main__':",
        "    out = replay_test()",
        "    print(json.dumps(out, indent=2, ensure_ascii=False))",
        "    sys.exit(0 if out.get('reproduced') else 1)",
        "",
    ]
    return "\n".join(lines)


@dataclass
class ReplayBundle:
    finding_id: str
    target: str
    vulnerability_type: str
    timestamp: float
    skill_version: str
    tool_version: str
    state_hash: str
    metadata: Dict[str, Any]
    sanitized_request: str
    sanitized_response: str
    screenshot_path: Optional[str]
    replay_code_snippet: str
    replay_spec: Dict[str, Any] = field(default_factory=dict)

    def to_bundle_dir(self, output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        bundle_path = output_dir / f"replay_{self.finding_id}"
        bundle_path.mkdir(parents=True, exist_ok=True)

        (bundle_path / "metadata.json").write_text(json.dumps(self.metadata, indent=2), encoding="utf-8")
        (bundle_path / "replay_spec.json").write_text(json.dumps(self.replay_spec, indent=2), encoding="utf-8")
        (bundle_path / "request.raw").write_text(self.sanitized_request, encoding="utf-8")
        (bundle_path / "response.raw").write_text(self.sanitized_response, encoding="utf-8")
        (bundle_path / "replay.py").write_text(self.replay_code_snippet, encoding="utf-8")

        return bundle_path


class ReplayBundleFactory:
    """Factory creating sanitized, parameterized, executable HTTP replay bundles."""

    @classmethod
    def redact_secrets(cls, text: str) -> str:
        if not text:
            return ""
        sanitized = text
        for pattern, repl in SECRET_PATTERNS:
            sanitized = re.sub(pattern, repl, sanitized)
        return sanitized

    @classmethod
    def create_bundle(
        cls,
        finding_id: str,
        target: str,
        vulnerability_type: str,
        request_raw: str,
        response_raw: str,
        skill_version: str = "2.1.0",
        tool_version: str = "HunterAI-Unified-v2.5",
        screenshot_path: Optional[str] = None,
        *,
        expected_token: str = "",
        baseline_body: str = "",
        probed_expression: str = "",
        expected_result: str = "",
        parameter: str = "",
    ) -> ReplayBundle:
        san_req = cls.redact_secrets(request_raw)
        san_resp = cls.redact_secrets(response_raw)

        raw_state = f"{finding_id}:{target}:{vulnerability_type}:{san_req}"
        state_hash = hashlib.sha256(raw_state.encode()).hexdigest()[:16]

        parsed_req = _parse_raw_http_request(san_req, target)
        resp_body = _extract_response_body(san_resp)
        resp_body_sha = hashlib.sha256(resp_body.encode("utf-8", errors="replace")).hexdigest()

        meta = {
            "finding_id": finding_id,
            "target": target,
            "vulnerability_type": vulnerability_type,
            "created_at": time.time(),
            "skill_version": skill_version,
            "tool_version": tool_version,
            "state_hash": state_hash,
            "original_response_body_sha256": resp_body_sha,
            "sanitized": True,
        }

        spec: Dict[str, Any] = {
            "schema": "hunterai.repro_spec.v2",
            "finding_id": finding_id,
            "target": target,
            "vulnerability_type": vulnerability_type,
            "state_hash": state_hash,
            "request": parsed_req,
            "original_response_body_sha256": resp_body_sha,
            "expected_token": expected_token,
            "baseline_body": cls.redact_secrets(baseline_body),
            "probed_expression": probed_expression,
            "expected_result": expected_result,
            "parameter": parameter,
        }

        replay_py = _render_replay_script(spec)

        return ReplayBundle(
            finding_id=finding_id,
            target=target,
            vulnerability_type=vulnerability_type,
            timestamp=time.time(),
            skill_version=skill_version,
            tool_version=tool_version,
            state_hash=state_hash,
            metadata=meta,
            sanitized_request=san_req,
            sanitized_response=san_resp,
            screenshot_path=screenshot_path,
            replay_code_snippet=replay_py,
            replay_spec=spec,
        )
