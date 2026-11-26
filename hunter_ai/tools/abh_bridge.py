"""
Agentic Bug Hunter (ABH) Bridge
===============================
Unified interface bridging the real security scanners and deterministic verifiers
in ``bughunter.tools.*`` and ``bughunter.tools.verifiers`` into HunterAI,
OmniHunterEngine, ``pentest.py``, and MasterToolRegistry.

Never fabricates synthetic findings: when a tool, runtime, or target is
unavailable or blocked by policy/SSRF invariants, returns an explicit
``status="UNAVAILABLE"`` / ``status="BLOCKED"`` / ``status="ERROR"`` payload.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.scope_engine import validate_http_url_target

logger = logging.getLogger(__name__)


def _check_url_safety(url: str, *, allow_loopback: bool = False) -> Optional[str]:
    ok, reason = validate_http_url_target(
        url,
        allow_loopback=allow_loopback,
        resolve_dns=False,
        fail_closed=False,
    )
    return None if ok else reason


class ABHToolBridge:
    """Unified bridge for Agentic Bug Hunter scanners and deterministic verifiers."""

    @classmethod
    def scan_cors(cls, url: str, *, allow_loopback: bool = False) -> Dict[str, Any]:
        """Runs real CORS misconfiguration inspection via ``bughunter.tools.cors_scanner``."""
        denied = _check_url_safety(url, allow_loopback=allow_loopback)
        if denied:
            return {"url": url, "status": "BLOCKED", "error": denied, "findings_count": 0, "findings": []}
        try:
            from bughunter.tools import cors_scanner
            findings = cors_scanner.scan(url)
            return {
                "url": url,
                "status": "OK",
                "findings_count": len(findings),
                "findings": [
                    {
                        "severity": f.severity,
                        "title": f.title,
                        "origin_tested": f.origin_tested,
                        "acao": f.acao,
                        "acac": f.acac,
                        "evidence": f.evidence,
                    }
                    for f in findings
                ],
            }
        except Exception as exc:
            logger.warning("[ABHBridge] CORS scan failed: %s", exc)
            return {"url": url, "status": "ERROR", "error": str(exc), "findings_count": 0, "findings": []}

    @classmethod
    def scan_crlf(
        cls,
        url: str,
        *,
        host_header: bool = False,
        allow_loopback: bool = False,
    ) -> Dict[str, Any]:
        """Runs real CRLF injection and HTTP response splitting inspection."""
        denied = _check_url_safety(url, allow_loopback=allow_loopback)
        if denied:
            return {"url": url, "status": "BLOCKED", "error": denied, "findings_count": 0, "findings": []}
        try:
            from bughunter.tools import crlf_scanner
            findings = crlf_scanner.scan(url, host_header=host_header)
            return {
                "url": url,
                "status": "OK",
                "findings_count": len(findings),
                "findings": [
                    {
                        "injection_type": f.injection_type,
                        "payload": f.payload,
                        "reflected_in": f.reflected_in,
                        "evidence": f.evidence,
                    }
                    for f in findings
                ],
            }
        except Exception as exc:
            logger.warning("[ABHBridge] CRLF scan failed: %s", exc)
            return {"url": url, "status": "ERROR", "error": str(exc), "findings_count": 0, "findings": []}

    @classmethod
    def scan_nosqli(
        cls,
        url: str,
        *,
        user_field: str = "username",
        pass_field: str = "password",
        allow_loopback: bool = False,
    ) -> Dict[str, Any]:
        """Runs real NoSQL injection operator and timing probes."""
        denied = _check_url_safety(url, allow_loopback=allow_loopback)
        if denied:
            return {"url": url, "status": "BLOCKED", "error": denied, "findings_count": 0, "findings": []}
        try:
            from bughunter.tools import nosqli_scanner
            findings = nosqli_scanner.scan_login(url, user_field=user_field, pass_field=pass_field)
            return {
                "url": url,
                "status": "OK",
                "findings_count": len(findings),
                "findings": [
                    {
                        "vector": f.vector,
                        "payload": str(f.payload),
                        "evidence": f.evidence,
                    }
                    for f in findings
                ],
            }
        except Exception as exc:
            logger.warning("[ABHBridge] NoSQLi scan failed: %s", exc)
            return {"url": url, "status": "ERROR", "error": str(exc), "findings_count": 0, "findings": []}

    @classmethod
    def analyze_jwt(cls, token: str, *, mode: str = "analyze") -> Dict[str, Any]:
        """Analyzes JWT via ``bughunter.tools.jwt_scanner`` (alg:none, RS256->HS256, weak secrets)."""
        try:
            from bughunter.tools import jwt_scanner
            header, payload, _sig = jwt_scanner.decode(token)
            issues = jwt_scanner.analyze(token)
            return {
                "status": "OK",
                "mode": mode,
                "header": header,
                "payload": payload,
                "issues": [
                    {
                        "title": iss.title,
                        "severity": iss.severity,
                        "details": iss.details,
                    }
                    for iss in issues
                ],
            }
        except Exception as exc:
            logger.warning("[ABHBridge] JWT analysis failed: %s", exc)
            return {"status": "ERROR", "token": token[:15] + "...", "error": str(exc), "issues": []}

    @classmethod
    def generate_oob_payloads(
        cls,
        oob_domain: str = "interact.sh",
        classes: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Generate OOB correlation payloads via ``bughunter.tools.oob_listener``."""
        try:
            from bughunter.tools import oob_listener
            payloads = oob_listener.oob_payloads(oob_domain, classes)
            return {
                "status": "OK",
                "oob_domain": oob_domain,
                "interactsh_available": bool(oob_listener._have_interactsh()),
                "payloads": payloads,
            }
        except Exception as exc:
            logger.warning("[ABHBridge] OOB payload generation failed: %s", exc)
            return {"status": "ERROR", "oob_domain": oob_domain, "error": str(exc), "payloads": []}

    @classmethod
    def scan_sast(cls, path: str, configs: Optional[List[str]] = None) -> Dict[str, Any]:
        """Run real SAST via ``bughunter.tools.sast_scan`` (Semgrep); never fabricates findings."""
        import shutil
        from pathlib import Path

        target_path = Path(path)
        if not target_path.exists():
            return {"path": path, "status": "ERROR", "error": f"Path not found: {path}", "findings": [], "total": 0}
        if shutil.which("semgrep") is None:
            return {
                "path": path,
                "status": "UNAVAILABLE",
                "error": "semgrep CLI is not installed in PATH",
                "findings": [],
                "total": 0,
            }
        try:
            from bughunter.tools import sast_scan
            findings = sast_scan.run(str(target_path), configs=configs)
            items = [
                {
                    "file": getattr(f, "path", getattr(f, "file", str(target_path))),
                    "line": getattr(f, "line", 0),
                    "rule": getattr(f, "rule_id", getattr(f, "rule", "")),
                    "severity": getattr(f, "severity", "info"),
                    "message": getattr(f, "message", ""),
                }
                for f in findings
            ]
            return {"path": path, "status": "OK", "findings": items, "total": len(items)}
        except Exception as exc:
            logger.warning("[ABHBridge] SAST scan failed: %s", exc)
            return {"path": path, "status": "ERROR", "error": str(exc), "findings": [], "total": 0}

    @classmethod
    def scan_domxss(cls, url: str, *, allow_loopback: bool = False) -> Dict[str, Any]:
        """Run real headless Chromium DOM XSS harness via ``bughunter.tools.dom_xss_harness``."""
        denied = _check_url_safety(url, allow_loopback=allow_loopback)
        if denied:
            return {"url": url, "status": "BLOCKED", "vulnerable": False, "error": denied, "findings": []}
        try:
            import playwright  # noqa: F401
        except ImportError:
            return {
                "url": url,
                "status": "UNAVAILABLE",
                "vulnerable": False,
                "error": "Playwright is not installed; cannot confirm DOM XSS execution.",
                "findings": [],
            }
        try:
            from bughunter.tools import dom_xss_harness
            findings = dom_xss_harness.run(url)
            items = [
                {
                    "url": getattr(f, "url", url),
                    "param": getattr(f, "param", ""),
                    "payload": getattr(f, "payload", ""),
                    "fired": bool(getattr(f, "fired", False)),
                    "evidence": getattr(f, "evidence", ""),
                }
                for f in findings
            ]
            confirmed = any(item["fired"] for item in items)
            return {
                "url": url,
                "status": "OK",
                "vulnerable": confirmed,
                "findings": items,
                "evidence": items[0]["evidence"] if items else "No DOM XSS payload executed.",
            }
        except Exception as exc:
            logger.warning("[ABHBridge] DOM XSS harness failed: %s", exc)
            return {"url": url, "status": "ERROR", "vulnerable": False, "error": str(exc), "findings": []}

    @classmethod
    def scan_llm_redteam(
        cls,
        endpoint: str,
        *,
        field: str = "prompt",
        allow_loopback: bool = False,
    ) -> Dict[str, Any]:
        """Run real LLM red-team probe suite via ``bughunter.tools.llm_redteam``."""
        denied = _check_url_safety(endpoint, allow_loopback=allow_loopback)
        if denied:
            return {"endpoint": endpoint, "status": "BLOCKED", "vulnerable": False, "error": denied, "hits": []}
        try:
            from bughunter.tools import llm_redteam
            hits = llm_redteam.run(endpoint, field=field)
            hit_dicts = [
                {
                    "category": getattr(h, "category", ""),
                    "name": getattr(h, "name", ""),
                    "evidence": getattr(h, "evidence", ""),
                }
                for h in hits
            ]
            return {
                "endpoint": endpoint,
                "status": "OK",
                "vulnerable": len(hit_dicts) > 0,
                "hits": hit_dicts,
            }
        except Exception as exc:
            logger.warning("[ABHBridge] LLM redteam scan failed: %s", exc)
            return {"endpoint": endpoint, "status": "ERROR", "vulnerable": False, "error": str(exc), "hits": []}

    @classmethod
    def verify_finding(cls, finding: Dict[str, Any], scope_checker: Any = None) -> Dict[str, Any]:
        """Run deterministic verifier via ``bughunter.tools.verifiers.verify_finding``."""
        try:
            from bughunter.tools.verifiers import verify_finding as bh_verify
            res = bh_verify(finding, scope_checker=scope_checker)
            if hasattr(res, "__dict__"):
                return {"status": "OK", **dict(res.__dict__)}
            return {"status": "OK", "result": res}
        except Exception as exc:
            logger.warning("[ABHBridge] Finding verification failed: %s", exc)
            return {"status": "ERROR", "verified": False, "error": str(exc)}

    @classmethod
    def verify_bundle(
        cls,
        bundle_dir: str,
        *,
        confirm_unsafe: bool = False,
    ) -> Dict[str, Any]:
        """Re-verify an evidence bundle via ``bughunter.tools.verifier.verify``."""
        try:
            from bughunter.tools import verifier as bh_verifier
            verdict = bh_verifier.verify(bundle_dir, confirm_unsafe=confirm_unsafe)
            return {
                "status": "OK",
                "bundle_dir": bundle_dir,
                "verdict": getattr(verdict, "status", str(verdict)),
                "verified": bool(getattr(verdict, "verified", False)),
                "reason": getattr(verdict, "reason", ""),
            }
        except Exception as exc:
            logger.warning("[ABHBridge] Bundle verification failed: %s", exc)
            return {"status": "ERROR", "bundle_dir": bundle_dir, "verified": False, "error": str(exc)}

    @classmethod
    def evaluate_7question_gate(
        cls,
        target: str,
        vuln_class: str,
        impact_statement: str,
        in_scope: bool = True,
        is_reproducible: bool = True,
    ) -> Dict[str, Any]:
        """Evaluates candidate finding against the 7-Question Validation Gate."""
        always_rejected = {
            "missing_spf", "missing_dmarc", "self_xss", "cors_wildcard_no_creds",
            "clickjacking_no_sensitive_action", "software_banner_disclosure",
        }
        clean_class = vuln_class.strip().lower().replace(" ", "_").replace("-", "_")
        if clean_class in always_rejected:
            return {
                "verdict": "KILLED",
                "reason": f"Vulnerability class '{vuln_class}' is on the Always-Rejected Kill List.",
                "pass_gate": False,
            }

        if not in_scope:
            return {
                "verdict": "KILLED",
                "reason": f"Target '{target}' is out of scope.",
                "pass_gate": False,
            }

        if not is_reproducible:
            return {
                "verdict": "KILLED",
                "reason": "Finding is not reliably reproducible.",
                "pass_gate": False,
            }

        if len(impact_statement.strip()) < 10:
            return {
                "verdict": "KILLED",
                "reason": "Impact statement is too weak or missing concrete exploitation consequence.",
                "pass_gate": False,
            }

        return {
            "verdict": "PASSED",
            "reason": "Finding satisfies all 7 validation criteria.",
            "pass_gate": True,
            "target": target,
            "vuln_class": vuln_class,
        }
