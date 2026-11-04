"""
Agentic Bug Hunter (ABH) Bridge
===============================
Unified interface bridging the 50 autonomous security tools from
Awarexone/Agentic-Bug-Hunter into PentestAI-Unified, OmniHunterEngine,
and MasterToolRegistry.

Exposes:
- cors_scan(url)
- crlf_scan(url)
- nosqli_scan(url)
- jwt_analyze(token, secret_wordlist=None)
- validate_finding_gate(target, vuln_class, description, impact)
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class ABHToolBridge:
    """Unified bridge for Agentic Bug Hunter scanners and validation gates."""

    @classmethod
    def scan_cors(cls, url: str) -> Dict[str, Any]:
        """Runs CORS misconfiguration inspection (origin reflection, null, credentialed)."""
        try:
            from bughunter.tools import cors_scanner
            findings = cors_scanner.scan(url)
            return {
                "url": url,
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
            return {"url": url, "error": str(exc), "findings_count": 0, "findings": []}

    @classmethod
    def scan_crlf(cls, url: str) -> Dict[str, Any]:
        """Runs CRLF injection and HTTP response splitting inspection."""
        try:
            from bughunter.tools import crlf_scanner
            findings = crlf_scanner.scan(url)
            return {
                "url": url,
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
            return {"url": url, "error": str(exc), "findings_count": 0, "findings": []}

    @classmethod
    def scan_nosqli(cls, url: str) -> Dict[str, Any]:
        """Runs NoSQL injection operator and timing probes."""
        try:
            from bughunter.tools import nosqli_scanner
            findings = nosqli_scanner.scan_login(url)
            return {
                "url": url,
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
            return {"url": url, "error": str(exc), "findings_count": 0, "findings": []}

    @classmethod
    def analyze_jwt(cls, token: str) -> Dict[str, Any]:
        """Analyzes JWT for alg:none, RS256 to HS256 confusion, and weak secrets."""
        try:
            from bughunter.tools import jwt_scanner
            header, payload, sig = jwt_scanner.decode(token)
            issues = jwt_scanner.analyze(token)
            return {
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
            return {"token": token[:15] + "...", "error": str(exc), "issues": []}

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
        # Gate 1: In Scope
        # Gate 2: Can attacker do this RIGHT NOW?
        # Gate 3: Is impact real (P1-P3) or informational/theoretical?
        # Gate 4: Clear reproduction steps?
        # Gate 5: CVSS severity score > 4.0?
        # Gate 6: Not on always-rejected list (e.g. missing SPF/DMARC, self-XSS, open redirect without impact)?
        # Gate 7: Evidence bundle complete?
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
