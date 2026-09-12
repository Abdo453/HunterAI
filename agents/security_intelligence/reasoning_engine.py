"""
Reasoning & Threat Correlation Engine
Synthesizes contextual knowledge from Project Memory, Target History, and active Findings into correlated attack paths.
"""
import logging
from typing import Dict, List, Any, Optional
from agents.security_intelligence.schemas import IntelligenceFinding
from agents.security_intelligence.memory_manager import MemoryManager

log = logging.getLogger("security_intelligence.reasoning")


class ReasoningEngine:
    """محرك الاستدلال والربط الأمني: فهم الصورة الكاملة للهجوم وبناء مسارات الهجوم المترابطة"""

    def __init__(self, memory_manager: Optional[MemoryManager] = None):
        self.memory = memory_manager or MemoryManager()

    def correlate_findings(self, target_host: str, findings: List[IntelligenceFinding]) -> Dict[str, Any]:
        """
        ربط الثغرات المكتشفة مع سياق التطبيق والتقنيات لتحديد سلاسل الهجوم المتوقعة
        """
        proj_summary = self.memory.project.get_summary()
        target_info = self.memory.target.get_or_create_target(target_host)

        attack_chains: List[Dict[str, Any]] = []

        # Correlate Auth + Access Control
        auth_findings = [f for f in findings if f.vulnerability_type in ["JWT", "Auth_Bypass", "Session_Flaw"]]
        ac_findings = [f for f in findings if f.vulnerability_type in ["BOLA", "BFLA", "IDOR", "Mass_Assignment"]]

        if auth_findings and ac_findings:
            attack_chains.append({
                "chain_name": "Authentication Tampering to Privilege Escalation / Data Exfiltration",
                "severity": "CRITICAL",
                "steps": [
                    f"1. Exploit Authentication weakness ({auth_findings[0].vulnerability_type}) to forge identity token",
                    f"2. Utilize forged token to access protected object-level endpoints ({ac_findings[0].title})",
                    "3. Extract multi-tenant data or escalate administrative privileges"
                ]
            })
        elif ac_findings:
            attack_chains.append({
                "chain_name": "Direct Object Identifier Manipulation (IDOR / BOLA)",
                "severity": "HIGH",
                "steps": [
                    "1. Identify user-controlled object parameter in endpoint",
                    f"2. Modify identifier to victim object ID ({ac_findings[0].title})",
                    "3. Access victim resources without authorization"
                ]
            })

        # Suggest Next Investigation Steps
        next_steps: List[str] = []
        for f in findings:
            if f.vulnerability_type in ["BOLA", "IDOR"]:
                next_steps.append(f"Inspect sibling endpoints matching pattern '{f.title}' across other HTTP methods (PUT, DELETE).")
            elif f.vulnerability_type == "SQLi":
                next_steps.append("Verify if parameterized queries or ORM sanitization can be validated from response headers or stack traces.")

        return {
            "target": target_host,
            "project_context": proj_summary,
            "attack_chains": attack_chains,
            "recommended_investigations": list(set(next_steps)),
            "findings_count": len(findings)
        }
