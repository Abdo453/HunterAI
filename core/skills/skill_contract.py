"""
Skill Contract Specification & Declaration Engine
Formalizes contracts for every skill: inputs, outputs, dependencies, permissions, timeout, risk level, success/failure conditions.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class SkillContract:
    name: str
    purpose: str
    inputs: List[str]
    outputs: List[str]
    dependencies: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    timeout_seconds: int = 120
    risk_level: str = "low"  # "low", "medium", "high"
    success_conditions: List[str] = field(default_factory=list)
    failure_conditions: List[str] = field(default_factory=list)

    def validate_inputs(self, provided_inputs: Dict[str, Any]) -> bool:
        """تحقق من توفر جميع المدخلات المطلوبة لتشغيل المهارة"""
        for req in self.inputs:
            if req not in provided_inputs or provided_inputs[req] is None:
                logger.warning(f"[SkillContract:{self.name}] Missing required input: '{req}'")
                return False
        return True


# Predefined standard contracts for core skills
BUILTIN_CONTRACTS: Dict[str, SkillContract] = {
    "browser_recon": SkillContract(
        name="browser_recon",
        purpose="Performs headless cognitive browser crawling, DOM extraction, and interactive form discovery.",
        inputs=["target_url"],
        outputs=["pages", "links", "forms", "api_endpoints"],
        dependencies=["network.http"],
        permissions=["browser.navigate", "browser.interact", "browser.extract"],
        timeout_seconds=90,
        risk_level="low",
        success_conditions=["Browser initialized", "Clean Markdown DOM extracted"],
        failure_conditions=["Browser crash", "Navigation timeout"]
    ),
    "authorization_analysis": SkillContract(
        name="authorization_analysis",
        purpose="Evaluates Broken Object Level Authorization (BOLA/IDOR) using dual-account comparison.",
        inputs=["endpoint_url", "object_id_param", "account_a_token", "account_b_token"],
        outputs=["authorization_finding", "differential_proof"],
        dependencies=["browser_recon", "endpoint_discovery"],
        permissions=["network.http", "knowledge.write"],
        timeout_seconds=60,
        risk_level="low",
        success_conditions=["Dual session test completed", "Status code & body evaluated"],
        failure_conditions=["Target endpoint unreachable", "Session token expired"]
    ),
    "sqli_differential_testing": SkillContract(
        name="sqli_differential_testing",
        purpose="Performs non-destructive Boolean/mathematical differential tests to prove SQL injection hypotheses.",
        inputs=["target_url", "parameter_name", "base_value"],
        outputs=["sqli_finding", "differential_evidence"],
        dependencies=["parameter_discovery"],
        permissions=["network.http", "evidence.write"],
        timeout_seconds=45,
        risk_level="low",
        success_conditions=["1=1 vs 1=2 differential matched", "Benign calculation verified"],
        failure_conditions=["WAF rate-limit block", "Target connection reset"]
    ),
    "waf_detection": SkillContract(
        name="waf_detection",
        purpose="Detects and fingerprints Web Application Firewalls in front of target hosts.",
        inputs=["target_domain"],
        outputs=["waf_detection.txt"],
        dependencies=[],
        permissions=["network.http"],
        timeout_seconds=120,
        risk_level="low",
        success_conditions=["At least one target probed", "WAF detection output parsed"],
        failure_conditions=["No target available", "Tool produced no parsable output"]
    ),
    "ssh_audit": SkillContract(
        name="ssh_audit",
        purpose="Audits SSH server algorithms (KEX, ciphers, MACs, host keys) for weak/deprecated configuration.",
        inputs=["target_domain"],
        outputs=["ssh_audit.txt", "ssh_audit_findings.json"],
        dependencies=[],
        permissions=["network.tcp"],
        timeout_seconds=120,
        risk_level="low",
        success_conditions=["SSH service reachable", "Algorithm audit parsed from tool output"],
        failure_conditions=["No SSH auditing tool available", "SSH port unreachable"]
    ),
    "tls_audit": SkillContract(
        name="tls_audit",
        purpose="Audits TLS/SSL service configuration (protocol versions, ciphers, certificate posture).",
        inputs=["target_domain"],
        outputs=["tls_audit.txt", "tls_audit_findings.json"],
        dependencies=[],
        permissions=["network.tcp"],
        timeout_seconds=150,
        risk_level="low",
        success_conditions=["TLS service reachable", "Protocol/cipher audit parsed"],
        failure_conditions=["No TLS auditing tool available", "TLS port unreachable"]
    ),
    "smb_enum": SkillContract(
        name="smb_enum",
        purpose="Enumerates SMB/NetBIOS/AD surface (signing, SMBv1, null sessions, shares, users, domain).",
        inputs=["target_domain"],
        outputs=["smb_enum.txt", "smb_enum_findings.json"],
        dependencies=[],
        permissions=["network.tcp"],
        timeout_seconds=180,
        risk_level="medium",
        success_conditions=["SMB service reachable", "Enumeration output parsed"],
        failure_conditions=["No SMB enumeration tool available", "SMB port unreachable"]
    )
}
