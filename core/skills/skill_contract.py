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
    )
}
