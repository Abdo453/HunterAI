"""
HunterAI Attack Path Chaining & Compound Impact Modeling Engine
===============================================================
Models how atomic low/medium-severity security findings compound into high/critical impact:
Example:
  [Atomic Finding 1: Info Disclosure of UUID] (Low)
        +
  [Atomic Finding 2: Unauthenticated Profile Endpoint] (Low)
        +
  [Atomic Finding 3: BOLA on Resource ID] (Medium)
        ↓
  [Compound Attack Path: Full Account Takeover / ATO] (Critical CVSS 9.8)

Invariants:
- Strictly architectural modeling within the Security Digital Twin.
- Computes compound risk scoring and visualizes attack graph topologies for defense.
- Does NOT generate weaponized exploit code or destructive scripts.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class CompoundImpactTier(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class AtomicFindingNode:
    finding_id: str
    vulnerability_title: str
    cwe_id: str
    severity: str  # "LOW", "MEDIUM", "HIGH"
    provides_primitive: str  # e.g., "USER_UUID", "UNAUTHENTICATED_ROUTE", "OBJECT_MUTATION"
    target_endpoint: str


@dataclass
class ChainedAttackPath:
    path_id: str
    name: str
    stages: List[AtomicFindingNode]
    compound_impact: CompoundImpactTier
    composite_cvss: float
    business_impact_narrative: str
    recommended_mitigation_priority: str
    timestamp: float = field(default_factory=time.time)

    def format_topology_ascii(self) -> str:
        sep = "─" * 60
        lines = [
            f"┌{sep}┐",
            f"│ ⛓️ COMPOUND ATTACK PATH: {self.name:<33} │",
            f"│ Composite CVSS: {self.composite_cvss:<4.1f} ({self.compound_impact.value}){' ' * (37 - len(self.compound_impact.value))} │",
            f"├{sep}┤"
        ]
        for i, stage in enumerate(self.stages, 1):
            arrow = "   │      ↓" if i < len(self.stages) else ""
            lines.append(f"│ [Step {i}] {stage.vulnerability_title:<48} │")
            lines.append(f"│         Primitive Gained: {stage.provides_primitive:<34} │")
            if arrow:
                lines.append(arrow)

        lines.extend([
            f"├{sep}┤",
            f"│ 🎯 Business Impact: {self.business_impact_narrative:<38} │",
            f"│ 🛡️ Mitigation Priority: {self.recommended_mitigation_priority:<35} │",
            f"└{sep}┘"
        ])
        return "\n".join(lines)


class AttackPathChainingEngine:
    """Evaluates multi-finding combinatorial relationships in the target digital twin"""

    @classmethod
    def analyze_compound_paths(cls, findings: List[Dict[str, Any]]) -> List[ChainedAttackPath]:
        """Synthesizes compound attack paths from a collection of atomic findings"""
        chained_paths: List[ChainedAttackPath] = []

        # Convert dicts into typed nodes
        nodes = []
        for f in findings:
            cwe = str(f.get("cwe", ""))
            title = str(f.get("title", ""))
            ep = str(f.get("endpoint", ""))
            
            # Infer primitives
            primitive = "GENERIC_ANOMALY"
            if "200" in cwe or "INFO" in title.upper() or "UUID" in title.upper():
                primitive = "INTERNAL_IDENTIFIER_LEAK"
            elif "AUTH" in title.upper() or "UNAUTHENTICATED" in title.upper():
                primitive = "UNAUTHENTICATED_ACCESS"
            elif "639" in cwe or "BOLA" in title.upper() or "IDOR" in title.upper():
                primitive = "CROSS_TENANT_OBJECT_MANIPULATION"
            elif "89" in cwe or "SQLI" in title.upper():
                primitive = "DATABASE_DATA_EXFILTRATION"

            nodes.append(AtomicFindingNode(
                finding_id=f.get("finding_id", "F-01"),
                vulnerability_title=title or f.get("type", "Anomaly"),
                cwe_id=cwe,
                severity=f.get("severity", "MEDIUM"),
                provides_primitive=primitive,
                target_endpoint=ep
            ))

        # Pattern 1: Identifier Leak + BOLA -> High Risk Account Data Access
        leak_nodes = [n for n in nodes if n.provides_primitive == "INTERNAL_IDENTIFIER_LEAK"]
        bola_nodes = [n for n in nodes if n.provides_primitive == "CROSS_TENANT_OBJECT_MANIPULATION"]

        if leak_nodes and bola_nodes:
            chained_paths.append(ChainedAttackPath(
                path_id="CHAIN-PATH-ATO-01",
                name="Leaked Identifier to Cross-Tenant Data Access",
                stages=[leak_nodes[0], bola_nodes[0]],
                compound_impact=CompoundImpactTier.HIGH,
                composite_cvss=8.8,
                business_impact_narrative="Attacker uses leaked user identifier to access cross-tenant records.",
                recommended_mitigation_priority="URGENT (Remediate object ownership filter first)"
            ))

        # Pattern 2: Unauthenticated Endpoint + BOLA/SQLi -> Critical ATO
        unauth_nodes = [n for n in nodes if n.provides_primitive == "UNAUTHENTICATED_ACCESS"]
        if unauth_nodes and (bola_nodes or leak_nodes):
            stages = [unauth_nodes[0]]
            if leak_nodes:
                stages.append(leak_nodes[0])
            if bola_nodes:
                stages.append(bola_nodes[0])

            chained_paths.append(ChainedAttackPath(
                path_id="CHAIN-PATH-ATO-02",
                name="Unauthenticated Chain to Full Account Compromise",
                stages=stages,
                compound_impact=CompoundImpactTier.CRITICAL,
                composite_cvss=9.6,
                business_impact_narrative="Unauthenticated attacker chains exposed route and IDOR to hijack account.",
                recommended_mitigation_priority="IMMEDIATE (Enforce authentication gateway and role verification)"
            ))

        return chained_paths
