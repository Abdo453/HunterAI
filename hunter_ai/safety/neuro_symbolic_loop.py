"""
HunterAI Neuro-Symbolic Safety Loop
====================================

طبقة تحقق عصبية-رمزية تُشغّل قبل تنفيذ أي أمر هجومي، لمنع:
1. الأوامر خارج النطاق (out-of-scope)
2. حجب الخدمة (DoS) العرضي
3. العمليات المدمرة على أنظمة إنتاجية

يستخدم تحقق حتمي (deterministic) على رسم بياني للمعرفة
يحتوي على العلاقات المؤكدة بين الأجهزة، البورتات، والثغرات (CVEs).
"""

from __future__ import annotations

import ipaddress
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from enum import Enum


class SafetyVerdict(str, Enum):  # type: ignore[misc, valid-type]
    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"
    CONDITIONAL = "CONDITIONAL"


@dataclass
class SafetyCheckResult:
    command: str
    target: str
    verdict: SafetyVerdict
    reason: str
    risk_score: float  # 0.0 = آمن، 1.0 = عالي الخطورة
    checks_passed: List[str] = field(default_factory=list)
    checks_failed: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "command": self.command,
            "target": self.target,
            "verdict": self.verdict.value,
            "reason": self.reason,
            "risk_score": self.risk_score,
            "checks_passed": self.checks_passed,
            "checks_failed": self.checks_failed,
            "timestamp": self.timestamp,
        }


class KnowledgeGraph:
    """
    رسم بياني للمعرفة يخزن العلاقات المؤكدة بين:
    - الأجهزة (IP، نطاق)
    - البورتات المفتوحة
    - الخدمات
    - الثغرات (CVEs)
    - النطاق المصرح به (scope)
    """

    def __init__(self, graph_file: str = "data/safety_knowledge_graph.json"):
        self.graph_file = Path(graph_file)
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, Any]] = []
        self.in_scope: Set[str] = set()
        self._load()

    def _load(self) -> None:
        if self.graph_file.exists():
            try:
                with open(self.graph_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.nodes = data.get("nodes", {})
                self.edges = data.get("edges", [])
                self.in_scope = set(data.get("in_scope", []))
            except Exception:
                pass

    def save(self) -> None:
        data = {
            "nodes": self.nodes,
            "edges": self.edges,
            "in_scope": list(self.in_scope),
        }
        self.graph_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.graph_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def add_in_scope(self, target: str) -> None:
        self.in_scope.add(target)
        self.save()

    def remove_in_scope(self, target: str) -> None:
        self.in_scope.discard(target)
        self.save()

    def is_in_scope(self, target: str) -> bool:
        return target in self.in_scope

    def add_node(self, node_id: str, properties: Dict[str, Any]) -> None:
        self.nodes[node_id] = properties
        self.save()

    def add_edge(self, source: str, target: str, relation: str, confidence: float = 1.0) -> None:
        self.edges.append({
            "source": source,
            "target": target,
            "relation": relation,
            "confidence": confidence,
        })
        self.save()

    def get_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        return self.nodes.get(node_id)

    def get_neighbors(self, node_id: str, relation: Optional[str] = None) -> List[Dict[str, Any]]:
        neighbors = []
        for edge in self.edges:
            if edge["source"] == node_id:
                if relation is None or edge["relation"] == relation:
                    neighbors.append(edge)
        return neighbors


class NeuroSymbolicSafetyLoop:
    """
    حلقة التحقق العصبية-الرمزية.
    قبل تنفيذ أي أمر، تُنفذ سلسلة من الفحوص الحتمية للتأكد من الأمان والنطاق.
    """

    # أنماط الأوامر المحظورة (تدميرية أو عالية الخطورة)
    DESTRUCTIVE_PATTERNS = [
        r"rm\s+-rf",
        r"mkfs",
        r"dd\s+if=",
        r">\s*/dev/",
        r":\(\)\{.*\|.*\)",
        r"shutdown",
        r"reboot",
        r"halt",
        r"poweroff",
        r"iptables\s+-F",
        r"nohup\s+.*\s+&\s*$",
        r"curl.*\|\s*bash",
        r"wget.*\|\s*sh",
    ]

    # أنماط الأوامر التي قد تسبب DoS
    DOS_PATTERNS = [
        r"ping\s+.*\s+-f",
        r"hping3",
        r"slowloris",
        r"goldeneye",
        r"rudy",
        r"udp-flood",
        r"syn-flood",
    ]

    def __init__(self, knowledge_graph: Optional[KnowledgeGraph] = None):
        self.kg = knowledge_graph or KnowledgeGraph()
        self._check_history: List[SafetyCheckResult] = []

    def check_command(
        self,
        command: str,
        target: str,
        require_proof: bool = False,
    ) -> SafetyCheckResult:
        """
        التحقق من أمر قبل تنفيذه.
        يعيد نتيجة Seguridad مع حكم: ALLOWED، BLOCKED، أو CONDITIONAL.
        """
        checks_passed: List[str] = []
        checks_failed: List[str] = []
        risk_score = 0.0

        # الفحص 1: النطاق (Scope)
        if not self.kg.is_in_scope(target):
            checks_failed.append("OUT_OF_SCOPE")
            risk_score += 0.4
        else:
            checks_passed.append("IN_SCOPE")

        # الفحص 2: الأوامر المدمرة
        destructive_match = None
        for pattern in self.DESTRUCTIVE_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                destructive_match = pattern
                break
        if destructive_match:
            checks_failed.append(f"DESTRUCTIVE_COMMAND: {destructive_match}")
            risk_score += 0.5
        else:
            checks_passed.append("NO_DESTRUCTIVE_PATTERN")

        # الفحص 3: أنماط DoS المحتملة
        dos_match = None
        for pattern in self.DOS_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                dos_match = pattern
                break
        if dos_match:
            checks_failed.append(f"POTENTIAL_DOS: {dos_match}")
            risk_score += 0.3
        else:
            checks_passed.append("NO_DOS_PATTERN")

        # الفحص 4: الهدف صالح (IP أو نطاق)
        if self._is_valid_target(target):
            checks_passed.append("VALID_TARGET_FORMAT")
        else:
            checks_failed.append("INVALID_TARGET_FORMAT")
            risk_score += 0.2

        # الفحص 5: нали ор 그래fik مؤكد للهدف (إذا كان مطلوبًا دليل)
        if require_proof:
            node = self.kg.get_node(target)
            if node:
                checks_passed.append("TARGET_VERIFIED_IN_GRAPH")
            else:
                checks_failed.append("TARGET_NOT_IN_KNOWLEDGE_GRAPH")
                risk_score += 0.1

        # حساب الحكم النهائي
        risk_score = min(1.0, risk_score)

        if checks_failed:
            if "OUT_OF_SCOPE" in checks_failed or "DESTRUCTIVE_COMMAND" in checks_failed:
                verdict = SafetyVerdict.BLOCKED
                reason = f"محظور: {', '.join(checks_failed)}"
            elif risk_score >= 0.5:
                verdict = SafetyVerdict.BLOCKED
                reason = f"نسبة خطورة عالية ({risk_score:.0%}) — محظور"
            else:
                verdict = SafetyVerdict.CONDITIONAL
                reason = f"مشروط — يتطلب مراجعة ({risk_score:.0%})"
        else:
            verdict = SafetyVerdict.ALLOWED
            reason = "جميع فحوصات الأمان ناجحة"

        result = SafetyCheckResult(
            command=command,
            target=target,
            verdict=verdict,
            reason=reason,
            risk_score=risk_score,
            checks_passed=checks_passed,
            checks_failed=checks_failed,
        )

        self._check_history.append(result)
        return result

    def _is_valid_target(self, target: str) -> bool:
        """التحقق من أن الهدف هو IP صالح أو نطاق."""
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            pass
        # نطاق بسيط
        if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", target):
            return True
        if re.match(r"^https?://", target):
            return True
        return False

    def get_history(self, target: Optional[str] = None) -> List[SafetyCheckResult]:
        if target:
            return [c for c in self._check_history if c.target == target]
        return list(self._check_history)

    def stats(self) -> Dict[str, Any]:
        total = len(self._check_history)
        if total == 0:
            return {"total": 0, "allowed": 0, "blocked": 0, "conditional": 0}
        allowed = sum(1 for c in self._check_history if c.verdict == SafetyVerdict.ALLOWED)
        blocked = sum(1 for c in self._check_history if c.verdict == SafetyVerdict.BLOCKED)
        conditional = sum(1 for c in self._check_history if c.verdict == SafetyVerdict.CONDITIONAL)
        return {
            "total": total,
            "allowed": allowed,
            "blocked": blocked,
            "conditional": conditional,
            "block_rate": blocked / total if total else 0.0,
        }
