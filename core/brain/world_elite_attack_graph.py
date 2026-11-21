"""
╔══════════════════════════════════════════════════════════════════════════╗
║           WORLD ELITE ATTACK GRAPH — Crown Jewel Analysis               ║
║                                                                          ║
║  مستوحى من:                                                              ║
║  • Strix (RedAmon) → Graph-native attack surface mapping                ║
║  • Unit 8200       → OSINT graph building + Crown Jewel Analysis        ║
║  • VAPOR PANDA     → Multi-hop lateral movement through graph           ║
║  • MITRE ATT&CK    → Tactic/technique mapping on graph edges            ║
║                                                                          ║
║  للأغراض التعليمية فقط — على أهداف مصرح بها                             ║
╚══════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# ENUMS & CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

class AssetType(Enum):
    HOST        = "host"
    SERVICE     = "service"
    WEB_APP     = "web_app"
    API_ENDPOINT = "api_endpoint"
    DATABASE    = "database"
    USER_ACCOUNT = "user_account"
    CLOUD_RESOURCE = "cloud_resource"
    NETWORK_SEGMENT = "network_segment"
    CROWN_JEWEL = "crown_jewel"       # الأصل الأهم — الهدف الرئيسي


class EdgeType(Enum):
    """أنواع العلاقات بين الأصول — مسارات الهجوم المحتملة"""
    CONNECTS_TO    = "connects_to"     # اتصال شبكي
    AUTHENTICATES  = "authenticates"   # يستخدم للمصادقة
    HOSTS          = "hosts"           # يستضيف خدمة
    EXPOSES        = "exposes"         # يكشف endpoint
    DEPENDS_ON     = "depends_on"      # يعتمد عليه
    LATERAL_MOVE   = "lateral_move"    # حركة جانبية محتملة
    PRIVILEGE_ESC  = "privilege_esc"   # تصعيد صلاحيات محتمل
    DATA_FLOW      = "data_flow"       # تدفق بيانات


class MitreTactic(Enum):
    """MITRE ATT&CK Tactics — لربط كل edge بتكتيك"""
    RECON           = "TA0043"
    RESOURCE_DEV    = "TA0042"
    INITIAL_ACCESS  = "TA0001"
    EXECUTION       = "TA0002"
    PERSISTENCE     = "TA0003"
    PRIV_ESC        = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CRED_ACCESS     = "TA0006"
    DISCOVERY       = "TA0007"
    LATERAL_MOVE    = "TA0008"
    COLLECTION      = "TA0009"
    EXFILTRATION    = "TA0010"
    IMPACT          = "TA0040"


# ─────────────────────────────────────────────────────────────────────────────
# NODES & EDGES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AssetNode:
    """
    عقدة في خريطة الهجوم — تمثل أصلاً واحداً.
    مستوحى من Unit 8200: كل أصل له metadata كاملة.
    """
    id: str
    asset_type: AssetType
    name: str
    ip: Optional[str] = None
    port: Optional[int] = None
    os: Optional[str] = None
    services: List[str] = field(default_factory=list)
    vulnerabilities: List[Dict] = field(default_factory=list)
    access_level: str = "none"          # none/user/admin/root
    is_crown_jewel: bool = False         # هل هو الهدف الرئيسي؟
    compromise_probability: float = 0.0  # 0.0 → 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: Set[str] = field(default_factory=set)

    def add_vulnerability(self, vuln: Dict):
        """يضيف ثغرة ويحدث احتمالية الاختراق"""
        self.vulnerabilities.append(vuln)
        # زيادة احتمالية الاختراق بناءً على خطورة الثغرة
        severity_weights = {
            "critical": 0.4,
            "high": 0.25,
            "medium": 0.1,
            "low": 0.05,
        }
        weight = severity_weights.get(vuln.get("severity", "low"), 0.05)
        self.compromise_probability = min(1.0, self.compromise_probability + weight)

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "type": self.asset_type.value,
            "name": self.name,
            "ip": self.ip,
            "port": self.port,
            "vulnerabilities_count": len(self.vulnerabilities),
            "access_level": self.access_level,
            "is_crown_jewel": self.is_crown_jewel,
            "compromise_prob": round(self.compromise_probability, 3),
        }


@dataclass
class AttackEdge:
    """
    حافة في خريطة الهجوم — تمثل مسار هجوم محتمل.
    مستوحى من Strix: كل edge له تكتيك MITRE وصعوبة.
    """
    from_id: str
    to_id: str
    edge_type: EdgeType
    mitre_tactic: Optional[MitreTactic] = None
    mitre_technique: Optional[str] = None      # مثل T1190
    difficulty: float = 0.5                    # 0.0 (سهل) → 1.0 (صعب)
    requires_creds: bool = False
    requires_exploit: bool = False
    description: str = ""
    tools_suggested: List[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK GRAPH ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class WorldEliteAttackGraph:
    """
    محرك خريطة الهجوم الكامل.
    
    الميزات:
    1. Crown Jewel Analysis — يحدد أهم أصل للوصول إليه
    2. Shortest Attack Path — يجد أسهل مسار للاختراق
    3. MITRE ATT&CK Mapping — يربط كل مسار بتكتيك
    4. Mermaid Export — يصدر رسم بياني جاهز للتقرير
    5. Risk Scoring — يحسب خطورة كل مسار
    
    مستوحى من: Strix + Unit 8200 + VAPOR PANDA
    """

    def __init__(self):
        self.nodes: Dict[str, AssetNode] = {}
        self.edges: List[AttackEdge] = []
        self._adjacency: Dict[str, List[str]] = {}  # for path finding

    # ── Node Management ──────────────────────────────────────────────────────

    def add_asset(self, node: AssetNode) -> AssetNode:
        """يضيف أصل جديد للخريطة"""
        self.nodes[node.id] = node
        if node.id not in self._adjacency:
            self._adjacency[node.id] = []
        logger.debug("📌 Asset added: %s (%s)", node.name, node.asset_type.value)
        return node

    def get_asset(self, asset_id: str) -> Optional[AssetNode]:
        return self.nodes.get(asset_id)

    def add_vulnerability_to_asset(self, asset_id: str, vuln: Dict):
        """يضيف ثغرة لأصل موجود"""
        node = self.nodes.get(asset_id)
        if node:
            node.add_vulnerability(vuln)

    # ── Edge Management ──────────────────────────────────────────────────────

    def add_attack_path(
        self,
        from_id: str,
        to_id: str,
        edge_type: EdgeType,
        mitre_tactic: Optional[MitreTactic] = None,
        technique: Optional[str] = None,
        difficulty: float = 0.5,
        description: str = "",
        tools: Optional[List[str]] = None,
    ) -> AttackEdge:
        """يضيف مسار هجوم بين أصلين"""
        edge = AttackEdge(
            from_id=from_id,
            to_id=to_id,
            edge_type=edge_type,
            mitre_tactic=mitre_tactic,
            mitre_technique=technique,
            difficulty=difficulty,
            description=description,
            tools_suggested=tools or [],
        )
        self.edges.append(edge)
        self._adjacency.setdefault(from_id, []).append(to_id)
        logger.debug("🔗 Attack path: %s → %s [%s]", from_id, to_id, edge_type.value)
        return edge

    # ── Crown Jewel Analysis ─────────────────────────────────────────────────

    def identify_crown_jewels(self) -> List[AssetNode]:
        """
        يحدد أهم الأصول (Crown Jewels) بناءً على:
        1. عدد الـ assets المتصلة به (centrality)
        2. نوع الأصل (database > server > endpoint)
        3. العلاقات الواردة (كم asset يعتمد عليه)

        مستوحى من Unit 8200: تحديد الأهداف عالية القيمة.
        """
        type_weights = {
            AssetType.DATABASE:       1.0,
            AssetType.CROWN_JEWEL:    1.0,
            AssetType.CLOUD_RESOURCE: 0.9,
            AssetType.HOST:           0.7,
            AssetType.WEB_APP:        0.6,
            AssetType.SERVICE:        0.5,
            AssetType.API_ENDPOINT:   0.4,
            AssetType.USER_ACCOUNT:   0.3,
            AssetType.NETWORK_SEGMENT:0.5,
        }

        # حساب in-degree (كم edge واردة لكل node)
        in_degree: Dict[str, int] = {nid: 0 for nid in self.nodes}
        for edge in self.edges:
            in_degree[edge.to_id] = in_degree.get(edge.to_id, 0) + 1

        scored = []
        for node_id, node in self.nodes.items():
            type_weight = type_weights.get(node.asset_type, 0.5)
            centrality = in_degree.get(node_id, 0) / max(len(self.nodes), 1)
            score = type_weight * 0.5 + centrality * 0.3 + node.compromise_probability * 0.2
            scored.append((score, node))

        # الـ Top 20% هم Crown Jewels
        scored.sort(key=lambda x: x[0], reverse=True)
        top_n = max(1, len(scored) // 5)
        crown_jewels = [node for _, node in scored[:top_n]]

        for cj in crown_jewels:
            cj.is_crown_jewel = True

        logger.info("👑 Crown Jewels identified: %s", [cj.name for cj in crown_jewels])
        return crown_jewels

    # ── Shortest Attack Path (BFS) ───────────────────────────────────────────

    def find_shortest_attack_path(
        self,
        from_id: str,
        to_id: str,
    ) -> Optional[List[str]]:
        """
        يجد أقصر مسار هجوم من asset لآخر باستخدام BFS.
        مستوحى من VAPOR PANDA: lateral movement path planning.
        """
        if from_id not in self.nodes or to_id not in self.nodes:
            return None

        visited: Set[str] = set()
        queue: List[List[str]] = [[from_id]]

        while queue:
            path = queue.pop(0)
            current = path[-1]

            if current == to_id:
                return path

            if current in visited:
                continue
            visited.add(current)

            for neighbor in self._adjacency.get(current, []):
                if neighbor not in visited:
                    queue.append(path + [neighbor])

        return None  # لا يوجد مسار

    def find_easiest_attack_path(
        self,
        from_id: str,
        to_id: str,
    ) -> Tuple[Optional[List[str]], float]:
        """
        يجد أسهل مسار (أقل difficulty) بدلاً من أقصر مسار.
        الأجدى في الـ penetration testing الحقيقي.
        """
        if from_id not in self.nodes or to_id not in self.nodes:
            return None, float("inf")

        # Dijkstra-style with difficulty as weight
        import heapq
        heap = [(0.0, [from_id])]
        visited: Dict[str, float] = {}

        while heap:
            cost, path = heapq.heappop(heap)
            current = path[-1]

            if current in visited and visited[current] <= cost:
                continue
            visited[current] = cost

            if current == to_id:
                return path, cost

            for edge in self.edges:
                if edge.from_id == current and edge.to_id not in visited:
                    new_cost = cost + edge.difficulty
                    heapq.heappush(heap, (new_cost, path + [edge.to_id]))

        return None, float("inf")

    # ── Risk Scoring ─────────────────────────────────────────────────────────

    def calculate_path_risk(self, path: List[str]) -> Dict[str, Any]:
        """يحسب مستوى خطورة مسار هجوم كامل"""
        if not path:
            return {"risk": 0.0, "steps": 0}

        total_difficulty = 0.0
        techniques = []
        tools_needed = []

        for i in range(len(path) - 1):
            edge = self._get_edge(path[i], path[i + 1])
            if edge:
                total_difficulty += edge.difficulty
                if edge.mitre_technique:
                    techniques.append(edge.mitre_technique)
                tools_needed.extend(edge.tools_suggested)

        avg_difficulty = total_difficulty / max(len(path) - 1, 1)
        # Risk = inverse of difficulty (أسهل = أخطر)
        risk_score = 1.0 - avg_difficulty

        return {
            "risk_score": round(risk_score, 3),
            "path_length": len(path),
            "avg_difficulty": round(avg_difficulty, 3),
            "mitre_techniques": list(set(techniques)),
            "tools_needed": list(set(tools_needed)),
            "severity": (
                "critical" if risk_score > 0.8 else
                "high"     if risk_score > 0.6 else
                "medium"   if risk_score > 0.4 else
                "low"
            ),
        }

    # ── Graph Summary ─────────────────────────────────────────────────────────

    def get_attack_surface_summary(self) -> Dict[str, Any]:
        """ملخص كامل لسطح الهجوم"""
        crown_jewels = self.identify_crown_jewels()
        total_vulns = sum(len(n.vulnerabilities) for n in self.nodes.values())

        return {
            "total_assets": len(self.nodes),
            "total_attack_paths": len(self.edges),
            "crown_jewels": [cj.to_dict() for cj in crown_jewels],
            "total_vulnerabilities": total_vulns,
            "high_risk_assets": [
                n.to_dict() for n in self.nodes.values()
                if n.compromise_probability > 0.6
            ],
            "asset_types": {
                atype.value: sum(
                    1 for n in self.nodes.values()
                    if n.asset_type == atype
                )
                for atype in AssetType
            },
        }

    # ── Export ───────────────────────────────────────────────────────────────

    def export_to_mermaid(self, highlight_crown_jewels: bool = True) -> str:
        """
        يصدر الخريطة كـ Mermaid diagram للتقارير.
        مستوحى من ARTEX Global: visual attack graph في التقارير.
        """
        lines = ["flowchart LR"]

        # Node definitions
        for node in self.nodes.values():
            label = f"{node.name}\\n[{node.asset_type.value}]"
            if node.is_crown_jewel and highlight_crown_jewels:
                lines.append(f'    {node.id}["{label} 👑"]:::crown')
            elif node.compromise_probability > 0.6:
                lines.append(f'    {node.id}["{label}"]:::highrisk')
            else:
                lines.append(f'    {node.id}["{label}"]')

        # Edge definitions
        for edge in self.edges:
            arrow = "-->"
            if edge.edge_type == EdgeType.LATERAL_MOVE:
                arrow = "==>"
            elif edge.edge_type == EdgeType.PRIVILEGE_ESC:
                arrow = "-..->"

            label = edge.mitre_technique or edge.edge_type.value
            lines.append(f"    {edge.from_id} {arrow}|{label}| {edge.to_id}")

        # Styles
        lines.extend([
            "    classDef crown fill:#ff4444,color:#fff,stroke:#cc0000",
            "    classDef highrisk fill:#ff8800,color:#fff,stroke:#cc6600",
        ])

        return "\n".join(lines)

    def export_to_json(self) -> str:
        """يصدر الخريطة كـ JSON للتكامل مع أدوات خارجية"""
        return json.dumps({
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [
                {
                    "from": e.from_id,
                    "to": e.to_id,
                    "type": e.edge_type.value,
                    "mitre": e.mitre_technique,
                    "difficulty": e.difficulty,
                }
                for e in self.edges
            ],
            "summary": self.get_attack_surface_summary(),
        }, indent=2, ensure_ascii=False)

    def _get_edge(self, from_id: str, to_id: str) -> Optional[AttackEdge]:
        """يبحث عن edge بين نودين"""
        for edge in self.edges:
            if edge.from_id == from_id and edge.to_id == to_id:
                return edge
        return None
