"""
Hierarchical Attack Surface Graph
Models target architecture: Domain -> Subdomain -> Application -> Page / API / Param / Auth -> Service.
Stores rich metadata, timestamps, hashes, confidence, and cross-references.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


@dataclass
class SurfaceNode:
    node_id: str
    node_type: str  # "domain", "subdomain", "application", "page", "api_endpoint", "parameter", "auth_mechanism", "service"
    label: str
    parent_id: Optional[str] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    source_skill: str = "recon"
    timestamp: float = field(default_factory=time.time)
    confidence: float = 1.0
    related_requests: List[str] = field(default_factory=list)
    related_files: List[str] = field(default_factory=list)
    state_hash: str = ""

    def __post_init__(self):
        if not self.state_hash:
            raw = f"{self.node_id}:{self.node_type}:{self.label}:{json.dumps(self.attributes, sort_keys=True)}"
            self.state_hash = hashlib.sha256(raw.encode()).hexdigest()[:12]


class AttackSurfaceGraph:
    """
    الرسم البياني لهيكل الهدف المعماري (Attack Surface Graph)
    - يربط جميع الأصول من النطاق وحتى الـ Parameter ونوع التوثيق.
    - يعمل كذاكرة مكانية وزمنية موحدة للـ Agent.
    """

    def __init__(self, target_root_domain: str):
        self.root_domain = target_root_domain
        self.nodes: Dict[str, SurfaceNode] = {}
        # Initialize root node
        self.add_node(
            node_id=f"domain:{target_root_domain}",
            node_type="domain",
            label=target_root_domain,
            attributes={"in_scope": True}
        )

    def add_node(
        self,
        node_id: str,
        node_type: str,
        label: str,
        parent_id: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None,
        source_skill: str = "recon",
        confidence: float = 1.0,
        related_requests: Optional[List[str]] = None,
        related_files: Optional[List[str]] = None
    ) -> SurfaceNode:
        node = SurfaceNode(
            node_id=node_id,
            node_type=node_type,
            label=label,
            parent_id=parent_id,
            attributes=attributes or {},
            source_skill=source_skill,
            confidence=confidence,
            related_requests=related_requests or [],
            related_files=related_files or []
        )
        self.nodes[node_id] = node
        return node

    def add_subdomain(self, subdomain: str, ip: str = "", tech: Optional[List[str]] = None) -> SurfaceNode:
        return self.add_node(
            node_id=f"subdomain:{subdomain}",
            node_type="subdomain",
            label=subdomain,
            parent_id=f"domain:{self.root_domain}",
            attributes={"ip": ip, "technologies": tech or []}
        )

    def add_endpoint(self, subdomain: str, path: str, method: str = "GET", auth_required: bool = False) -> SurfaceNode:
        sub_id = f"subdomain:{subdomain}"
        if sub_id not in self.nodes:
            self.add_subdomain(subdomain)
        return self.add_node(
            node_id=f"endpoint:{subdomain}{path}#{method}",
            node_type="api_endpoint",
            label=f"{method} {path}",
            parent_id=sub_id,
            attributes={"method": method, "path": path, "auth_required": auth_required}
        )

    def add_parameter(self, endpoint_node_id: str, param_name: str, param_type: str = "query") -> SurfaceNode:
        return self.add_node(
            node_id=f"param:{endpoint_node_id}:{param_name}",
            node_type="parameter",
            label=param_name,
            parent_id=endpoint_node_id,
            attributes={"param_type": param_type}
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "root_domain": self.root_domain,
            "node_count": len(self.nodes),
            "nodes": [n.__dict__ for n in self.nodes.values()]
        }

    def to_mermaid(self) -> str:
        lines = ["graph TD", f'    root["Domain: {self.root_domain}"]']
        for n in self.nodes.values():
            if n.node_type == "domain":
                continue
            safe_id = n.node_id.replace(":", "_").replace("/", "_").replace("#", "_").replace(".", "_")
            safe_parent = (n.parent_id or f"domain:{self.root_domain}").replace(":", "_").replace("/", "_").replace("#", "_").replace(".", "_")
            lines.append(f'    {safe_parent} --> {safe_id}["{n.node_type.title()}: {n.label}"]')
        return "\n".join(lines)
