"""
Attack Surface Graph & Third-Party Dependency Firewall
======================================================
Hierarchical attack graph:
Root Target -> Subdomains -> Endpoints -> Parameters / Auth Context
External dependencies (GTM, Google Play, Cloudflare, external CDNs) are
classified as EXTERNAL_DEPENDENCY and strictly firewalled from active probing.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

logger = logging.getLogger("hunter_ai.attack_surface_graph")


class NodeCategory(str, Enum):
    IN_SCOPE_TARGET = "IN_SCOPE_TARGET"
    SUBDOMAIN = "SUBDOMAIN"
    ENDPOINT = "ENDPOINT"
    PARAMETER = "PARAMETER"
    EXTERNAL_DEPENDENCY = "EXTERNAL_DEPENDENCY"  # Firewalled: Never actively tested


@dataclass
class SurfaceNode:
    identifier: str
    category: NodeCategory
    url: str = ""
    is_in_scope: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)
    children: List[str] = field(default_factory=list)


class ThirdPartyDependencyFirewall:
    """Blocks any active probes against third-party external dependencies"""

    BLOCKED_DOMAINS = {
        "google.com", "googletagmanager.com", "google-analytics.com",
        "play.google.com", "apple.com", "apps.apple.com", "facebook.com",
        "twitter.com", "linkedin.com", "cloudflare.com", "cloudflareinsights.com",
        "gstatic.com", "googleapis.com"
    }

    @classmethod
    def is_external_dependency(cls, url: str, base_target_host: str) -> bool:
        try:
            h = (urlparse(url).hostname or "").lower().strip()
            if not h:
                return False
            base_h = base_target_host.lower().strip()

            # Exact match or subdomain
            if h == base_h or h.endswith(f".{base_h}"):
                return False

            # Check root domain
            parts = base_h.split(".")
            if len(parts) >= 2:
                root = ".".join(parts[-2:])
                if h == root or h.endswith(f".{root}"):
                    return False

            # Matches known external domains or foreign host
            if any(h == b or h.endswith(f".{b}") for b in cls.BLOCKED_DOMAINS):
                return True

            return True  # Any different host is external dependency
        except Exception:
            return True


class AttackSurfaceGraph:
    """Manages the in-scope target tree and firewall boundaries"""

    def __init__(self, root_target_url: str):
        self.root_url = root_target_url
        self.base_host = (urlparse(root_target_url).hostname or "").lower().strip()
        self.nodes: Dict[str, SurfaceNode] = {}

        # Add root node
        self.root_node = SurfaceNode(
            identifier=self.base_host,
            category=NodeCategory.IN_SCOPE_TARGET,
            url=root_target_url,
            is_in_scope=True
        )
        self.nodes[self.base_host] = self.root_node

    def add_endpoint(self, url: str, method: str = "GET") -> SurfaceNode:
        is_external = ThirdPartyDependencyFirewall.is_external_dependency(url, self.base_host)
        cat = NodeCategory.EXTERNAL_DEPENDENCY if is_external else NodeCategory.ENDPOINT
        node_id = f"{method.upper()}:{url}"

        node = SurfaceNode(
            identifier=node_id,
            category=cat,
            url=url,
            is_in_scope=not is_external,
            metadata={"method": method}
        )
        self.nodes[node_id] = node
        if not is_external:
            self.root_node.children.append(node_id)
        return node

    def can_probe(self, url: str) -> bool:
        """Firewall Gate: Returns True ONLY if URL is within authorized scope"""
        return not ThirdPartyDependencyFirewall.is_external_dependency(url, self.base_host)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "root_target": self.root_url,
            "base_host": self.base_host,
            "total_nodes": len(self.nodes),
            "in_scope_endpoints": len([n for n in self.nodes.values() if n.is_in_scope]),
            "firewalled_external_deps": len([n for n in self.nodes.values() if not n.is_in_scope]),
            "nodes": {k: {"category": v.category.value, "is_in_scope": v.is_in_scope, "url": v.url} for k, v in self.nodes.items()}
        }