"""
HunterAI / ARTEX Dual-Graph Architecture
=========================================
Separates "What the target is" (Asset Graph) from "How far testing has progressed" (Exploration Graph),
interlinked bidirectionally via Exploration Anchors.

1. Asset Graph:
   Globally shared source-of-truth across tasks/engagements.
   Hierarchical: company -> root_domain -> subdomain -> ip -> service -> endpoint.

2. Exploration Graph:
   Per-task cognitive progression chain.
   Nodes: goal, intent, fact, finding, hint.
   Edges: spawns, derived_from, yields, proves.

3. Anchors:
   exploration_anchors(node_id, asset_id) binding intents, facts, and findings to assets.
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("hunter_ai.dual_graph")


class AssetKind(str, Enum):
    COMPANY = "company"
    ROOT_DOMAIN = "root_domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    SERVICE = "service"
    ENDPOINT = "endpoint"


class ExplorationKind(str, Enum):
    GOAL = "goal"
    INTENT = "intent"
    FACT = "fact"
    FINDING = "finding"
    HINT = "hint"


class ExplorationEdgeType(str, Enum):
    SPAWNS = "spawns"
    DERIVED_FROM = "derived_from"
    YIELDS = "yields"
    PROVES = "proves"


@dataclass
class AssetNode:
    id: str
    kind: AssetKind
    value: str
    parent_id: Optional[str] = None
    company_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    @property
    def dedup_key(self) -> str:
        p = self.parent_id or ""
        return f"{self.kind.value}:{p}:{self.value.strip().lower()}"


@dataclass
class ExplorationNode:
    id: str
    kind: ExplorationKind
    title: str
    task_id: str
    state: str = "open"  # open, running, done, exhausted, blocked, proved
    payload: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)


@dataclass
class ExplorationEdge:
    source_id: str
    target_id: str
    edge_type: ExplorationEdgeType
    task_id: str
    created_at: float = field(default_factory=time.time)


class DualGraphManager:
    """
    Unified manager for the Asset Graph, Exploration Graph, and Anchors.
    Supports in-memory querying, lineage traversal, and JSON snapshot persistence.
    """

    def __init__(self, storage_dir: Optional[str] = None):
        self.storage_dir = Path(storage_dir) if storage_dir else None
        # Asset Graph Store
        self.assets: Dict[str, AssetNode] = {}
        self.asset_dedup_index: Dict[str, str] = {}  # dedup_key -> asset_id
        # Exploration Graph Store
        self.exploration_nodes: Dict[str, ExplorationNode] = {}
        self.edges: List[ExplorationEdge] = []
        # Anchors: exploration_node_id -> set of asset_ids
        self.anchors_exp_to_asset: Dict[str, Set[str]] = {}
        # Anchors: asset_id -> set of exploration_node_ids
        self.anchors_asset_to_exp: Dict[str, Set[str]] = {}

    # ── Asset Graph Operations ──────────────────────────────────────────────────

    def upsert_asset(
        self,
        kind: AssetKind,
        value: str,
        parent_id: Optional[str] = None,
        company_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AssetNode:
        temp_node = AssetNode(
            id="",
            kind=kind,
            value=value,
            parent_id=parent_id,
            company_id=company_id,
            metadata=metadata or {},
        )
        d_key = temp_node.dedup_key
        if d_key in self.asset_dedup_index:
            existing_id = self.asset_dedup_index[d_key]
            existing = self.assets[existing_id]
            if metadata:
                existing.metadata.update(metadata)
            return existing

        node_id = f"asset_{uuid.uuid4().hex[:10]}"
        temp_node.id = node_id
        self.assets[node_id] = temp_node
        self.asset_dedup_index[d_key] = node_id
        return temp_node

    def get_asset(self, asset_id: str) -> Optional[AssetNode]:
        return self.assets.get(asset_id)

    def list_assets(self, kind: Optional[AssetKind] = None) -> List[AssetNode]:
        if kind:
            return [a for a in self.assets.values() if a.kind == kind]
        return list(self.assets.values())

    # ── Exploration Graph Operations ────────────────────────────────────────────

    def add_exploration_node(
        self,
        kind: ExplorationKind,
        title: str,
        task_id: str,
        state: str = "open",
        payload: Optional[Dict[str, Any]] = None,
        anchored_asset_ids: Optional[List[str]] = None,
    ) -> ExplorationNode:
        node_id = f"{kind.value}_{uuid.uuid4().hex[:8]}"
        node = ExplorationNode(
            id=node_id,
            kind=kind,
            title=title,
            task_id=task_id,
            state=state,
            payload=payload or {},
        )
        self.exploration_nodes[node_id] = node

        if anchored_asset_ids:
            for aid in anchored_asset_ids:
                self.anchor_node_to_asset(node_id, aid)

        return node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: ExplorationEdgeType,
        task_id: str,
    ) -> ExplorationEdge:
        edge = ExplorationEdge(
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            task_id=task_id,
        )
        self.edges.append(edge)
        return edge

    def update_node_state(self, node_id: str, new_state: str, payload_update: Optional[Dict[str, Any]] = None) -> bool:
        node = self.exploration_nodes.get(node_id)
        if not node:
            return False
        node.state = new_state
        node.updated_at = time.time()
        if payload_update:
            node.payload.update(payload_update)
        return True

    # ── Anchors Operations ──────────────────────────────────────────────────────

    def anchor_node_to_asset(self, exploration_node_id: str, asset_id: str) -> None:
        self.anchors_exp_to_asset.setdefault(exploration_node_id, set()).add(asset_id)
        self.anchors_asset_to_exp.setdefault(asset_id, set()).add(exploration_node_id)

    def get_anchored_assets(self, exploration_node_id: str) -> List[AssetNode]:
        asset_ids = self.anchors_exp_to_asset.get(exploration_node_id, set())
        return [self.assets[aid] for aid in asset_ids if aid in self.assets]

    def get_anchored_exploration(self, asset_id: str) -> List[ExplorationNode]:
        exp_ids = self.anchors_asset_to_exp.get(asset_id, set())
        return [self.exploration_nodes[eid] for eid in exp_ids if eid in self.exploration_nodes]

    # ── Lineage & Traversal ─────────────────────────────────────────────────────

    def get_exploration_chain(self, start_node_id: str) -> List[Tuple[ExplorationNode, str, ExplorationNode]]:
        """Returns sequence of (source, edge_type, target) for tracing causality."""
        chain: List[Tuple[ExplorationNode, str, ExplorationNode]] = []
        visited = set()

        def _traverse(cur_id: str):
            if cur_id in visited:
                return
            visited.add(cur_id)
            for e in self.edges:
                if e.source_id == cur_id:
                    src = self.exploration_nodes.get(e.source_id)
                    tgt = self.exploration_nodes.get(e.target_id)
                    if src and tgt:
                        chain.append((src, e.edge_type.value, tgt))
                        _traverse(e.target_id)

        _traverse(start_node_id)
        return chain

    def export_summary(self) -> Dict[str, Any]:
        return {
            "total_assets": len(self.assets),
            "assets_by_kind": {k.value: len(self.list_assets(k)) for k in AssetKind},
            "total_exploration_nodes": len(self.exploration_nodes),
            "exploration_by_kind": {
                k.value: len([n for n in self.exploration_nodes.values() if n.kind == k])
                for k in ExplorationKind
            },
            "total_edges": len(self.edges),
            "total_anchors": sum(len(v) for v in self.anchors_exp_to_asset.values()),
        }
