"""
Evidence-Based Attack Graph Engine for BurpAgent
Constructs directed graphs representing application states, transitions, and privilege escalation paths.
"""
import logging
from typing import Dict, Any, List, Optional
from agents.burp_agent.storage.models import GraphNodeModel, GraphEdgeModel, HTTPRequestModel
from agents.burp_agent.storage.database import TrafficDatabase

log = logging.getLogger("burp_agent.attack_graph")


class AttackGraphEngine:
    """محرك رسم شجرة الهجوم المبنية على الأدلة والمسارات المكتشفة فعلياً"""

    def __init__(self, db: TrafficDatabase):
        self.db = db

    def update_from_request(self, req: HTTPRequestModel):
        """تحديث عقد وحواف شجرة الهجوم وفقاً للطلب المكتشف"""
        node_id = f"endpoint:{req.method}:{req.path}"
        node = GraphNodeModel(
            id=node_id,
            label=f"{req.method} {req.path}",
            node_type="endpoint",
            metadata={"host": req.host, "params_count": len(req.parameters)}
        )
        self.db.upsert_graph_node(node)

        # Link parameters to endpoint node
        for p in req.parameters:
            if p.is_user_controlled_id or p.is_role_indicator:
                param_node_id = f"param:{p.name}:{p.value}"
                p_node = GraphNodeModel(
                    id=param_node_id,
                    label=f"Param: {p.name}={p.value}",
                    node_type="parameter",
                    metadata={"is_user_id": p.is_user_controlled_id, "is_role": p.is_role_indicator}
                )
                self.db.upsert_graph_node(p_node)

                # Edge from endpoint to param
                edge = GraphEdgeModel(
                    source_node=node_id,
                    target_node=param_node_id,
                    relationship="EXPOSES_PARAMETER",
                    confidence=0.95
                )
                self.db.insert_graph_edge(edge)
