"""
HunterAI Security Knowledge Compiler & Security Intermediate Representation (SIR)
================================================================================
Compiles heterogeneous security knowledge sources:
- OpenAPI / Swagger specifications
- Burp Suite HTTP wire telemetry
- Browser DOM actions and form affordances
- Code AST route handlers and data sinks
- Application logs & Network traces

into a unified, normalized, graph-based Security Intermediate Representation (SIR).
Enables all downstream reasoning, attack path simulation, and contract verification
to operate against a single canonical model rather than writing source-specific adapters.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("hunter_ai.compiler.sir")


class SIREntityType(str, Enum):
    ENDPOINT = "ENDPOINT"
    IDENTITY = "IDENTITY"
    RESOURCE = "RESOURCE"
    PARAMETER = "PARAMETER"
    SINK = "SINK"
    CONTROL = "CONTROL"
    STATE_TRANSITION = "STATE_TRANSITION"


@dataclass
class SIREntity:
    """Canonical Security IR Entity Node"""
    entity_id: str
    entity_type: SIREntityType
    name: str
    attributes: Dict[str, Any] = field(default_factory=dict)
    observed_sources: Set[str] = field(default_factory=set)
    evidence_refs: List[str] = field(default_factory=list)
    confidence: float = 1.0
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type.value,
            "name": self.name,
            "attributes": self.attributes,
            "observed_sources": sorted(list(self.observed_sources)),
            "evidence_refs": self.evidence_refs,
            "confidence": self.confidence,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SIREntity:
        return cls(
            entity_id=data["entity_id"],
            entity_type=SIREntityType(data["entity_type"]),
            name=data["name"],
            attributes=data.get("attributes", {}),
            observed_sources=set(data.get("observed_sources", [])),
            evidence_refs=data.get("evidence_refs", []),
            confidence=data.get("confidence", 1.0),
            created_at=data.get("created_at", time.time()),
        )


@dataclass
class SIRRelationship:
    """Directed edge representing causal, access, or dataflow relationship"""
    rel_id: str
    source_id: str
    target_id: str
    rel_type: str  # e.g., "ROUTES_TO", "MANIPULATES", "GUARDS", "FLOWS_TO", "AUTHENTICATES"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SIRGraph:
    """In-memory Canonical Security Knowledge Graph"""

    def __init__(self, target_host: str = "target.local"):
        self.target_host = target_host
        self.entities: Dict[str, SIREntity] = {}
        self.relationships: List[SIRRelationship] = []

    def add_entity(self, entity: SIREntity) -> SIREntity:
        if entity.entity_id in self.entities:
            # Merge sources and evidence
            existing = self.entities[entity.entity_id]
            existing.observed_sources.update(entity.observed_sources)
            existing.evidence_refs = list(set(existing.evidence_refs + entity.evidence_refs))
            existing.attributes.update(entity.attributes)
            return existing
        self.entities[entity.entity_id] = entity
        return entity

    def add_relationship(self, source_id: str, target_id: str, rel_type: str, metadata: Optional[Dict[str, Any]] = None) -> SIRRelationship:
        rel_id = f"rel_{hashlib.sha256(f'{source_id}:{rel_type}:{target_id}'.encode()).hexdigest()[:8]}"
        rel = SIRRelationship(
            rel_id=rel_id,
            source_id=source_id,
            target_id=target_id,
            rel_type=rel_type,
            metadata=metadata or {}
        )
        self.relationships.append(rel)
        return rel

    def find_by_type(self, entity_type: SIREntityType) -> List[SIREntity]:
        return [e for e in self.entities.values() if e.entity_type == entity_type]

    def get_endpoints(self) -> List[SIREntity]:
        return self.find_by_type(SIREntityType.ENDPOINT)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_host": self.target_host,
            "total_entities": len(self.entities),
            "total_relationships": len(self.relationships),
            "entities": {eid: e.to_dict() for eid, e in self.entities.items()},
            "relationships": [r.to_dict() for r in self.relationships],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class SecurityKnowledgeCompiler:
    """
    Normalizes diverse operational telemetry into the canonical SIR format.
    """

    @classmethod
    def compile_openapi(cls, spec_dict: Dict[str, Any], target_host: str = "api.target.local") -> SIRGraph:
        """Compiles OpenAPI / Swagger specification into canonical SIR entities"""
        graph = SIRGraph(target_host=target_host)
        paths = spec_dict.get("paths", {})

        for path, methods in paths.items():
            for method, details in methods.items():
                if method.lower() not in ("get", "post", "put", "delete", "patch", "options", "head"):
                    continue
                method_upper = method.upper()
                ep_id = f"ep_{method_upper}_{path.replace('/', '_').strip('_')}"
                
                auth_required = bool(details.get("security") or spec_dict.get("security"))
                tags = details.get("tags", [])

                ep_entity = SIREntity(
                    entity_id=ep_id,
                    entity_type=SIREntityType.ENDPOINT,
                    name=f"{method_upper} {path}",
                    attributes={
                        "path": path,
                        "method": method_upper,
                        "auth_required": auth_required,
                        "tags": tags,
                        "summary": details.get("summary", ""),
                    },
                    observed_sources={"OPENAPI_SPEC"},
                    confidence=1.0,
                )
                graph.add_entity(ep_entity)

                # Parameters
                for p in details.get("parameters", []):
                    p_name = p.get("name")
                    if p_name:
                        param_id = f"param_{p_name}_{ep_id}"
                        p_entity = SIREntity(
                            entity_id=param_id,
                            entity_type=SIREntityType.PARAMETER,
                            name=p_name,
                            attributes={
                                "in": p.get("in", "query"),
                                "required": p.get("required", False),
                                "schema": p.get("schema", {}),
                            },
                            observed_sources={"OPENAPI_SPEC"},
                        )
                        graph.add_entity(p_entity)
                        graph.add_relationship(ep_id, param_id, "ACCEPTS_PARAMETER")

        return graph

    @classmethod
    def compile_burp_transaction(cls, tx: Any, target_host: str = "app.local") -> SIRGraph:
        """Compiles captured Burp HTTP wire transaction into SIR entities"""
        graph = SIRGraph(target_host=target_host)
        
        # Support BurpSessionContext, dict, or object
        method = getattr(tx, "method", "GET") if hasattr(tx, "method") else tx.get("method", "GET")
        url = getattr(tx, "url", "") if hasattr(tx, "url") else tx.get("url", "")
        status_code = getattr(tx, "status_code", 200) if hasattr(tx, "status_code") else tx.get("status_code", 200)
        auth_context = getattr(tx, "auth_context", "ANONYMOUS") if hasattr(tx, "auth_context") else tx.get("auth_context", "ANONYMOUS")
        req_id = getattr(tx, "request_id", "req_01") if hasattr(tx, "request_id") else tx.get("request_id", "req_01")

        from urllib.parse import urlparse
        path = urlparse(url).path or "/"
        ep_id = f"ep_{method.upper()}_{path.replace('/', '_').strip('_')}"

        ep_entity = SIREntity(
            entity_id=ep_id,
            entity_type=SIREntityType.ENDPOINT,
            name=f"{method.upper()} {path}",
            attributes={
                "url": url,
                "path": path,
                "method": method.upper(),
                "last_status_code": status_code,
                "auth_required": auth_context != "ANONYMOUS",
            },
            observed_sources={"BURP_WIRE_SENSOR"},
            evidence_refs=[req_id],
        )
        graph.add_entity(ep_entity)

        # Identity
        id_entity_id = f"ident_{auth_context.replace(' ', '_').lower()}"
        id_entity = SIREntity(
            entity_id=id_entity_id,
            entity_type=SIREntityType.IDENTITY,
            name=auth_context,
            attributes={"role": "ADMIN" if "admin" in auth_context.lower() else "USER"},
            observed_sources={"BURP_WIRE_SENSOR"},
        )
        graph.add_entity(id_entity)
        graph.add_relationship(id_entity_id, ep_id, "EXECUTES_REQUEST", {"request_id": req_id})

        return graph

    @classmethod
    def compile_browser_event(cls, action_type: str, selector: str, page_url: str, label: str = "") -> SIRGraph:
        """Compiles user interactive action into SIR entities"""
        from urllib.parse import urlparse
        host = urlparse(page_url).netloc or "app.local"
        graph = SIRGraph(target_host=host)

        action_id = f"ui_{action_type}_{hashlib.md5(selector.encode()).hexdigest()[:6]}"
        entity = SIREntity(
            entity_id=action_id,
            entity_type=SIREntityType.RESOURCE,
            name=label or selector,
            attributes={
                "action_type": action_type,
                "selector": selector,
                "page_url": page_url,
            },
            observed_sources={"BROWSER_DOM_SENSOR"},
        )
        graph.add_entity(entity)
        return graph

    @classmethod
    def merge_graphs(cls, *graphs: SIRGraph) -> SIRGraph:
        """Merges multiple SIRGraphs into a unified authoritative model"""
        if not graphs:
            return SIRGraph()
        
        merged = SIRGraph(target_host=graphs[0].target_host)
        for g in graphs:
            for entity in g.entities.values():
                merged.add_entity(entity)
            for rel in g.relationships:
                merged.relationships.append(rel)

        return merged
