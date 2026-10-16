"""
HunterAI Security Digital Twin / World Model
نموذج الهدف الرقمي — يحتوى على الهويات، الموارد، العلاقات، والنقاط الضعيفة
مقتبس من فكرة HunterAI Architecture Layer 2: IdentityGraph & AuthZ Matrix
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set
from enum import Enum

log = logging.getLogger("hunter_ai.world_model")


class IdentityContextType(str):
    ANONYMOUS = "anonymous"
    USER = "user"
    ADMIN = "admin"
    SUPPORT = "support"
    SERVICE = "service"
    GUEST = "guest"


@dataclass
class IdentityContext:
    """سياق هوية واحد في النموذج الرقمي"""
    identity_id: str
    identity_type: str  # anonymous, user, admin, support, service, guest
    tenant_id: Optional[str] = None
    roles: List[str] = field(default_factory=list)
    tokens: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    privileges: List[str] = field(default_factory=list)
    discovered_at: float = field(default_factory=time.time)
    last_verified: Optional[float] = None
    is_compromised: bool = False

    def to_dict(self) -> dict:
        return {
            "identity_id": self.identity_id,
            "identity_type": self.identity_type,
            "tenant_id": self.tenant_id,
            "roles": self.roles,
            "tokens": self.tokens,
            "cookies": self.cookies,
            "privileges": self.privileges,
            "discovered_at": self.discovered_at,
            "last_verified": self.last_verified,
            "is_compromised": self.is_compromised,
        }


@dataclass
class ResourceObject:
    """كائن مورد واحد في الهدف (نقطة نهاية، ملف، قاعدة بيانات، إلخ)"""
    resource_id: str
    resource_type: str  # endpoint, file, database, api, panel, ...
    url: Optional[str] = None
    owner_identity_id: Optional[str] = None
    tenant_id: Optional[str] = None
    sensitivity: str = "low"  # low, medium, high, critical
    authentication_required: bool = False
    authorization_required: bool = False
    known_vulnerabilities: List[str] = field(default_factory=list)
    discovered_at: float = field(default_factory=time.time)
    is_alive: bool = True

    def to_dict(self) -> dict:
        return {
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "url": self.url,
            "owner_identity_id": self.owner_identity_id,
            "tenant_id": self.tenant_id,
            "sensitivity": self.sensitivity,
            "authentication_required": self.authentication_required,
            "authorization_required": self.authorization_required,
            "known_vulnerabilities": self.known_vulnerabilities,
            "discovered_at": self.discovered_at,
            "is_alive": self.is_alive,
        }


@dataclass
class AuthZAnomaly:
    """شذوذ في التفويض (مثلاً: مستخدم A يرى بيانات مستخدم B)"""
    anomaly_id: str
    anomaly_type: str  # IDOR, BOLA, privilege_escalation, ...
    resource_id: str
    actor_identity_id: str
    victim_identity_id: Optional[str]
    description: str
    severity: str = "medium"
    evidence: List[str] = field(default_factory=list)
    confirmed: bool = False

    def to_dict(self) -> dict:
        return {
            "anomaly_id": self.anomaly_id,
            "anomaly_type": self.anomaly_type,
            "resource_id": self.resource_id,
            "actor_identity_id": self.actor_identity_id,
            "victim_identity_id": self.victim_identity_id,
            "description": self.description,
            "severity": self.severity,
            "evidence": self.evidence,
            "confirmed": self.confirmed,
        }


class SecurityDigitalTwin:
    """
    النموذج الرقمي للهدف — يحتوى على كل ما تم اكتشافه عن الهدف
    من هويات، موارد، علاقات، وشذوذات تفويض.
    """

    def __init__(self, target: str):
        self.target = target
        self.identities: Dict[str, IdentityContext] = {}
        self.resources: Dict[str, ResourceObject] = {}
        self.authz_anomalies: Dict[str, AuthZAnomaly] = {}
        self.relationships: Dict[str, List[str]] = field(default_factory=dict)  # resource_id -> [related_resource_ids]
        self.created_at: float = time.time()
        self.last_updated: float = time.time()

    # ── هويات ────────────────────────────────────────────────────

    def register_identity(self, identity: IdentityContext):
        self.identities[identity.identity_id] = identity
        self.last_updated = time.time()
        log.debug(f"[DigitalTwin] Registered identity: {identity.identity_id} ({identity.identity_type})")

    def get_identity(self, identity_id: str) -> Optional[IdentityContext]:
        return self.identities.get(identity_id)

    def list_identities(self) -> List[IdentityContext]:
        return list(self.identities.values())

    def mark_compromised(self, identity_id: str):
        if identity_id in self.identities:
            self.identities[identity_id].is_compromised = True
            self.identities[identity_id].last_verified = time.time()
            self.last_updated = time.time()

    # ── موارد ────────────────────────────────────────────────────

    def register_resource(self, resource: ResourceObject):
        self.resources[resource.resource_id] = resource
        self.last_updated = time.time()
        log.debug(f"[DigitalTwin] Registered resource: {resource.resource_id} ({resource.resource_type})")

    def get_resource(self, resource_id: str) -> Optional[ResourceObject]:
        return self.resources.get(resource_id)

    def list_resources(self) -> List[ResourceObject]:
        return list(self.resources.values())

    def list_resources_by_owner(self, identity_id: str) -> List[ResourceObject]:
        return [r for r in self.resources.values() if r.owner_identity_id == identity_id]

    # ── علاقات ───────────────────────────────────────────────────

    def add_relationship(self, resource_id_a: str, resource_id_b: str):
        self.relationships.setdefault(resource_id_a, []).append(resource_id_b)
        self.relationships.setdefault(resource_id_b, []).append(resource_id_a)
        self.last_updated = time.time()

    def get_related_resources(self, resource_id: str) -> List[str]:
        return self.relationships.get(resource_id, [])

    # ── شذوذات تفويض ────────────────────────────────────────────

    def register_anomaly(self, anomaly: AuthZAnomaly):
        self.authz_anomalies[anomaly.anomaly_id] = anomaly
        self.last_updated = time.time()
        log.warning(f"[DigitalTwin] AuthZ anomaly: {anomaly.anomaly_type} on {anomaly.resource_id}")

    def list_anomalies(self) -> List[AuthZAnomaly]:
        return list(self.authz_anomalies.values())

    def list_confirmed_anomalies(self) -> List[AuthZAnomaly]:
        return [a for a in self.authz_anomalies.values() if a.confirmed]

    # ── ملخص ────────────────────────────────────────────────────

    def summary(self) -> dict:
        return {
            "target": self.target,
            "identities_count": len(self.identities),
            "resources_count": len(self.resources),
            "anomalies_count": len(self.authz_anomalies),
            "confirmed_anomalies_count": len(self.list_confirmed_anomalies()),
            "relationships_count": sum(len(v) for v in self.relationships.values()) // 2,
            "created_at": self.created_at,
            "last_updated": self.last_updated,
        }

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "identities": {k: v.to_dict() for k, v in self.identities.items()},
            "resources": {k: v.to_dict() for k, v in self.resources.items()},
            "anomalies": {k: v.to_dict() for k, v in self.authz_anomalies.items()},
            "relationships": self.relationships,
            "created_at": self.created_at,
            "last_updated": self.last_updated,
        }


# مثيل افتراضي يمكن استخدامه في toda the system
digital_twin: Optional[SecurityDigitalTwin] = None


def get_digital_twin(target: str = "default") -> SecurityDigitalTwin:
    global digital_twin
    if digital_twin is None or digital_twin.target != target:
        digital_twin = SecurityDigitalTwin(target)
    return digital_twin
