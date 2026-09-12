"""
SecurityState — Attack State Memory for HunterAI (Cairn-Inspired State-Space Representation)
Tracks the evolving knowledge state S_0 -> S_1 -> S_n across assets, endpoints,
identities, sessions, vulnerabilities, evidence, and causal attack paths.
"""
import time
import uuid
import logging
from typing import Dict, List, Set, Any, Optional, Tuple
from pydantic import BaseModel, Field

from agents.security_intelligence.schemas import (
    FindingStatus,
    IntelligenceFinding,
    EvidenceItem
)
from agents.security_intelligence.finding_validator import FindingValidator

log = logging.getLogger("core.state.security_state")


# -----------------------------------------------------------------------------
# Graph Node Representations
# -----------------------------------------------------------------------------

class AssetNode(BaseModel):
    host: str
    ip: Optional[str] = None
    ports: List[int] = Field(default_factory=list)
    technologies: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    first_seen: float = Field(default_factory=time.time)


class EndpointNode(BaseModel):
    url: str
    path: str
    method: str = "GET"
    parameters: List[str] = Field(default_factory=list)
    auth_required: bool = False
    role_required: Optional[str] = None
    technologies: List[str] = Field(default_factory=list)
    status_codes_seen: List[int] = Field(default_factory=list)
    first_seen: float = Field(default_factory=time.time)


class IdentityNode(BaseModel):
    username: str
    role: str = "user"
    tenant_id: Optional[str] = None
    token: Optional[str] = None
    cookies: Dict[str, str] = Field(default_factory=dict)
    is_authenticated: bool = True
    created_at: float = Field(default_factory=time.time)


class VulnerabilityNode(BaseModel):
    finding_id: str
    vulnerability_type: str
    title: str
    status: FindingStatus = FindingStatus.OBSERVED
    target: str
    endpoint: str
    confidence: float = 0.5
    severity: str = "MEDIUM"
    hypotheses_validated: List[str] = Field(default_factory=list)
    reasoning_chain: List[str] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)
    poc_steps: List[str] = Field(default_factory=list)
    reproduction_curl: Optional[str] = None
    impact_description: Optional[str] = None
    updated_at: float = Field(default_factory=time.time)


class AttackPathNode(BaseModel):
    id: str = Field(default_factory=lambda: f"PATH-{uuid.uuid4().hex[:6]}")
    title: str
    steps: List[str] = Field(default_factory=list)
    source_node: str
    target_node: str
    status: str = "potential"  # "potential", "active", "confirmed", "broken"
    created_at: float = Field(default_factory=time.time)


# -----------------------------------------------------------------------------
# Central Attack State Memory
# -----------------------------------------------------------------------------

class SecurityState(BaseModel):
    """
    ذاكرة حالة الهجوم والأمن (Cairn-inspired Attack State Memory):
    تمثل الفضاء الحقيقي لمعرفة الـ Agent وتتطور عبر انتقالات الحالات S_0 -> S_1 -> S_n
    """
    target: str
    project_id: str = "default_project"
    version: int = 1
    
    # State components
    assets: Dict[str, AssetNode] = Field(default_factory=dict)
    endpoints: Dict[str, EndpointNode] = Field(default_factory=dict)
    technologies: List[str] = Field(default_factory=list)
    identities: Dict[str, IdentityNode] = Field(default_factory=dict)
    sessions: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    vulnerabilities: Dict[str, VulnerabilityNode] = Field(default_factory=dict)
    evidence_store: Dict[str, EvidenceItem] = Field(default_factory=dict)
    
    # Epistemic tracking (what we know vs what we need to find out)
    known_facts: List[str] = Field(default_factory=list)
    unknowns: List[str] = Field(default_factory=list)
    attack_paths: List[AttackPathNode] = Field(default_factory=list)
    
    # Audit transition history
    transitions: List[Dict[str, Any]] = Field(default_factory=list)
    last_updated: float = Field(default_factory=time.time)

    # ── State Mutation Methods ──────────────────────────────────────────────

    def add_asset(
        self,
        host: str,
        ip: Optional[str] = None,
        ports: Optional[List[int]] = None,
        technologies: Optional[List[str]] = None,
        tags: Optional[List[str]] = None
    ) -> AssetNode:
        """Register or update an asset in state"""
        clean_host = host.strip().lower()
        if clean_host not in self.assets:
            node = AssetNode(
                host=clean_host,
                ip=ip,
                ports=ports or [],
                technologies=technologies or [],
                tags=tags or []
            )
            self.assets[clean_host] = node
            self._record_transition("add_asset", f"Discovered asset {clean_host}")
        else:
            node = self.assets[clean_host]
            if ip and not node.ip:
                node.ip = ip
            if ports:
                node.ports = sorted(list(set(node.ports + ports)))
            if technologies:
                node.technologies = sorted(list(set(node.technologies + technologies)))
            if tags:
                node.tags = sorted(list(set(node.tags + tags)))
        
        # Add technologies to global state pool
        if technologies:
            for t in technologies:
                if t not in self.technologies:
                    self.technologies.append(t)

        return self.assets[clean_host]

    def add_endpoint(
        self,
        path: str,
        method: str = "GET",
        url: Optional[str] = None,
        parameters: Optional[List[str]] = None,
        auth_required: bool = False,
        role_required: Optional[str] = None,
        status_code: Optional[int] = None,
        technologies: Optional[List[str]] = None
    ) -> EndpointNode:
        """Register or update an endpoint in state"""
        key = f"{method.upper()} {path}"
        computed_url = url or f"https://{self.target}{path}"
        if key not in self.endpoints:
            node = EndpointNode(
                url=computed_url,
                path=path,
                method=method.upper(),
                parameters=parameters or [],
                auth_required=auth_required,
                role_required=role_required,
                technologies=technologies or [],
                status_codes_seen=[status_code] if status_code else []
            )
            self.endpoints[key] = node
            self._record_transition("add_endpoint", f"Discovered endpoint {key}")
        else:
            node = self.endpoints[key]
            if parameters:
                node.parameters = sorted(list(set(node.parameters + parameters)))
            if auth_required:
                node.auth_required = True
            if role_required and not node.role_required:
                node.role_required = role_required
            if status_code and status_code not in node.status_codes_seen:
                node.status_codes_seen.append(status_code)
            if technologies:
                node.technologies = sorted(list(set(node.technologies + technologies)))

        return self.endpoints[key]

    def add_identity(
        self,
        username: str,
        role: str = "user",
        tenant_id: Optional[str] = None,
        token: Optional[str] = None,
        cookies: Optional[Dict[str, str]] = None
    ) -> IdentityNode:
        """Register an authenticated identity / role in state"""
        clean_user = username.strip()
        node = IdentityNode(
            username=clean_user,
            role=role,
            tenant_id=tenant_id,
            token=token,
            cookies=cookies or {}
        )
        self.identities[clean_user] = node
        self._record_transition("add_identity", f"Acquired identity {clean_user} ({role})")
        return node

    def add_evidence(self, item: EvidenceItem) -> None:
        """Store raw verified evidence in state"""
        self.evidence_store[item.id] = item
        self._record_transition("add_evidence", f"Stored evidence {item.type.value} ({item.id})")

    def record_finding(self, finding: IntelligenceFinding) -> VulnerabilityNode:
        """Synchronize an IntelligenceFinding into state"""
        # Store evidence items into store
        for ev in finding.evidence:
            self.evidence_store[ev.id] = ev

        v_node = VulnerabilityNode(
            finding_id=finding.id,
            vulnerability_type=finding.vulnerability_type,
            title=finding.title,
            status=finding.status,
            target=finding.target,
            endpoint=finding.reasoning_chain[0] if finding.reasoning_chain else finding.target,
            confidence=finding.confidence_score,
            severity=finding.severity.value,
            hypotheses_validated=finding.hypotheses_validated,
            reasoning_chain=finding.reasoning_chain,
            evidence_ids=[e.id for e in finding.evidence],
            poc_steps=finding.poc_steps,
            reproduction_curl=finding.reproduction_curl,
            impact_description=finding.impact_description
        )
        self.vulnerabilities[finding.id] = v_node
        self._record_transition("record_finding", f"Registered finding {finding.id} as {finding.status.value}")
        return v_node

    def transition_finding_status(
        self,
        finding_id: str,
        target_status: FindingStatus,
        validator: Optional[FindingValidator] = None,
        new_evidence: Optional[List[EvidenceItem]] = None,
        poc_steps: Optional[List[str]] = None,
        reproduction_curl: Optional[str] = None,
        impact_description: Optional[str] = None,
        rationale: str = ""
    ) -> Tuple[bool, str]:
        """Transition finding status through evidence-gated validator"""
        if finding_id not in self.vulnerabilities:
            return False, f"Finding '{finding_id}' not found in state."

        v_node = self.vulnerabilities[finding_id]

        if validator:
            # Reconstruct dummy IntelligenceFinding for validation
            from agents.security_intelligence.schemas import SeverityLevel, ConfidenceLevel
            dummy_finding = IntelligenceFinding(
                id=v_node.finding_id,
                target=v_node.target,
                title=v_node.title,
                vulnerability_type=v_node.vulnerability_type,
                severity=SeverityLevel(v_node.severity),
                confidence_score=v_node.confidence,
                confidence_level=ConfidenceLevel.HIGH if v_node.confidence >= 0.8 else ConfidenceLevel.POSSIBLE,
                status=v_node.status,
                hypotheses_validated=v_node.hypotheses_validated,
                reasoning_chain=v_node.reasoning_chain,
                evidence=[self.evidence_store[eid] for eid in v_node.evidence_ids if eid in self.evidence_store],
                poc_steps=v_node.poc_steps,
                reproduction_curl=v_node.reproduction_curl,
                impact_description=v_node.impact_description
            )
            success, reason, updated = validator.transition_finding(
                finding=dummy_finding,
                target_status=target_status,
                new_evidence=new_evidence,
                poc_steps=poc_steps,
                reproduction_curl=reproduction_curl,
                impact_description=impact_description,
                rationale=rationale
            )
            if not success:
                return False, reason

            # Apply updates to state node
            v_node.status = updated.status
            v_node.confidence = updated.confidence_score
            v_node.poc_steps = updated.poc_steps
            v_node.reproduction_curl = updated.reproduction_curl
            v_node.impact_description = updated.impact_description
            if new_evidence:
                for ev in new_evidence:
                    self.evidence_store[ev.id] = ev
                    if ev.id not in v_node.evidence_ids:
                        v_node.evidence_ids.append(ev.id)
            v_node.updated_at = time.time()
            self._record_transition("transition_finding", f"Finding {finding_id} -> {target_status.value} ({reason})")
            return True, reason
        else:
            # Direct transition without validator
            prev = v_node.status
            v_node.status = target_status
            v_node.updated_at = time.time()
            self._record_transition("transition_finding", f"Finding {finding_id} direct transition {prev.value} -> {target_status.value}")
            return True, f"Direct transition to {target_status.value}"

    def add_unknown(self, question: str) -> None:
        """Record an unanswered security hypothesis/question to drive exploration"""
        clean_q = question.strip()
        if clean_q and clean_q not in self.unknowns:
            self.unknowns.append(clean_q)
            self._record_transition("add_unknown", f"Added exploratory unknown: '{clean_q}'")

    def resolve_unknown(self, question: str, fact: str) -> None:
        """Resolve an unknown into an established known fact"""
        clean_q = question.strip()
        clean_fact = fact.strip()
        if clean_q in self.unknowns:
            self.unknowns.remove(clean_q)
        if clean_fact and clean_fact not in self.known_facts:
            self.known_facts.append(clean_fact)
        self._record_transition("resolve_unknown", f"Resolved unknown '{clean_q}' -> Fact: '{clean_fact}'")

    def add_attack_path(
        self,
        title: str,
        steps: List[str],
        source_node: str,
        target_node: str,
        status: str = "potential"
    ) -> AttackPathNode:
        """Record a causal multi-hop attack chain"""
        path = AttackPathNode(
            title=title,
            steps=steps,
            source_node=source_node,
            target_node=target_node,
            status=status
        )
        self.attack_paths.append(path)
        self._record_transition("add_attack_path", f"Formulated attack path '{title}' ({source_node} -> {target_node})")
        return path

    def _record_transition(self, action: str, description: str) -> None:
        """Increment version and record state delta transition log"""
        self.version += 1
        self.last_updated = time.time()
        self.transitions.append({
            "version": self.version,
            "action": action,
            "description": description,
            "timestamp": self.last_updated
        })

    def get_snapshot(self) -> Dict[str, Any]:
        """Export serialized snapshot for UI, AI reasoning, and persistence"""
        return {
            "target": self.target,
            "project_id": self.project_id,
            "version": self.version,
            "last_updated": self.last_updated,
            "summary": {
                "assets_count": len(self.assets),
                "endpoints_count": len(self.endpoints),
                "technologies_count": len(self.technologies),
                "identities_count": len(self.identities),
                "vulnerabilities_count": len(self.vulnerabilities),
                "status_breakdown": self._get_status_breakdown(),
                "unknowns_count": len(self.unknowns),
                "known_facts_count": len(self.known_facts),
                "attack_paths_count": len(self.attack_paths)
            },
            "assets": {k: v.model_dump() for k, v in self.assets.items()},
            "endpoints": {k: v.model_dump() for k, v in self.endpoints.items()},
            "technologies": list(self.technologies),
            "identities": {k: v.model_dump() for k, v in self.identities.items()},
            "vulnerabilities": {k: v.model_dump() for k, v in self.vulnerabilities.items()},
            "known_facts": list(self.known_facts),
            "unknowns": list(self.unknowns),
            "attack_paths": [p.model_dump() for p in self.attack_paths],
            "recent_transitions": self.transitions[-10:]
        }

    def _get_status_breakdown(self) -> Dict[str, int]:
        breakdown = {s.value: 0 for s in FindingStatus}
        for v in self.vulnerabilities.values():
            breakdown[v.status.value] = breakdown.get(v.status.value, 0) + 1
        return breakdown
