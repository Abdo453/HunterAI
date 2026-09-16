"""
HunterAI V27.0 - Multi-Tenant Identity Matrix
=============================================
Formal Access Grid modeling principals, tenants, roles, session states,
and resource ownership.
Treats untested matrix cross-points as Candidate Experiments ('?'):
  Actor A -> Resource B  (?)
  Actor B -> Resource A  (?)
  Tenant 1 -> Tenant 2   (?)
  User -> Admin Resource (?)
  Expired Session -> Protected Resource (?)
"""
from __future__ import annotations

import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("hunter_ai.identity_matrix")


class AccessOutcome(str, Enum):
    ALLOWED = "ALLOWED"                      # Legitimate authorized access (✓)
    DENIED = "DENIED"                        # Enforced security boundary (✗)
    CANDIDATE = "CANDIDATE"                  # Untested cell: Experiment Candidate (?)
    BYPASS_CONFIRMED = "BYPASS_CONFIRMED"    # Confirmed BOLA/Privilege Escalation (!)


@dataclass
class IdentityPrincipal:
    principal_id: str              # e.g., 'user_42', 'user_43', 'admin'
    tenant_id: str = "tenant_1"    # Multi-tenant boundary
    role: str = "MEMBER"           # 'GUEST', 'MEMBER', 'MANAGER', 'ADMIN'
    session_token: Optional[str] = None
    auth_headers: Dict[str, str] = field(default_factory=dict)
    auth_state: str = "ACTIVE"     # 'ACTIVE', 'EXPIRED', 'REVOKED', 'ANONYMOUS'
    resource_ownership: Set[str] = field(default_factory=set)
    evidence_refs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["resource_ownership"] = list(self.resource_ownership)
        return d


@dataclass
class IdentityMatrixCell:
    actor_principal_id: str
    resource_id: str
    resource_owner_id: str
    outcome: AccessOutcome = AccessOutcome.CANDIDATE
    evidence_id: Optional[str] = None
    reason: str = "Untested cross-tenant boundary"
    last_tested_timestamp: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["outcome"] = self.outcome.value
        return d


class IdentityMatrixEngine:
    """
    Manages the multi-tenant cross-authorization grid.
    Identifies candidate access control experiments and records proven defense boundaries.
    """

    def __init__(self):
        self.principals: Dict[str, IdentityPrincipal] = {}
        self.resources: Dict[str, str] = {}  # resource_id -> owner_principal_id
        self.grid: Dict[Tuple[str, str], IdentityMatrixCell] = {}

    def register_principal(self, principal: IdentityPrincipal):
        """Registers an observed identity in the matrix."""
        self.principals[principal.principal_id] = principal
        for res in principal.resource_ownership:
            self.resources[res] = principal.principal_id
        self._rebuild_grid()

    def register_resource(self, resource_id: str, owner_id: str):
        """Registers a data resource and its legitimate owner."""
        self.resources[resource_id] = owner_id
        if owner_id in self.principals:
            self.principals[owner_id].resource_ownership.add(resource_id)
        self._rebuild_grid()

    def _rebuild_grid(self):
        """Populates matrix cells for all (Actor, Resource) pairs."""
        for actor_id, actor in self.principals.items():
            for res_id, owner_id in self.resources.items():
                pair = (actor_id, res_id)
                if pair not in self.grid:
                    if actor_id == owner_id:
                        # Legitimate owner access
                        self.grid[pair] = IdentityMatrixCell(
                            actor_principal_id=actor_id,
                            resource_id=res_id,
                            resource_owner_id=owner_id,
                            outcome=AccessOutcome.ALLOWED,
                            reason="Legitimate resource owner",
                        )
                    else:
                        # Cross-principal / Cross-tenant access candidate
                        self.grid[pair] = IdentityMatrixCell(
                            actor_principal_id=actor_id,
                            resource_id=res_id,
                            resource_owner_id=owner_id,
                            outcome=AccessOutcome.CANDIDATE,
                            reason="Cross-principal access candidate for verification",
                        )

    def generate_candidate_experiments(self) -> List[Dict[str, Any]]:
        """
        Synthesizes structured candidate experiments for every '?' cell in the matrix.
        """
        candidates: List[Dict[str, Any]] = []
        for (actor_id, res_id), cell in self.grid.items():
            if cell.outcome != AccessOutcome.CANDIDATE:
                continue

            actor = self.principals.get(actor_id)
            owner = self.principals.get(cell.resource_owner_id)
            if not actor or not owner:
                continue

            # Determine hypothesis category
            if actor.tenant_id != owner.tenant_id:
                vuln_category = "CROSS_TENANT_ISOLATION_BREACH"
                hypothesis = f"Actor '{actor_id}' (Tenant {actor.tenant_id}) can access Resource '{res_id}' belonging to Tenant {owner.tenant_id}"
            elif actor.role != "ADMIN" and owner.role == "ADMIN":
                vuln_category = "VERTICAL_PRIVILEGE_ESCALATION"
                hypothesis = f"Unprivileged Actor '{actor_id}' can access Administrative Resource '{res_id}'"
            elif actor.auth_state in ("EXPIRED", "REVOKED"):
                vuln_category = "REVOKED_SESSION_REUSE"
                hypothesis = f"Revoked/Expired session for '{actor_id}' can still access Resource '{res_id}'"
            else:
                vuln_category = "HORIZONTAL_BOLA_IDOR"
                hypothesis = f"Actor '{actor_id}' can access Peer Resource '{res_id}' owned by '{owner.principal_id}'"

            candidates.append({
                "candidate_id": f"cand_id_{actor_id}_to_{res_id}",
                "category": vuln_category,
                "hypothesis": hypothesis,
                "actor": actor.to_dict(),
                "target_resource_id": res_id,
                "resource_owner": owner.to_dict(),
                "mutation": {
                    "resource_parameter_override": res_id,
                    "actor_session_token": actor.session_token,
                    "actor_auth_headers": actor.auth_headers,
                },
                "expected_negative_observable": "HTTP 403 Forbidden / Authorization Denied",
            })

        return candidates

    def update_verdict(
        self,
        actor_id: str,
        resource_id: str,
        outcome: AccessOutcome,
        evidence_id: str,
        reason: str,
    ):
        """
        Updates the matrix based on real BCSL execution feedback.
        """
        pair = (actor_id, resource_id)
        owner_id = self.resources.get(resource_id, "unknown")
        cell = self.grid.get(pair)
        if not cell:
            cell = IdentityMatrixCell(
                actor_principal_id=actor_id,
                resource_id=resource_id,
                resource_owner_id=owner_id,
            )
            self.grid[pair] = cell

        cell.outcome = outcome
        cell.evidence_id = evidence_id
        cell.reason = reason
        cell.last_tested_timestamp = time.time()

        logger.info(f"[IDENTITY MATRIX] Cell ({actor_id} -> {resource_id}) updated: {outcome.value} ({reason})")

    def export_matrix_summary(self) -> Dict[str, Any]:
        """Returns JSON representation of the identity grid."""
        total_cells = len(self.grid)
        allowed = sum(1 for c in self.grid.values() if c.outcome == AccessOutcome.ALLOWED)
        denied = sum(1 for c in self.grid.values() if c.outcome == AccessOutcome.DENIED)
        candidates = sum(1 for c in self.grid.values() if c.outcome == AccessOutcome.CANDIDATE)
        bypasses = sum(1 for c in self.grid.values() if c.outcome == AccessOutcome.BYPASS_CONFIRMED)

        return {
            "principals_count": len(self.principals),
            "resources_count": len(self.resources),
            "matrix_cells_count": total_cells,
            "metrics": {
                "legitimate_allowed": allowed,
                "verified_denied": denied,
                "untested_candidates": candidates,
                "confirmed_bypasses": bypasses,
            },
            "cells": {f"{k[0]}->{k[1]}": v.to_dict() for k, v in self.grid.items()},
        }
