"""
HunterAI Identity Graph & Multi-Identity Authorization Replayer
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional

from core.identity.schemas import AuthZAnomalyType, AuthZDifferentialResult, IdentityContext

logger = logging.getLogger("hunter_ai.identity_graph")


class IdentityGraph:
    """
    Maintains target application identity contexts, roles, and tenant boundaries.
    Allows HunterAI to reason about authorization across multiple actors.
    """

    def __init__(self):
        self._identities: Dict[str, IdentityContext] = {}
        self._resource_ownership: Dict[str, str] = {}  # resource_id -> identity_id
        self._initialize_default_identities()

    def _initialize_default_identities(self):
        """Pre-seeds standard investigation profiles"""
        self.register_identity(IdentityContext(
            identity_id="anonymous",
            tenant_id="none",
            roles=["anonymous"],
            tokens={},
            cookies={}
        ))
        self.register_identity(IdentityContext(
            identity_id="user_a",
            tenant_id="tenant_alpha",
            roles=["user"],
            tokens={"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.user_a"},
            cookies={"session_id": "sess_user_a_88921"}
        ))
        self.register_identity(IdentityContext(
            identity_id="user_b",
            tenant_id="tenant_beta",
            roles=["user"],
            tokens={"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.user_b"},
            cookies={"session_id": "sess_user_b_77341"}
        ))
        self.register_identity(IdentityContext(
            identity_id="admin",
            tenant_id="tenant_alpha",
            roles=["admin", "superadmin"],
            tokens={"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.admin_token"},
            cookies={"session_id": "sess_admin_root_001"}
        ))

    def register_identity(self, identity: IdentityContext):
        self._identities[identity.identity_id] = identity
        logger.info(f"[IDENTITY_GRAPH] Registered identity: {identity.identity_id} (roles: {identity.roles})")

    def get_identity(self, identity_id: str) -> Optional[IdentityContext]:
        return self._identities.get(identity_id)

    def list_identities(self) -> List[IdentityContext]:
        return list(self._identities.values())

    def bind_resource_owner(self, resource_id: str, owner_identity_id: str):
        self._resource_ownership[resource_id] = owner_identity_id

    def get_resource_owner(self, resource_id: str) -> Optional[str]:
        return self._resource_ownership.get(resource_id)


class MultiIdentityReplayer:
    """
    Executes cross-identity differential authorization testing.
    Pits requests from Identity A against Identity B, Admin, and Anonymous.
    """

    def __init__(self, identity_graph: Optional[IdentityGraph] = None):
        self.identity_graph = identity_graph or IdentityGraph()

    def replay_authorization_matrix(
        self,
        endpoint: str,
        method: str,
        target_object_id: str,
        owner_identity_id: str,
        simulator_fn: Optional[Callable[[str, IdentityContext], Dict[str, Any]]] = None
    ) -> List[AuthZDifferentialResult]:
        """
        Replays request across all registered identities.
        Uses simulator_fn if provided, or default deterministic simulation.
        """
        results: List[AuthZDifferentialResult] = []
        owner = self.identity_graph.get_identity(owner_identity_id)
        if not owner:
            return results

        # Baseline request as owner
        if simulator_fn:
            baseline_resp = simulator_fn(target_object_id, owner)
        else:
            baseline_resp = {
                "status": 200,
                "body": f'{{"order_id": "{target_object_id}", "owner": "{owner_identity_id}", "secret_data": "CONFIDENTIAL"}}',
                "private_data": ["CONFIDENTIAL", target_object_id]
            }

        baseline_status = baseline_resp.get("status", 200)
        baseline_length = len(baseline_resp.get("body", ""))
        private_markers = baseline_resp.get("private_data", ["CONFIDENTIAL"])

        # Replay against every other identity
        for ident in self.identity_graph.list_identities():
            if ident.identity_id == owner_identity_id:
                continue

            if simulator_fn:
                test_resp = simulator_fn(target_object_id, ident)
            else:
                # Default simulation behavior: vulnerable if target_object_id contains 'insecure' or 'vuln'
                is_vulnerable = "vuln" in endpoint.lower() or "insecure" in endpoint.lower()
                if is_vulnerable:
                    test_resp = {
                        "status": 200,
                        "body": baseline_resp.get("body", ""),
                        "private_data": private_markers
                    }
                else:
                    if ident.is_anonymous():
                        test_resp = {"status": 401, "body": '{"error": "Unauthorized"}'}
                    elif ident.is_admin():
                        test_resp = {"status": 200, "body": '{"status": "Admin audit view"}'}
                    else:
                        test_resp = {"status": 403, "body": '{"error": "Forbidden: Not object owner"}'}

            test_status = test_resp.get("status", 200)
            test_body = test_resp.get("body", "")
            test_length = len(test_body)

            # Check if private markers leaked
            leaked = any(marker in test_body for marker in private_markers)

            is_anomaly = False
            anomaly_type = None
            rationale = ""

            if ident.is_anonymous():
                if test_status == 200 and leaked:
                    is_anomaly = True
                    anomaly_type = AuthZAnomalyType.UNAUTHENTICATED_INFORMATION_LEAK
                    rationale = f"Anonymous request succeeded with 200 OK and leaked sensitive owner data on {endpoint}."
            elif ident.is_admin():
                # Admin accessing user data is typically authorized unless tenant boundary strictly forbids
                pass
            else:
                # Cross-tenant / Horizontal user comparison
                is_cross_tenant = ident.tenant_id != owner.tenant_id
                if test_status == 200 and leaked:
                    is_anomaly = True
                    if is_cross_tenant:
                        anomaly_type = AuthZAnomalyType.CROSS_TENANT_BREACH
                        rationale = f"Cross-tenant identity {ident.identity_id} ({ident.tenant_id}) accessed {owner.identity_id} ({owner.tenant_id}) object {target_object_id}."
                    else:
                        anomaly_type = AuthZAnomalyType.BOLA_HORIZONTAL_ACCESS
                        rationale = f"Horizontal peer {ident.identity_id} successfully retrieved private object {target_object_id} of {owner.identity_id}."
                elif test_status == 200 and not leaked:
                    # Generic 200 OK without private data -> Strict suppression
                    rationale = "Status 200 OK observed but no sensitive private data leaked (Shielded)."

            # Also check vertical privilege escalation on administrative endpoints
            if "admin" in endpoint.lower() and not ident.is_admin() and not ident.is_anonymous():
                if test_status == 200:
                    is_anomaly = True
                    anomaly_type = AuthZAnomalyType.BFLA_VERTICAL_PRIVILEGE_ESCALATION
                    rationale = f"Non-admin identity {ident.identity_id} accessed restricted admin endpoint {endpoint}."

            results.append(AuthZDifferentialResult(
                endpoint=endpoint,
                method=method,
                target_object_id=target_object_id,
                base_identity=owner_identity_id,
                tested_identity=ident.identity_id,
                is_anomaly=is_anomaly,
                anomaly_type=anomaly_type,
                baseline_status=baseline_status,
                tested_status=test_status,
                baseline_content_length=baseline_length,
                tested_content_length=test_length,
                sensitive_data_leaked=leaked,
                evidence_rationale=rationale
            ))

        return results
