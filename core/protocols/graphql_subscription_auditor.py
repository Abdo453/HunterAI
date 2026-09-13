"""
HunterAI GraphQL Subscription & Pub/Sub Tenant Isolation Auditor (V13.0)
========================================================================
Audits GraphQL Subscriptions over WebSockets:
1. Protocol Initialization & Token Authentication (`connection_init`).
2. Cross-Tenant Data Leak Detection:
   - Verifies whether events intended for Tenant B are delivered to Tenant A.
3. Subscription Complexity & Pub/Sub Resource Exhaustion.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class GraphQLSubProtocol(str, Enum):
    GRAPHQL_WS = "graphql-ws"
    SUBSCRIPTIONS_TRANSPORT_WS = "subscriptions-transport-ws"


@dataclass
class SubscriptionAuditEvent:
    query: str
    subscriber_tenant_id: str
    emitted_event_tenant_id: str
    is_cross_tenant_leak: bool
    severity: str
    details: str
    cwe_id: str = "CWE-639"  # Broken Object Level Authorization / Tenant Boundary Violation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "query": self.query,
            "subscriber_tenant_id": self.subscriber_tenant_id,
            "emitted_event_tenant_id": self.emitted_event_tenant_id,
            "is_cross_tenant_leak": self.is_cross_tenant_leak,
            "severity": self.severity,
            "details": self.details,
            "cwe_id": self.cwe_id,
        }


class GraphQLSubscriptionAuditor:
    """
    Audits GraphQL subscriptions for connection authentication and multi-tenant event isolation.
    """

    @classmethod
    def validate_connection_init(
        cls,
        protocol: str,
        init_payload: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, str]:
        """
        Validates whether connection_init mandates authorization credentials.
        """
        init_payload = init_payload or {}
        has_token = any(
            k.lower() in ["authorization", "authtoken", "token", "jwt", "bearer"]
            for k in init_payload.keys()
        )

        if not has_token:
            return False, "VULNERABLE: Server accepted connection_init without required authorization token payload."
        return True, "SECURE: Connection initialization requires authentication token."

    @classmethod
    def audit_tenant_boundary(
        cls,
        subscription_query: str,
        subscriber_tenant_id: str,
        emitted_event_data: Dict[str, Any]
    ) -> SubscriptionAuditEvent:
        """
        Checks whether an event published over a shared channel leaks data across tenants.
        """
        # Look for common tenant/organization/user identification fields in the event data
        flat_str = json.dumps(emitted_event_data)
        event_tenant = None

        # Heuristic detection of tenant identifier in the event payload
        for key in ["tenant_id", "tenantId", "org_id", "orgId", "account_id", "accountId", "company_id"]:
            if key in emitted_event_data:
                event_tenant = str(emitted_event_data[key])
                break
            # Check nested dicts
            for v in emitted_event_data.values():
                if isinstance(v, dict) and key in v:
                    event_tenant = str(v[key])
                    break
            if event_tenant:
                break

        # If tenant was found and differs from the subscriber's tenant
        is_leak = bool(event_tenant and event_tenant != subscriber_tenant_id)

        if is_leak:
            details = (
                f"CRITICAL MULTI-TENANT LEAK: Subscriber from tenant '{subscriber_tenant_id}' "
                f"received confidential pub/sub event containing data belonging to tenant '{event_tenant}'. "
                f"Subscription resolver lacks tenant isolation gating."
            )
            severity = "CRITICAL"
        else:
            details = f"SECURE: Event correctly isolated to tenant '{subscriber_tenant_id}'."
            severity = "NONE"

        return SubscriptionAuditEvent(
            query=subscription_query,
            subscriber_tenant_id=subscriber_tenant_id,
            emitted_event_tenant_id=event_tenant or subscriber_tenant_id,
            is_cross_tenant_leak=is_leak,
            severity=severity,
            details=details
        )

    @classmethod
    def audit_subscription_complexity(cls, query: str, max_depth_limit: int = 5) -> Dict[str, Any]:
        """
        Audits subscription query nesting depth to detect DoS via unbounded fan-out.
        """
        depth = 0
        max_depth = 0
        for char in query:
            if char == "{":
                depth += 1
                max_depth = max(max_depth, depth)
            elif char == "}":
                depth = max(0, depth - 1)

        is_deep = max_depth > max_depth_limit
        return {
            "query_depth": max_depth,
            "max_allowed_depth": max_depth_limit,
            "is_excessive_depth": is_deep,
            "risk": "HIGH" if is_deep else "LOW",
            "recommendation": "Enforce maximum query depth and field complexity limits on GraphQL subscription resolvers." if is_deep else "Depth is within safe limits."
        }
