"""
GraphQL Autonomous Skill
========================
Discovers GraphQL endpoints and audits Schema Introspection and Query Batching.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin
import httpx

from agents.skills.base_skill import BaseSkill, SkillResult
from core.protocols.graphql_subscription_auditor import GraphQLSubscriptionAuditor

log = logging.getLogger("hunter_ai.skills.graphql")


class GraphQLSkill(BaseSkill):
    name: str = "GraphQLSkill"
    vuln_type: str = "graphql"
    cwe: str = "CWE-200"
    owasp_top10: str = "A01:2021 — Broken Access Control"
    default_severity: str = "Medium"

    INTROSPECTION_QUERY = {"query": "{ __schema { types { name } } }"}
    BATCH_QUERY = [{"query": "{ __typename }"}, {"query": "{ __typename }"}]

    async def run(self, target_url: str, param_name: str = "query", **kwargs) -> SkillResult:
        logs = [f"[GRAPHQL] Auditing GraphQL on {target_url}"]
        transport = None
        if self.proxy:
            try:
                transport = httpx.AsyncHTTPTransport(proxy=self.proxy, verify=False)
            except Exception:
                pass

        common_endpoints = ["/graphql", "/api/graphql", "/v1/graphql"]
        candidate_urls = [target_url] if "graphql" in target_url.lower() else [urljoin(target_url, p) for p in common_endpoints]

        async with httpx.AsyncClient(transport=transport, timeout=self.timeout, verify=False) as client:
            for ep_url in candidate_urls:
                try:
                    # 1. Test Introspection
                    r_intro = await client.post(ep_url, json=self.INTROSPECTION_QUERY)
                    if r_intro.status_code == 200 and "__schema" in r_intro.text and "types" in r_intro.text:
                        logs.append(f"[GRAPHQL] Introspection enabled on {ep_url}!")
                        return SkillResult(
                            verified=True,
                            vuln_type="graphql_introspection",
                            title=f"GraphQL Introspection Schema Publicly Exposed on {ep_url}",
                            severity="Medium",
                            endpoint=ep_url,
                            param_name="query",
                            evidence=f"Server returned complete schema definition in response to __schema introspection query.",
                            payload_used=str(self.INTROSPECTION_QUERY),
                            remediation="Disable GraphQL Introspection in production environments.",
                            confidence=0.95,
                            tool=self.name,
                            evidence_sources=[f"{self.name}/IntrospectionAudit"],
                            cwe="CWE-200",
                            owasp_top10="A01:2021 — Broken Access Control",
                            logs=logs
                        )

                    # 2. Test Batching
                    r_batch = await client.post(ep_url, json=self.BATCH_QUERY)
                    if r_batch.status_code == 200 and isinstance(r_batch.json(), list) and len(r_batch.json()) == 2:
                        logs.append(f"[GRAPHQL] Query Batching allowed on {ep_url}!")
                        return SkillResult(
                            verified=True,
                            vuln_type="graphql_batching",
                            title=f"GraphQL Query Batching Enabled (Brute-Force & DoS Hazard)",
                            severity="Low",
                            endpoint=ep_url,
                            param_name="query",
                            evidence="Server processed an array of queries in a single HTTP transaction.",
                            payload_used=str(self.BATCH_QUERY),
                            remediation="Limit query batch size or disable array batching in GraphQL server configuration.",
                            confidence=0.90,
                            tool=self.name,
                            evidence_sources=[f"{self.name}/BatchingAudit"],
                            cwe="CWE-400",
                            owasp_top10="A05:2021 — Security Misconfiguration",
                            logs=logs
                        )
                except Exception as e:
                    logs.append(f"[GRAPHQL] Probe error on {ep_url}: {e}")

        logs.append("[GRAPHQL] No GraphQL vulnerabilities confirmed")
        return SkillResult(verified=False, vuln_type=self.vuln_type, endpoint=target_url,
                           param_name=param_name, tool=self.name, logs=logs)
