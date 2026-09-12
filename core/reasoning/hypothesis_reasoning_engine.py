"""
Observation → Hypothesis → Validation Engine
Transforms static tool output and observations into scientific security hypotheses with dynamic Bayesian-inspired confidence scoring.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.database.knowledge_db import KnowledgeDB

logger = logging.getLogger(__name__)


@dataclass
class SecurityHypothesis:
    hyp_id: str
    target: str
    title: str
    vuln_type: str
    observation: str
    rationale: str
    confidence: float                  # 0.0 to 1.0
    status: str                        # draft | testing | validated | rejected | inconclusive
    recommended_skill: str
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)


class HypothesisReasoningEngine:
    """
    محرك الاستدلال وتوليد الفرضيات الأمنية (Observation → Hypothesis → Validation):
    - يحلل المدخلات والملاحظات ويصيغ فرضيات أمنية محددة وقابلة للاختبار.
    - يدير درجات الثقة (Confidence Scoring) ديناميكياً بناءً على الأدلة المؤيدة أو النافية.
    - يوجه الـ Planner لاختيار المهارة المناسبة للتحقق من الفرضية.
    """

    def __init__(self, db: KnowledgeDB):
        self.db = db

    def generate_hypotheses_from_observations(
        self,
        target: str,
        endpoints: List[Dict[str, Any]],
        parameters: List[Dict[str, Any]],
        technologies: List[str]
    ) -> List[SecurityHypothesis]:
        """
        تحليل الـ endpoints والـ parameters والتقنيات وتوليد الفرضيات
        """
        generated: List[SecurityHypothesis] = []

        # 1. Check for IDOR / BOLA patterns in parameters
        for p in parameters:
            p_name = p.get("name", "").lower()
            p_val = str(p.get("sample_value", ""))
            if p_name in ("id", "user_id", "account_id", "order_id", "profile_id", "doc_id") or p.get("is_identifier"):
                hyp_id = self.db.insert_hypothesis(
                    target=target,
                    title=f"Potential IDOR/BOLA on parameter '{p.get('name')}'",
                    vuln_type="broken_access_control.idor",
                    observation=f"Endpoint exposes object identifier '{p.get('name')}' with value '{p_val}'",
                    rationale="Direct object reference parameters often lack proper server-side authorization checks between different tenant sessions.",
                    confidence=0.55,
                    recommended_skill="authorization_analysis"
                )
                generated.append(SecurityHypothesis(
                    hyp_id=hyp_id, target=target,
                    title=f"Potential IDOR/BOLA on parameter '{p.get('name')}'",
                    vuln_type="broken_access_control.idor",
                    observation=f"Parameter '{p.get('name')}'={p_val}",
                    rationale="Object identifier exposed",
                    confidence=0.55, status="draft",
                    recommended_skill="authorization_analysis"
                ))

        # 2. Check for GraphQL Introspection & API Endpoints
        for ep in endpoints:
            ep_url = ep.get("url", "").lower()
            if "graphql" in ep_url:
                hyp_id = self.db.insert_hypothesis(
                    target=target,
                    title="Exposed GraphQL Introspection & Batching Surface",
                    vuln_type="api.graphql_introspection",
                    observation=f"GraphQL endpoint discovered at {ep.get('url')}",
                    rationale="Exposed GraphQL endpoints frequently permit full schema introspection and denial-of-service batching queries.",
                    confidence=0.75,
                    recommended_skill="api_surface_audit"
                )
                generated.append(SecurityHypothesis(
                    hyp_id=hyp_id, target=target,
                    title="Exposed GraphQL Introspection Surface",
                    vuln_type="api.graphql_introspection",
                    observation=f"GraphQL route {ep.get('url')}",
                    rationale="Introspection might be enabled",
                    confidence=0.75, status="draft",
                    recommended_skill="api_surface_audit"
                ))
            elif "swagger" in ep_url or "openapi.json" in ep_url or "api-docs" in ep_url:
                hyp_id = self.db.insert_hypothesis(
                    target=target,
                    title="Exposed API Documentation & Schema",
                    vuln_type="information_disclosure.swagger",
                    observation=f"Swagger/OpenAPI documentation exposed at {ep.get('url')}",
                    rationale="Publicly exposed API schemas provide attackers with complete endpoint inventories and parameter requirements.",
                    confidence=0.85,
                    recommended_skill="api_surface_audit"
                )
                generated.append(SecurityHypothesis(
                    hyp_id=hyp_id, target=target,
                    title="Exposed API Documentation & Schema",
                    vuln_type="information_disclosure.swagger",
                    observation=f"Schema exposed at {ep.get('url')}",
                    rationale="Full API specification visible",
                    confidence=0.85, status="draft",
                    recommended_skill="api_surface_audit"
                ))

        # 3. Check for Cloud Metadata / SSRF indicators
        for tech in technologies:
            tech_lower = tech.lower()
            if any(cloud in tech_lower for cloud in ("aws", "amazon", "ec2", "s3", "gcp", "azure", "alibaba")):
                hyp_id = self.db.insert_hypothesis(
                    target=target,
                    title=f"Cloud Infrastructure Identified ({tech}) — Audit Cloud Metadata Exposure",
                    vuln_type="server_side_injection.ssrf.cloud",
                    observation=f"Technology detection identified cloud hosting: {tech}",
                    rationale="Cloud deployments may be vulnerable to SSRF attacks targeting instance metadata services (IMDSv1/v2).",
                    confidence=0.60,
                    recommended_skill="cloud_metadata_audit"
                )
                generated.append(SecurityHypothesis(
                    hyp_id=hyp_id, target=target,
                    title=f"Cloud Infrastructure Identified ({tech})",
                    vuln_type="server_side_injection.ssrf.cloud",
                    observation=f"Cloud tech {tech}",
                    rationale="Potential IMDS vulnerability",
                    confidence=0.60, status="draft",
                    recommended_skill="cloud_metadata_audit"
                ))

        return generated

    def record_validation_result(
        self,
        hyp_id: str,
        corroborating: bool,
        evidence_snippet: str,
        confidence_delta: float = 0.25
    ) -> float:
        """
        تسجيل نتيجة التحقق وتحديث درجة الثقة وحالة الفرضية:
        - أدلة مؤيدة -> زيادة الثقة (تصل إلى 98% -> validated)
        - أدلة نافية -> خفض الثقة (تنزل إلى أقل من 20% -> rejected)
        """
        hypotheses = self.db.get_hypotheses()
        target_hyp = next((h for h in hypotheses if h["hyp_id"] == hyp_id), None)
        if not target_hyp:
            return 0.0

        current_conf = float(target_hyp["confidence"])
        if corroborating:
            new_conf = min(current_conf + confidence_delta, 0.98)
            new_status = "validated" if new_conf >= 0.85 else "testing"
        else:
            new_conf = max(current_conf - confidence_delta, 0.05)
            new_status = "rejected" if new_conf <= 0.20 else "inconclusive"

        self.db.update_hypothesis_confidence(
            hyp_id=hyp_id,
            new_confidence=round(new_conf, 2),
            new_status=new_status
        )
        return new_conf
