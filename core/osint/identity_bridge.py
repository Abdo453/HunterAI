"""Identity Bridge — ربط أدلة OSINT Identity بـ World Model (IdentityGraph) و Evidence Court"""
from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional
from dataclasses import asdict

from core.osint.schemas import IdentityCluster, IdentityEvidenceRecord, ConfidenceLabel
from core.identity import IdentityGraph
from core.identity.schemas import IdentityContext

log = logging.getLogger("osint.identity_bridge")


class OSINTIdentityBridge:
    """
    يربط مخرجات OSINT Identity Agent (IdentityClusters) بـ:
      1. IdentityGraph (World Model Layer 2) — كهويات مرشحة للإستكشاف اللاحق
      2. Negative Space Ledger — للأسئلة المفتوحة التي لم تُحسم بعد
      3. Investigation Loop — كتوليد Hypotheses تلقائي للـ Closed-Loop Re-Investigation

    ملاحظة: هذه الجسر لا يُرفع أي نتيجة إلى "Confirmed Finding"؛ كل ما يُمرر هو Evidence (E0/E1).
    """

    def __init__(self, identity_graph: Optional[IdentityGraph] = None):
        self.graph = identity_graph or IdentityGraph()

    def ingest_clusters(
        self,
        clusters: List[IdentityCluster],
        source_session: str = "osint_identity",
    ) -> Dict[str, Any]:
        """
        يُدخل كل cluster إلى IdentityGraph كـ IdentityContextes (for platforms that support it)
        ويُرجع تقرير بالتتبع.
        """
        report: Dict[str, Any] = {
            "clusters_ingested": 0,
            "identities_registered": 0,
            "hypotheses_generated": 0,
            "negative_space_entries": 0,
            "details": [],
        }

        for cl in clusters:
            report["clusters_ingested"] += 1

            # لكل منصة في الكلاستر، نسجل هوية في الـ IdentityGraph (إن لم تكن مسجلة)
            for member in cl.members:
                platform = member.platform
                uid = f"osint_{platform}_{member.query_value}".replace(" ", "_")

                # لا نُعيد تسجيل هوية موجودة
                if self.graph.get_identity(uid) is not None:
                    continue

                ctx = IdentityContext(
                    identity_id=uid,
                    tenant_id="osint_public",
                    roles=["public_identity"],
                    tokens={},
                    cookies={},
                    # نضع मूल البيانات كـ metadata ضمن السياق إن كان schemat يسمح
                )
                try:
                    self.graph.register_identity(ctx)
                    report["identities_registered"] += 1
                except Exception as e:
                    log.debug(f"Could not register identity {uid}: {e}")

            # توليد hypothesis للـ investigation loop من كل cluster غير weak
            if cl.confidence_label in ("possible", "probable", "strong"):
                report["hypotheses_generated"] += 1
                report["details"].append({
                    "cluster_id": cl.cluster_id,
                    "anchor": cl.anchor,
                    "confidence": cl.confidence,
                    "label": cl.confidence_label,
                    "platforms": sorted(set(m.platform for m in cl.members)),
                    "hypothesis": (
                        f"Hypothesis: accounts across {', '.join(sorted(set(m.platform for m in cl.members)))} "
                        f"may share operator '{cl.anchor}' (confidence: {cl.confidence_label}, {cl.confidence:.2f}). "
                        f"Requires active browser verification before E2."
                    ),
                })

            # الأسئلة المفتوحة تدخل Negative Space Ledger (untested leads)
            for q in cl.open_questions:
                report["negative_space_entries"] += 1
                log.info(
                    f"[NEGATIVE_SPACE] OSINT Identity open question: {q} "
                    f"(cluster={cl.cluster_id}, anchor={cl.anchor})"
                )

        return report

    def cluster_to_finding_payload(self, cluster: IdentityCluster) -> Dict[str, Any]:
        """
        يُحول الـ cluster إلى payload قابل للإرسال لـ Evidence Court أو التحقيق التلقائي.
        يُMarker كـ "evidence_only" لمنع الخلط مع Findings مؤكدة.
        """
        return {
            "type": "osint_identity_evidence",
            "evidence_only": True,
            "cluster_id": cluster.cluster_id,
            "anchor": cluster.anchor,
            "confidence": cluster.confidence,
            "confidence_label": cluster.confidence_label,
            "members": [m.to_dict() for m in cluster.members],
            "correlation_signals": cluster.correlation_signals,
            "open_questions": cluster.open_questions,
            "verification_required": True,
            "max_evidence_level": "E1",
        }
