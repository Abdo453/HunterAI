"""Identity Correlation Engine — بناء الكلسترات من الأدلة"""
from __future__ import annotations

from typing import List, Dict, Any, Optional
from collections import defaultdict

from core.osint.schemas import (
    IdentityEvidenceRecord,
    IdentityCluster,
    ConfidenceLabel,
)
from core.osint.confidence_model import ConfidenceModel


class IdentityCorrelationEngine:
    """
    يأخذ قائمة IdentityEvidenceRecord ويحوّلها إلى IdentityCluster(s).
    المنطق:
    1. تجميع الأدلة حسب الـ anchor (القيمة المفحوصة: username أو email).
    2. دمج الأدلة التي تشير لنفس الهوية عبر منصات مختلفة (cross-platform).
    3. استخراج الإشارات الارتباطية (bio cross-links, avatar, website...).
    4. حساب الثقة عبر ConfidenceModel.
    """

    def __init__(self):
        self.confidence_model = ConfidenceModel()

    def correlate(
        self,
        records: List[IdentityEvidenceRecord],
        anchor: Optional[str] = None,
    ) -> List[IdentityCluster]:
        """
        يُرجع قائمة من الكلسترات المرتبة حسب الثقة تنازليًا.
        """
        if not records:
            return []

        # إذا لم يُحدد anchor، نستخدم أول query_value كمرجع
        anchor = anchor or records[0].query_value

        # تجميع السجلات حسب المنصة لتفادي التكرار داخل الكلاستر الواحد
        by_platform: Dict[str, List[IdentityEvidenceRecord]] = defaultdict(list)
        for r in records:
            by_platform[r.platform].append(r)

        # لكل منصة، نختار أفضل سجل (E1 يسبق E0، puis الأداة الأحدث)
        best_per_platform: List[IdentityEvidenceRecord] = []
        for platform, recs in by_platform.items():
            recs.sort(key=lambda r: (r.evidence_level == "E1", len(r.corroborating_tools)), reverse=True)
            best_per_platform.append(recs[0])

        # بناء الكلاستر
        cluster = IdentityCluster(
            cluster_id="",
            anchor=anchor,
            members=best_per_platform,
            correlation_signals=self._extract_signals(best_per_platform, records),
            confidence=0.0,
            confidence_label="weak",
            open_questions=[],
        )

        # تطبيق نموذج الثقة
        self.confidence_model.apply_to_cluster(cluster)

        return [cluster]

    def correlate_multi_anchor(
        self,
        records: List[IdentityEvidenceRecord],
    ) -> List[IdentityCluster]:
        """
        إذا كان لدينا evidence لعدد من القيم (مثلاً username + email)،
        نبني كلاستر لكل قيمة ثم نبحث عن ارتباط بينها (cross-scan).
        """
        by_anchor: Dict[str, List[IdentityEvidenceRecord]] = defaultdict(list)
        for r in records:
            by_anchor[r.query_value].append(r)

        clusters: List[IdentityCluster] = []
        for anchor, recs in by_anchor.items():
            clusters.extend(self.correlate(recs, anchor=anchor))

        # ترتيب تنازلي حسب الثقة
        clusters.sort(key=lambda c: c.confidence, reverse=True)
        return clusters

    # ── استخراج الإشارات ─────────────────────────────────────────

    def _extract_signals(
        self,
        best_per_platform: List[IdentityEvidenceRecord],
        all_records: List[IdentityEvidenceRecord],
    ) -> Dict[str, float]:
        signals: Dict[str, float] = {}

        # username_exact_match: دائمًا موجود إذا وجدنا أكثر من منصة بنفس القيمة
        if len(best_per_platform) >= 1:
            signals["username_exact_match"] = 0.15

        # single_source penalty إذا كانت منصة واحدة فقط
        if len(best_per_platform) == 1:
            signals["single_source"] = -0.20

        # cross-vector: لو وجدنا evidence من 벡تور email و username معًا لنفس القيمة
        vectors = {r.vector for r in all_records}
        if "username" in vectors and "email" in vectors:
            signals["email_username_cross"] = 0.15

        # detection method diversity: لو وُجد mobile_api أو api_enumeration إلى جانب web_status
        methods = {r.detection_method for r in best_per_platform}
        if "mobile_api" in methods or "api_enumeration" in methods:
            signals["cross_method_confirmation"] = 0.10

        # GitHub references
        if any("github" in r.platform for r in best_per_platform):
            signals["github_references"] = 0.15

        # bio cross-links و avatar similarity و linked website 
        # تُستخرج من contenido الفعلي للصفحة (يحتاج Browser Worker في Phase 4)،
        #所以暂时ًا نضعها كـ open questions وليس إشارات محسوبة.
        signals["bio_cross_links"] = 0.0   # يُحدّث لاحقًا من فحص المحتوى
        signals["avatar_similarity"] = 0.0 # يُحدّث لاحقًا من pHash الصور
        signals["linked_website"] = 0.0    # يُحدّث لاحقًا من تحليل البايو

        return signals

    def to_finding_dicts(self, clusters: List[IdentityCluster]) -> List[Dict[str, Any]]:
        return [c.to_finding_dict() for c in clusters]
