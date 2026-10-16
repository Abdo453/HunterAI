"""Confidence Model — أوزان الإشارات وحساب درجة الثقة للـ Identity Cluster"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from core.osint.schemas import IdentityCluster, IdentityEvidenceRecord


@dataclass
class SignalWeight:
    name: str
    weight: float
    description: str


# جدول الأوزان (مستخلص من خطة OSINT Identity Subsystem)
POSITIVE_SIGNALS: Dict[str, SignalWeight] = {
    "username_exact_match": SignalWeight(
        "username_exact_match", +0.15, "أساس الربط — ضعيف لوحده"
    ),
    "display_name_match": SignalWeight(
        "display_name_match", +0.10, "مطابقة الاسم الظاهر عبر المنصات"
    ),
    "bio_cross_links": SignalWeight(
        "bio_cross_links", +0.25, "أقوى إشارة — حساب يذكر الآخر في البايو"
    ),
    "avatar_similarity": SignalWeight(
        "avatar_similarity", +0.20, "تشابه صور البروفايل (perceptual hash)"
    ),
    "linked_website": SignalWeight(
        "linked_website", +0.20, "نفس الموقع الإلكتروني في بايو أكثر من منصة"
    ),
    "github_references": SignalWeight(
        "github_references", +0.15, "إيميلات الكوميت أو انتماء Organizations مشتركة"
    ),
    "email_username_cross": SignalWeight(
        "email_username_cross", +0.15, "تصليب بين الإيميل والـ username (user-scanner style)"
    ),
    "registration_proximity": SignalWeight(
        "registration_proximity", +0.05, "تقارب تواريخ الإنشاء — إشارة مساندة فقط"
    ),
}

NEGATIVE_SIGNALS: Dict[str, SignalWeight] = {
    "generic_username": SignalWeight(
        "generic_username", -0.30, "اسم مستخدم عام (admin, test, user...)"
    ),
    "soft404": SignalWeight(
        "soft404", -0.50, "صفحة تُعيد 200 لكنها تقول 'غير موجود'"
    ),
    "single_source": SignalWeight(
        "single_source", -0.20, "منصة واحدة فقط بلا تأكيد من مصدر ثاني"
    ),
    "redirect_collapse": SignalWeight(
        "redirect_collapse", -0.40, "الرابط حُوّل إلى الصفحة الرئيسية للمنصة"
    ),
    "non_identity_domain": SignalWeight(
        "non_identity_domain", -0.60, "نطاق ليس منصة هوية (google, bing...)"
    ),
}


@dataclass
class ConfidenceCalculation:
    """نتيجة حساب الثقة"""
    raw_score: float
    final_score: float
    label: str
    signals_applied: Dict[str, float]
    open_questions: List[str]


class ConfidenceModel:
    """
    يحسب درجة الثقة (0.0 → 1.0) لكل Identity Cluster بناءً على الإشارات الموجبة والسالبة.
    قاعدة ذهبية: حتى لو بلغت الدرجة 1.0، النتيجة remain "probable identity link" 
    وليست "confirmed finding" بمعنى HunterAI (الذي يحتاج E2+ reproducible proof).
    """

    def __init__(self, min_for_possible: float = 0.25,
                 min_for_probable: float = 0.50,
                 min_for_strong: float = 0.75):
        self.min_for_possible = min_for_possible
        self.min_for_probable = min_for_probable
        self.min_for_strong = min_for_strong

    def calculate(
        self,
        cluster: IdentityCluster,
        fp_penalties: Optional[Dict[str, float]] = None,
    ) -> ConfidenceCalculation:
        """
        계る:
        score = Σ(positive) − Σ(negative) − fp_penalties
        clamped إلى [0, 1]
        """
        signals_applied: Dict[str, float] = {}
        score = 0.0

        # الإشارات الموجبة الموجودة في cluster.correlation_signals
        for sig_name, sig in POSITIVE_SIGNALS.items():
            if sig_name in cluster.correlation_signals:
                val = cluster.correlation_signals[sig_name]
                signals_applied[sig_name] = val
                score += val

        # الإشارات السالبة من fp_guards (إذا تم تمريرها)
        fp_penalties = fp_penalties or {}
        for sig_name, sig in NEGATIVE_SIGNALS.items():
            if sig_name in fp_penalties:
                val = fp_penalties[sig_name]
                signals_applied[sig_name] = val
                score += val  # val سالب بالفعل

        # تحديد open questions بناءً على الإشارات الناقصة
        open_questions = self._derive_open_questions(cluster, signals_applied)

        # clamp
        final_score = max(0.0, min(1.0, score))
        label = self._label(final_score)

        return ConfidenceCalculation(
            raw_score=score,
            final_score=round(final_score, 3),
            label=label,
            signals_applied=signals_applied,
            open_questions=open_questions,
        )

    def _derive_open_questions(
        self, cluster: IdentityCluster, signals: Dict[str, float]
    ) -> List[str]:
        questions: List[str] = []
        if "bio_cross_links" not in signals:
            questions.append("لا يوجد بايو متقاطع يؤكد الربط بين الحسابات")
        if "avatar_similarity" not in signals:
            questions.append("لم يُتحقق من تشابه صور البروفايل")
        if "github_references" not in signals:
            questions.append("لا توجد مراجع GitHub تدعم الربط التقني")
        if len(cluster.members) < 2:
            questions.append("منصة واحدة فقط — يحتاج مصدر ثاني للتأكيد")
        if any(
            m.detection_method == "web_status" for m in cluster.members
        ) and not any(m.detection_method in ("mobile_api", "api_enumeration") for m in cluster.members):
            questions.append("모든 الأدلة تعتمد على 웹 статус codes فقط — قد تكون غير موثوقة لبعض المنصات")
        return questions

    @staticmethod
    def _label(score: float) -> str:
        if score >= 0.75:
            return "strong"
        elif score >= 0.50:
            return "probable"
        elif score >= 0.25:
            return "possible"
        return "weak"

    def apply_to_cluster(self, cluster: IdentityCluster, fp_penalties: Optional[Dict[str, float]] = None) -> IdentityCluster:
        """
        يُحدث الحقول الثقة والlabel والأسئلة المفتوحة في الكلاستر نفسه.
        """
        calc = self.calculate(cluster, fp_penalties)
        cluster.confidence = calc.final_score
        cluster.confidence_label = calc.label
        cluster.open_questions = calc.open_questions
        return cluster