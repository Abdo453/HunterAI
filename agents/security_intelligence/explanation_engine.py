"""
Multi-Level Arabic & English Security Explanation Engine 🇪🇬
Generates structured pedagogy tailored across 4 distinct expertise levels:
Level 1: Simple (ببساطة)
Level 2: Technical (تقني)
Level 3: Pentester (منهجية الفحص)
Level 4: Security Researcher (الجذور والحلول المعمارية)
"""
from typing import Dict, Any, Optional
from agents.security_intelligence.schemas import ExplanationLevel, IntelligenceFinding
from agents.security_intelligence.knowledge_engine import KnowledgeEngine


class ExplanationEngine:
    """محرك الشروحات متعدد المستويات باللغة العربية والإنجليزية"""

    def __init__(self, knowledge_engine: Optional[KnowledgeEngine] = None):
        self.kb = knowledge_engine or KnowledgeEngine()

    def generate_multi_level_explanation(
        self,
        topic_or_vuln: str,
        finding: Optional[IntelligenceFinding] = None,
        language: str = "ar"
    ) -> Dict[str, str]:
        """توليد شرح شامل عبر المستويات الـ 4 لمفهوم أو ثغرة محددة"""
        kb_data = self.kb.get_vulnerability(topic_or_vuln) or {}
        vuln_name = kb_data.get("title", topic_or_vuln)
        cwe = kb_data.get("cwe", "CWE-General")
        owasp = kb_data.get("owasp", "OWASP")
        concept_ar = kb_data.get("arabic_concept", f"مفهوم أمني يتعلق بـ {topic_or_vuln}.")
        root_cause = kb_data.get("root_cause", "Input validation or authorization failure.")
        remediation = kb_data.get("remediation", "Implement strict server-side controls.")

        finding_context = ""
        if finding:
            finding_context = f"\n(تمت ملاحظتها في الهدف: {finding.target} على الـ Endpoint: {finding.title})"

        # Level 1: Simple (ببساطة)
        level_1 = (
            f"🟢 **المستوى 1 — اشرحلي ببساطة:**\n"
            f"تخيل لو دخلت فندق ومعاك مفتاح غرفتك رقم 101، لكن جربت تحط المفتاح في غرفة 102 وفتحت معاك وشوفت أغراض شخص تاني!\n"
            f"ده بالضبط فكرة **{vuln_name}**: التطبيق بيسمح للمستخدم يشوف أو يعدل بيانات مش بتاعته بمجرد تغيير رقم الـ ID أو المعرف.{finding_context}"
        )

        # Level 2: Technical (تقني)
        level_2 = (
            f"🔵 **المستوى 2 — اشرح تقني:**\n"
            f"التصنيف: `{cwe}` | `{owasp}`\n"
            f"المشكلة التقنية تكمن في أن الخادم (Server) يستقبل معرّف الكائن (Object Identifier) من العميل (Client) "
            f"وينفذ الاستعلام مباشرة على قاعدة البيانات دون مقارنة معرّف صاحب الجلسة (Session Owner) مع الكائن المطلوب.\n"
            f"مثال: `GET /api/documents?id=9928` يرجع البيانات طالما المستخدم مسجل دخول، حتى لو المستند مملوك لمستخدم آخر."
        )

        # Level 3: Pentester (منهجية الفحص)
        level_3 = (
            f"🟠 **المستوى 3 — اشرح كـ Pentester:**\n"
            f"**المنهجية الميدانية لإثبات الثغرة (Proof of Concept):**\n"
            f"1. إنشاء حسابين مختلفين بصلاحيات متطابقة (User A و User B).\n"
            f"2. إنشاء مورد خاص بالمستخدم A وتدوين معرّف المورد (Resource ID).\n"
            f"3. إرسال نفس الطلب عبر توكن أو جلسة المستخدم B لمحاولة قراءة أو تعديل المورد.\n"
            f"4. **الدليل الحاسم (Conclusive Evidence):** استجابة السيرفر بـ `200 OK` وعرض بيانات المستخدم A للطلب القادم من المستخدم B، بدلاً من `403 Forbidden`."
        )

        # Level 4: Security Researcher (الجذور والحلول المعمارية)
        level_4 = (
            f"🟣 **المستوى 4 — اشرح كـ Security Researcher:**\n"
            f"**تحليل الجذر المعماري (Root Cause Analysis):**\n"
            f"{root_cause}\n"
            f"**الحل الهندسي الشامل (Architectural Remediation):**\n"
            f"- عدم الاعتماد على الـ UI لإخفاء المعرفات.\n"
            f"- تطبيق سياسة التفويض على مستوى طبقة الوصول للبيانات (Data Access Layer - DAL):\n"
            f"  `SELECT * FROM resources WHERE id = :resource_id AND owner_user_id = :session_user_id`\n"
            f"- {remediation}"
        )

        return {
            ExplanationLevel.SIMPLE.value: level_1,
            ExplanationLevel.TECHNICAL.value: level_2,
            ExplanationLevel.PENTESTER.value: level_3,
            ExplanationLevel.RESEARCHER.value: level_4
        }
