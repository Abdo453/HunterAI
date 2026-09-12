"""
Interactive Security Quiz & Knowledge Assessment Engine
Generates scenario-based security questions, evaluates answers, and measures conceptual understanding.
"""
from typing import Dict, List, Any, Optional
from agents.security_intelligence.schemas import QuizQuestion, QuizEvaluation
from agents.security_intelligence.knowledge_engine import KnowledgeEngine


class QuizEngine:
    """محرك الاختبارات الأمنية التفاعلية وتقييم الفهم العملي للمستخدم"""

    def __init__(self, knowledge_engine: Optional[KnowledgeEngine] = None):
        self.kb = knowledge_engine or KnowledgeEngine()
        self._quiz_bank = self._init_quiz_bank()

    def generate_quiz_for_topic(self, topic: str) -> QuizQuestion:
        topic_clean = topic.lower().strip()
        for key, q in self._quiz_bank.items():
            if key in topic_clean or topic_clean in key:
                return q

        # Default fallback scenario
        return QuizQuestion(
            topic=topic,
            scenario=f"أثناء فحص تطبيق ويب، لاحظت Endpoint يطلب: `GET /api/v1/orders/5412` ويستقبل توكن مستخدم مسجل. ما هو الاختبار الأساسي لتأكيد وجود Broken Access Control؟",
            options=[
                "إرسال طلب بحساب مستخدم آخر وملاحظة ما إذا كان السيرفر يعيد بيانات الطلب 5412 (200 OK)",
                "إرسال رمز أحادي (Single Quote) لاختبار SQL Injection",
                "تكرار الطلب 1000 مرة لاختبار الـ Rate Limiting",
                "فحص ما إذا كان الـ SSL Certificate سارياً"
            ],
            correct_option_index=0,
            explanation_on_correct="إجابة صحيحة ممتازة! المقارنة عبر حسابين (Cross-User Testing) هي الدليل القاطع لاكتشاف BOLA / Broken Access Control.",
            explanation_on_wrong="غير دقيق. لاكتشاف مشاكل الصلاحيات والـ Access Control، يجب إرسال نفس المعرف عبر حساب مختلف ومقارنة السلوك.",
            concept_tested="Broken Access Control / BOLA"
        )

    def evaluate_answer(self, quiz: QuizQuestion, user_choice_idx: int) -> QuizEvaluation:
        is_correct = (user_choice_idx == quiz.correct_option_index)
        score = 1.0 if is_correct else 0.20

        strong = [quiz.concept_tested] if is_correct else []
        weak = [] if is_correct else [quiz.concept_tested]

        feedback = quiz.explanation_on_correct if is_correct else quiz.explanation_on_wrong
        recommendation = "تابع إلى المستوى المتقدم في التحليل الأمني." if is_correct else f"راجع مفهوم {quiz.concept_tested} وطريقة المقارنة بين استجابات المستخدمين."

        return QuizEvaluation(
            quiz_id=quiz.id,
            user_answer_index=user_choice_idx,
            is_correct=is_correct,
            understanding_score=score,
            strong_points=strong,
            weak_points=weak,
            feedback_ar=feedback,
            next_recommendation=recommendation
        )

    def _init_quiz_bank(self) -> Dict[str, QuizQuestion]:
        return {
            "bola": QuizQuestion(
                topic="BOLA / IDOR",
                scenario="لديك الـ Endpoint التالي: `GET /api/users/profile?user_id=105` وأنت مسجل دخول بالمعرف 102. إيه أول دليل يثبت وجود BOLA؟",
                options=[
                    "تغيير user_id إلى 105 ورؤية استجابة 200 OK تحتوي على بيانات المستخدم 105",
                    "وجود علامة @ داخل الـ Response",
                    "استجابة السيرفر بـ 403 Forbidden",
                    "ظهور رسالة خطأ 500 Internal Server Error"
                ],
                correct_option_index=0,
                explanation_on_correct="🎯 بالضبط! وصول مستخدم لبيانات مستخدم آخر دون تصريح (200 OK) هو الدليل القاطع على BOLA.",
                explanation_on_wrong="❌ خطأ. استجابة 200 OK مع بيانات مستخدم آخر هي الدليل، بينما 403 تعني أن الحماية مفعلة والسيرفر يمنع الوصول.",
                concept_tested="Object-Level Access Control"
            ),
            "bfla": QuizQuestion(
                topic="BFLA",
                scenario="قمت باستخراج رابط من ملف JS: `POST /api/v1/admin/users/promote` وأنت تملك حساب مستخدم عادي (Role: User). كيف تثبت وجود BFLA؟",
                options=[
                    "إرسال الطلب بتوكن الـ User العادي وملاحظة ترقية الحساب بنجاح (200 OK)",
                    "إرسال XSS Payload في حقل البحث",
                    "تغيير التشفير من HTTPS إلى HTTP",
                    "فحص ملف robots.txt"
                ],
                correct_option_index=0,
                explanation_on_correct="🎯 صحيح! تنفيذ وظيفة إدارية بواسطة حساب عادي يثبت غياب الـ RBAC في السيرفر.",
                explanation_on_wrong="❌ خطأ. BFLA تتعلق بالصلاحيات الوظيفية؛ الإثبات يتطلب تنفيذ الوظيفة الإدارية بتوكن منخفض الصلاحية.",
                concept_tested="Function-Level Access Control"
            ),
            "sqli": QuizQuestion(
                topic="SQL Injection",
                scenario="عند إرسال المعامل `sort=asc'` استجاب السيرفر برسالة: `syntax error in SQL statement near 'asc''`. ما دلالة هذه الملاحظة؟",
                options=[
                    "دليل قوي على تسريب أخطاء قاعدة البيانات واحتمالية وجود SQL Injection",
                    "السيرفر آمن تماماً لأنه أظهر رسالة الخطأ",
                    "الثغرة من نوع Broken Authentication",
                    "الموقع يستخدم تشفير قوي"
                ],
                correct_option_index=0,
                explanation_on_correct="🎯 ممتاز! تسريب أخطاء الـ SQL يؤكد دمج مدخلات العميل مباشرة في استعلام قاعدة البيانات.",
                explanation_on_wrong="❌ خطأ. تسريب رسائل الـ Database Syntax Error مؤشر خطير على قابلية الحقن.",
                concept_tested="SQL Injection Error Handling"
            )
        }
