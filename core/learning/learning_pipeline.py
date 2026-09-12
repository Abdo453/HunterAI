"""
Continuous Learning & Burp Traffic Integration Pipeline
Coordinates the closed learning loop:
Burp Traffic / Target -> Signal Extraction -> RAG Retrieval -> Epistemic Reasoning -> Lesson Extraction -> Experience Memory.
"""
import re
import logging
from typing import Dict, List, Any, Optional

from core.learning.knowledge_store import KnowledgeStore
from core.learning.experience_store import ExperienceStore
from core.learning.retrieval import LearningRetrievalEngine
from core.learning.teacher_agent import TeacherAgent
from core.learning.learner_agent import LearnerAgent
from core.learning.curriculum import SecurityCurriculum

log = logging.getLogger("core.learning.pipeline")


class LearningPipeline:
    """
    خط أنابيب التعلم المستمر واستيعاب ترافيك Burp Suite
    """

    def __init__(
        self,
        knowledge_store: Optional[KnowledgeStore] = None,
        experience_store: Optional[ExperienceStore] = None
    ):
        self.kb = knowledge_store or KnowledgeStore()
        self.exp = experience_store or ExperienceStore()
        self.retrieval = LearningRetrievalEngine(self.kb, self.exp)
        self.curriculum = SecurityCurriculum()
        self.teacher = TeacherAgent(self.curriculum, self.kb)
        self.learner = LearnerAgent(self.retrieval, self.exp)

    def extract_signals_from_http(self, method: str, url: str, headers: Dict[str, str], body: str = "") -> List[str]:
        """استخراج الإشارات الأمنية تلقائياً من طلب HTTP (Burp Traffic)"""
        signals = []
        url_lower = url.lower()

        # Check for numeric or UUID resource identifiers
        if re.search(r"/\d+(?:/|$)", url) or re.search(r"[?&][a-zA-Z0-9_]*id=\d+", url_lower):
            signals.append("resource_identifier")
            signals.append("numeric_id")
        if re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", url_lower):
            signals.append("resource_identifier")
            signals.append("uuid_in_path")

        # Check administrative routes
        if any(admin_word in url_lower for admin_word in ["/admin", "/manage", "/dashboard", "/root", "/internal"]):
            signals.append("admin_path")

        # Check search/filter query parameters
        if any(p in url_lower for p in ["search=", "q=", "filter=", "order=", "sort="]):
            signals.append("search_query")
            signals.append("filter_parameter")

        # Check URL parameters for SSRF
        if any(p in url_lower for p in ["url=", "redirect=", "dest=", "target=", "fetch="]):
            signals.append("url_parameter")

        # Check Auth headers
        for h, v in headers.items():
            h_lower = h.lower()
            if h_lower == "authorization":
                signals.append("authenticated_request")
                if "bearer" in v.lower():
                    signals.append("bearer_token")
                    if "eyj" in v.lower():
                        signals.append("jwt_structure")
            elif h_lower == "cookie":
                signals.append("cookies")

        return list(set(signals))

    def process_burp_traffic(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: str = "",
        status_code: int = 200
    ) -> Dict[str, Any]:
        """
        معالجة ريكويست قادم من Burp Suite:
        1. استخراج الإشارات
        2. استدعاء المعرفة السابقة والتجارب المشابهة من الـ RAG
        3. إرجاع توصيات الفحص والفرضيات المناسبة للعقل الاستدلالي
        """
        signals = self.extract_signals_from_http(method, url, headers, body)
        rag_result = self.retrieval.retrieve_context(signals=signals)

        return {
            "url": url,
            "method": method,
            "extracted_signals": signals,
            "relevant_knowledge": rag_result["matched_knowledge_items"],
            "past_lessons": rag_result["relevant_past_lessons"],
            "recommended_strategy": rag_result["prompt_context"]
        }
