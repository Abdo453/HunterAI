"""
محرك فرضيات معزز بـ RAG لـ HunterAI
يسترجع معرفة من قاعدة RAG لتوجيه فرضيات الاستغلال.
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

from hunter_ai.knowledge.rag_engine import RAGEngine, KnowledgeItem


class RAGHypothesisEngine:
    """
    يعزز محرك الفرضيات الحالي باسترجاع معرفة من قاعدة RAG.
    """

    def __init__(self, rag_engine: Optional[RAGEngine] = None):
        self.rag = rag_engine or RAGEngine()

    def generate_hypothesis(
        self,
        target: str,
        endpoint: str,
        observed_behavior: str,
        top_k: int = 5,
        min_score: float = 0.3,
    ) -> List[Dict[str, Any]]:
        """
        توليد فرضيات استغلال بناءً على السلوك الملاحظ ومعرفة RAG.
        """
        query = f"{observed_behavior} {endpoint} vulnerability exploitation technique"
        results = self.rag.retrieve(
            query=query, top_k=top_k, source_filter=None, min_score=min_score
        )

        hypotheses: List[Dict[str, Any]] = []
        for r in results:
            hypotheses.append(
                {
                    "hypothesis_id": f"hyp-{int(time.time() * 1000)}-{len(hypotheses)}",
                    "technique": r.title,
                    "confidence": r.score,
                    "evidence": r.content[:300],
                    "source": r.source,
                    "item_id": r.item_id,
                    "target": target,
                    "endpoint": endpoint,
                    "observed_behavior": observed_behavior,
                    "generated_at": time.time(),
                }
            )

        return hypotheses

    def record_hypothesis_outcome(
        self,
        hypothesis_id: str,
        target: str,
        technique: str,
        success: bool,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> None:
        """تسجيل نتيجة الفرضية في محرك RAG للتعلم المستقبلي."""
        item = KnowledgeItem(
            item_id=hypothesis_id,
            title=technique,
            content=json.dumps(
                {
                    "target": target,
                    "technique": technique,
                    "success": success,
                    "evidence": evidence or {},
                    "timestamp": time.time(),
                },
                ensure_ascii=False,
            ),
            source="hypothesis_outcome",
            tags=["hypothesis", technique, "success" if success else "failure"],
        )
        # تجنب التكرار
        if not any(i.item_id == item.item_id for i in self.rag.items):
            self.rag.items.append(item)
            self.rag._build_index()
