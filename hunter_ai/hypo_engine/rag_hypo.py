"""
محرك فرضيات معزز بـ RAG لـ HunterAI
يسترجع معرفة من قاعدة RAG لتوجيه فرضيات الاستغلال، ويربطها بالمحرك الحالي للفرضيات (HypothesisEngine).
يدعم غير المتزامن (async)، السجلات، والتكوينات المركزية
"""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Dict, List, Optional

from core.config.settings import config
from core.exceptions import RAGError, HunterAIError
from core.logging.logger import logger
from hunter_ai.evidence.hypothesis_engine import (
    HypothesisEngine,
    Hypothesis,
    HypothesisStatus,
)
from hunter_ai.knowledge.rag_engine import RAGEngine, KnowledgeItem


class RAGHypothesisEngine:
    """
    يعزز محرك الفرضيات الحالي باسترجاع معرفة من قاعدة RAG.
    يربط بين معرفة RAG والمحرك الحالي للفرضيات (HypothesisEngine).
    """

    def __init__(self, rag_engine: Optional[RAGEngine] = None, hypo_engine: Optional[HypothesisEngine] = None):
        self.rag = rag_engine or RAGEngine(knowledge_dir=config.rag.knowledge_dir)
        self.hypo = hypo_engine or HypothesisEngine()
        self.rag_config = config.rag

    async def generate_hypothesis_async(
        self,
        target: str,
        endpoint: str,
        observed_behavior: str,
        top_k: Optional[int] = None,
        min_score: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """
        توليد فرضيات استغلال بشكل غير متزامن بناءً على السلوك الملاحظ ومعرفة RAG.
        """
        top_k = top_k or self.rag_config.top_k
        min_score = min_score or self.rag_config.min_score

        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(
            None,
            lambda: self._generate_sync(target, endpoint, observed_behavior, top_k, min_score)
        )
        return results

    def _generate_sync(
        self,
        target: str,
        endpoint: str,
        observed_behavior: str,
        top_k: int,
        min_score: float,
    ) -> List[Dict[str, Any]]:
        query = f"{observed_behavior} {endpoint} vulnerability exploitation technique"
        results = self.rag.retrieve(
            query=query, top_k=top_k, source_filter=None, min_score=min_score
        )

        hypotheses: List[Dict[str, Any]] = []
        for r in results:
            hyp = Hypothesis(
                title=r.title,
                vuln_type=r.source.upper(),
                observation=observed_behavior,
                endpoint=endpoint,
                confidence=r.score,
                status=HypothesisStatus.CREATED,
            )
            self.hypo.register(hyp)

            hypotheses.append(
                {
                    "hypothesis_id": hyp.hyp_id,
                    "technique": r.title,
                    "confidence": r.score,
                    "evidence": r.content[:300],
                    "source": r.source,
                    "item_id": r.item_id,
                    "target": target,
                    "endpoint": endpoint,
                    "observed_behavior": observed_behavior,
                    "generated_at": time.time(),
                    "status": hyp.status.value,
                }
            )

        logger.info(
            f"[RAG] تم توليد {len(hypotheses)} فرضية للهدف {target} على {endpoint}"
        )
        return hypotheses

    def generate_hypothesis(
        self,
        target: str,
        endpoint: str,
        observed_behavior: str,
        top_k: Optional[int] = None,
        min_score: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """نسخة متزامنة من generate_hypothesis_async."""
        return self._generate_sync(target, endpoint, observed_behavior, top_k or self.rag_config.top_k, min_score or self.rag_config.min_score)

    def record_hypothesis_outcome(
        self,
        hypothesis_id: str,
        target: str,
        technique: str,
        success: bool,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> None:
        """تسجيل نتيجة الفرضية في محرك الفرضيات والقاعدة المعرفية."""
        verdict = "CONFIRMED" if success else "REJECTED"
        reason = json.dumps(evidence or {}, ensure_ascii=False)
        success_updated = self.hypo.set_verdict(hypothesis_id, verdict, reason)
        if not success_updated:
            logger.warning(f"[RAG] الفرضية '{hypothesis_id}' غير موجودة في المحرك")

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
        if not any(i.item_id == item.item_id for i in self.rag.items):
            self.rag.items.append(item)
            self.rag._build_index()

        logger.info(
            f"[RAG] سجل نتيجة الفرضية '{hypothesis_id}': الحكم={verdict}, النجاح={success}"
        )

    def get_hypothesis(self, hypothesis_id: str) -> Optional[Dict[str, Any]]:
        """استرجاع فرضية من محرك الفرضيات."""
        hyp = self.hypo.get(hypothesis_id)
        if not hyp:
            return None
        return {
            "hypothesis_id": hyp.hyp_id,
            "technique": hyp.title,
            "vuln_type": hyp.vuln_type,
            "observation": hyp.observation,
            "endpoint": hyp.endpoint,
            "confidence": hyp.confidence,
            "status": hyp.status.value,
            "verdict": hyp.verdict,
        }

    def summary(self) -> Dict[str, Any]:
        """إرجاع ملخص جميع الفرضيات."""
        return self.hypo.summary()
