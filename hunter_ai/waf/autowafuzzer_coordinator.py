"""
AutoWAFuzzer Coordinator — منسق الوكلاء المتعددين لتجاوز WAF
==============================================================
ينسق 4 وكلاء متخصصين (مستوحى من إطار AutoWAFuzzer):

  1. Generative LLM Agent — يولّد payloads بناءً على السياق
  2. RL Policy Optimizer — يختار أفضل تقنية بناءً على التاريخ
  3. Reward Model Agent — يُقيّم payload قبل الإرسال ويحدّد المكافأة المتوقعة
  4. RAG Agent — يسترجع سياق التهديدات من MISP أو مصادر محلية

التدفق لكل محاولة:
  RAG (سياق) → RL (اختيار تقنية) → Generative (توليد payload) → Reward (تقييم مسبق)
  → إرسال فعلي → Gene Bank (تسجيل النتيجة) → RL (تحديث السياسة)
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from hunter_ai.tools.waf_bypass_ladder import WAFBypassLadder, BypassResult
from hunter_ai.tools.wafrift_integration import WafriftIntegration
from memory.waf_gene_bank import WAFGeneBank, GeneRecord
from tools.tool_manager import ToolManager

from .rl_policy_optimizer import RLPolicyOptimizer, RLPick
from .reward_model_agent import RewardModelAgent, PayloadEvaluation
from .rag_agent import RAGAgent, ThreatContext
from .generative_agent import GenerativeAgent, GeneratedPayload


@dataclass
class BypassDecision:
    technique_level: int
    technique_name: str
    payload: str
    headers: Dict[str, str]
    source_agent: str  # "rl" | "gene_bank" | "fallback"
    confidence: float


@dataclass
class BypassOutcome:
    success: bool
    waf_type: str
    target: str
    decision: BypassDecision
    evaluation: Optional[PayloadEvaluation] = None
    actual_status_code: Optional[int] = None
    attempts_count: int = 1
    gene_bank_hit: bool = False


class AutoWAFuzzerCoordinator:
    """
    المنسق الرئيسي لنظام تجاوز WAF متعدد الوكلاء.
    """

    def __init__(
        self,
        mgr: ToolManager,
        gene_bank: Optional[WAFGeneBank] = None,
        use_llm: bool = False,
        llm_endpoint: Optional[str] = None,
        misp_url: Optional[str] = None,
        misp_api_key: Optional[str] = None,
    ):
        self.mgr = mgr
        self.gene_bank = gene_bank or WAFGeneBank()
        self.ladder = WAFBypassLadder(mgr, self.gene_bank)

        # الوكلاء الأربعة
        self.rl = RLPolicyOptimizer(self.gene_bank)
        self.reward = RewardModelAgent(use_llm=use_llm, llm_endpoint=llm_endpoint)
        self.rag = RAGAgent(misp_url=misp_url, misp_api_key=misp_api_key)
        self.generative = GenerativeAgent(use_llm=use_llm, llm_endpoint=llm_endpoint)

        self.wafryt = WafriftIntegration(mgr)

        # إحصائيات الجلسة
        self.session_stats: Dict[str, Any] = {
            "total_attempts": 0,
            "successes": 0,
            "gene_bank_hits": 0,
            "by_waf": {},
            "by_technique": {},
        }

    # ------------------------------------------------------------------ #
    # نقطة الدخول الرئيسية
    # ------------------------------------------------------------------ #
    async def bypass(
        self,
        target: str,
        param_name: str,
        payload_hint: str,
        vuln_type: str = "xss",
        waf_type: str = "unknown",
        waf_version: Optional[str] = None,
        use_misp: bool = False,
    ) -> BypassOutcome:
        """
        يحاول تجاوز WAF باستخدام التنسيق متعدد الوكلاء.
        """
        self.session_stats["total_attempts"] += 1
        self.session_stats.setdefault("by_waf", {}).setdefault(waf_type, {"attempts": 0, "successes": 0})
        self.session_stats["by_waf"][waf_type]["attempts"] += 1

        # ── الوكيل 1: RAG — استرجاع سياق التهديدات ──
        rag_contexts = self.rag.retrieve(waf_type, "general", use_misp=use_misp)
        rag_notes = "; ".join(c.notes for c in rag_contexts[:3]) if rag_contexts else ""

        # ── التحقق من بنك الجينات أولًا ──
        best_known = self.gene_bank.get_best_payloads(waf_type, target=target, min_success_rate=0.5, limit=3)
        if best_known:
            self.session_stats["gene_bank_hits"] += 1
            self.session_stats["successes"] += 1
            self.session_stats["by_waf"][waf_type]["successes"] += 1
            b = best_known[0]
            return BypassOutcome(
                success=True,
                waf_type=waf_type,
                target=target,
                decision=BypassDecision(
                    technique_level=b.technique_level,
                    technique_name=b.technique_name,
                    payload=b.payload,
                    headers=b.headers or {},
                    source_agent="gene_bank",
                    confidence=b.success_rate,
                ),
                gene_bank_hit=True,
            )

        # ── بناء قائمة التقنيات المتاحة من السلم ──
        available = self._available_techniques(payload_hint, target, param_name)

        # ── الوكيل 2: RL — اختيار تقنية ──
        rl_pick = self.rl.pick_technique(waf_type, available, explore=True)

        if rl_pick:
            technique_level = rl_pick.technique_level
            technique_name = rl_pick.technique_name
            payload = rl_pick.payload
            source_agent = "rl"
        else:
            # fallback: استخدم أول تقنية متاحة
            level, name, p = available[0]
            technique_level = level
            technique_name = name
            payload = p
            source_agent = "fallback"

        # إضافة الهيدرز حسب التقنية
        headers = self._headers_for_technique(technique_name)

        # ── الوكيل 3: Generative — تحسين payload إذا لزم ──
        if source_agent == "rl" and vuln_type != "generic":
            gen = self.generative.generate(vuln_type, waf_type, technique_level, technique_name, rag_notes)
            if gen.source != "fallback":
                payload = gen.payload
                source_agent = "generative"
                confidence = gen.confidence
            else:
                confidence = rl_pick.confidence
        else:
            confidence = rl_pick.confidence if rl_pick else 0.5

        decision = BypassDecision(
            technique_level=technique_level,
            technique_name=technique_name,
            payload=payload,
            headers=headers,
            source_agent=source_agent,
            confidence=confidence,
        )

        # ── الوكيل 4: Reward — تقييم مسبق ──
        evaluation = self.reward.evaluate(payload, technique_name, waf_type)
        if evaluation.predicted_outcome == "block" and evaluation.confidence > 0.7:
            # لو التوقع مؤكد بالحظر، جرّب تقنية ثانية من القائمة (إن وجد)
            if len(available) > 1:
                alt = available[1]
                payload = alt[2]
                technique_name = alt[1]
                technique_level = alt[0]
                decision = BypassDecision(
                    technique_level=technique_level,
                    technique_name=technique_name,
                    payload=payload,
                    headers=self._headers_for_technique(technique_name),
                    source_agent="reward_override",
                    confidence=0.6,
                )
                evaluation = self.reward.evaluate(payload, technique_name, waf_type)

        # ── الإرسال الفعلي عبر السلم ──
        result = await self.ladder.run(
            target=target,
            param_name=param_name,
            payload=payload,
            waf_type=waf_type,
            waf_version=waf_version,
            method="GET",
        )

        # ── تحديث RL policy بالنتيجة الفعلية ──
        self.rl.update(waf_type, technique_name, result.success,
                       reward=1.0 if result.success else -0.1)

        # ── تحديث الإحصائيات ──
        if result.success:
            self.session_stats["successes"] += 1
            self.session_stats["by_waf"][waf_type]["successes"] += 1
        self.session_stats.setdefault("by_technique", {}).setdefault(technique_name, {"attempts": 0, "successes": 0})
        self.session_stats["by_technique"][technique_name]["attempts"] += 1
        if result.success:
            self.session_stats["by_technique"][technique_name]["successes"] += 1

        return BypassOutcome(
            success=result.success,
            waf_type=waf_type,
            target=target,
            decision=decision,
            evaluation=evaluation,
            actual_status_code=result.attempts[-1].status_code if result.attempts else None,
            attempts_count=len(result.attempts),
            gene_bank_hit=False,
        )

    # ------------------------------------------------------------------ #
    # helpers
    # ------------------------------------------------------------------ #
    def _available_techniques(
        self, payload_hint: str, target: str, param_name: str
    ) -> List[Tuple[int, str, str]]:
        """
        يبني قائمة التقنيات المتاحة من مولّدات السلم للإستخدام في RL.
        """
        gen = self.ladder.gen
        techniques: List[Tuple[int, str, str]] = []

        # مستوى 1: encoding
        for name, p, _ in gen.level1_encoding(payload_hint):
            techniques.append((1, name, p))
        # مستوى 2: tags
        for name, p, _ in gen.level2_tags(payload_hint):
            techniques.append((2, name, p))
        # مستوى 3: events
        for name, p, _ in gen.level3_events(payload_hint):
            techniques.append((3, name, p))
        # مستوى 4: js obfuscation
        for name, p, _ in gen.level4_js(payload_hint):
            techniques.append((4, name, p))
        # مستوى 5: parser
        for name, p, _ in gen.level5_parser(target, payload_hint):
            techniques.append((5, name, p))
        # مستوى 6: hpp
        for name, p, _ in gen.level6_hpp(param_name, payload_hint):
            techniques.append((6, name, p))
        # مستوى 7: http2
        for name, p, _ in gen.level7_http2(payload_hint):
            techniques.append((7, name, p))

        return techniques

    def _headers_for_technique(self, technique_name: str) -> Dict[str, str]:
        if "content_type" in technique_name:
            return {"Content-Type": "application/json"}
        if "method_override" in technique_name:
            return {"X-HTTP-Method-Override": "PUT"}
        if "path" in technique_name:
            return {"X-Original-URL": "/"}
        return {}

    # ------------------------------------------------------------------ #
    # training
    # ------------------------------------------------------------------ #
    def train_offline(self, episodes: int = 2000) -> Dict[str, Any]:
        """تدريب غيرnected من سجل gene bank التاريخي."""
        return self.rl.train_from_history(episodes=episodes)

    def train_focused(self, waf_type: str, episodes: int = 500) -> Dict[str, Any]:
        """تدريب مركّز على WAF معين."""
        return self.rl.focused_train(waf_type=waf_type, episodes=episodes)

    def summary(self) -> Dict[str, Any]:
        return {
            "session": self.session_stats,
            "rl": self.rl.summary(),
            "rag": self.rag.summary(),
            "gene_bank": self.gene_bank.summary(),
        }


__all__ = ["AutoWAFuzzerCoordinator", "BypassDecision", "BypassOutcome"]
