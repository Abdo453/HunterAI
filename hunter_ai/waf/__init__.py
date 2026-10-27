"""
WAF Bypass Package — نظام تجاوز WAF متعدد الوكلاء
==================================================

المكونات:
  - WAFBypassLadder: شجرة قرار السلم (المستويات 1-9)
  - WafriftIntegration: رابر أداة wafryt الخارجية
  - WAFGeneBank: بنك الجينات والتغذية الراجعة
  - RLPolicyOptimizer: وكيل تحسين السياسة بالتعلم المعزز
  - RewardModelAgent: وكيل نموذج المكافأة للتقييم المسبق
  - RAGAgent: وكيل الاسترجاع السياقي (MISP + محلي)
  - GenerativeAgent: وكيل التوليد (payload generation)
  - AutoWAFuzzerCoordinator: منسق الـ 4 وكلاء (إطار AutoWAFuzzer)
"""
from .autowafuzzer_coordinator import AutoWAFuzzerCoordinator, BypassDecision, BypassOutcome
from .rl_policy_optimizer import RLPolicyOptimizer, RLPick
from .reward_model_agent import RewardModelAgent, PayloadEvaluation
from .rag_agent import RAGAgent, ThreatContext
from .generative_agent import GenerativeAgent, GeneratedPayload

from hunter_ai.tools.waf_bypass_ladder import WAFBypassLadder, BypassResult
from hunter_ai.tools.wafrift_integration import WafriftIntegration, WafriftResult
from memory.waf_gene_bank import WAFGeneBank, GeneRecord

__all__ = [
    "AutoWAFuzzerCoordinator", "BypassDecision", "BypassOutcome",
    "RLPolicyOptimizer", "RLPick",
    "RewardModelAgent", "PayloadEvaluation",
    "RAGAgent", "ThreatContext",
    "GenerativeAgent", "GeneratedPayload",
    "WAFBypassLadder", "BypassResult",
    "WafriftIntegration", "WafriftResult",
    "WAFGeneBank", "GeneRecord",
]
