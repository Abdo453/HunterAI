"""
Cost & Token Intelligence Optimizer
Routes tasks to the most cost-effective tier:
- Deterministic Python (Parsing, Regex, Deduplication, Hash, Diffs) -> $0 / 0 tokens
- Light Tool / Fast HTTP (httpx, subfinder) -> Fast CLI / Minimal tokens
- Small LLM (Classification, Routing, Tagging) -> Fast tier
- Heavy / Reasoning LLM (Exploit Chain, Debate, Final Synthesis) -> Deep reasoning tier
Also indexes and summarizes large datasets (50,000 URLs -> Indexer -> RAG).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class ExecutionTierDecision:
    task_name: str
    recommended_tier: str  # "deterministic_python", "cli_tool", "small_llm", "reasoning_llm"
    estimated_token_cost: int
    rationale: str


class TokenCostOptimizer:
    """
    محسن التكلفة والـ Tokens وتوجيه المهام (Cost & Token Intelligence):
    - يوجه المهام الرياضية والنصية والفرز إلى Python بدلاً من إهدار الـ Tokens.
    - يستخدم التلخيص والفهرسة (Chunk & Index) للبيانات الكبيرة (50,000 URL).
    """

    @classmethod
    def decide_execution_tier(cls, task_name: str, payload_size_items: int) -> ExecutionTierDecision:
        t_lower = task_name.lower()

        # 1. Deterministic tasks -> 0 tokens
        if any(k in t_lower for k in ["dedup", "sort", "regex", "hash", "parse_json", "diff", "filter"]):
            return ExecutionTierDecision(
                task_name=task_name,
                recommended_tier="deterministic_python",
                estimated_token_cost=0,
                rationale="Pure deterministic algorithmic task executed locally in Python without LLM API calls."
            )

        # 2. HTTP probing / Network IO
        if any(k in t_lower for k in ["status_probe", "port_check", "dns_resolve"]):
            return ExecutionTierDecision(
                task_name=task_name,
                recommended_tier="cli_tool",
                estimated_token_cost=0,
                rationale="Standard fast networking tool (httpx/naabu) handles high concurrency efficiently."
            )

        # 3. Simple classification
        if any(k in t_lower for k in ["classify", "tag", "triage_filter"]):
            return ExecutionTierDecision(
                task_name=task_name,
                recommended_tier="small_llm",
                estimated_token_cost=150,
                rationale="Low-latency classification model suitable for structured decision."
            )

        # 4. Complex Security Reasoning
        return ExecutionTierDecision(
            task_name=task_name,
            recommended_tier="reasoning_llm",
            estimated_token_cost=1200,
            rationale="Multi-step exploit chaining, agent debate, and hypothesis synthesis require deep reasoning model."
        )

    @classmethod
    def compress_large_context(cls, raw_items: List[str], max_summary_items: int = 50) -> Dict[str, Any]:
        """تلخيص وفهرسة القوائم الضخمة دون إرسال 50,000 سطر للـ Prompt"""
        total = len(raw_items)
        unique_items = list(dict.fromkeys(raw_items))
        samples = unique_items[:max_summary_items]

        # Extract top path patterns / categories
        categories = {}
        for item in unique_items:
            prefix = item.split("/")[1] if item.startswith("/") and len(item.split("/")) > 1 else "root"
            categories[prefix] = categories.get(prefix, 0) + 1

        return {
            "total_count": total,
            "unique_count": len(unique_items),
            "sampled_items": samples,
            "top_categories": dict(sorted(categories.items(), key=lambda x: x[1], reverse=True)[:5]),
            "summarized_for_llm": f"Index of {len(unique_items)} unique endpoints partitioned across {len(categories)} namespaces."
        }
