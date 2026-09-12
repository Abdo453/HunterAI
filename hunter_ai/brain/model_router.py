"""
Hunter Agent Protocol v1: Intelligent AI Model Router
=====================================================
Dynamically matches task semantics and agent requests to the optimal AI model:
- Code Analysis & AST Parsing -> Qwen 2.5 Coder (14B)
- Offensive Vectors & WAF Breakouts -> WhiteRabbitNeo (8B)
- Large Context & Full Site DOM Correlation -> Google Gemini 2.0 Flash
- Deep Threat Modeling & Multi-Tenant Logic -> OpenRouter Llama 3.3 (70B) / DeepSeek
- Rapid Triage & Hypothesis Ranking -> xploiter / pentester (2.8B)
"""
from __future__ import annotations

import os
import re
import logging
from enum import Enum
from dataclasses import dataclass
from typing import Dict, List, Optional, Any

from hunter_ai.protocol.contract import ModelTierPreference

logger = logging.getLogger("hunter_ai.model_router")


class TaskIntent(str, Enum):
    EXPLAIN_VULNERABILITY  = "explain_vulnerability"
    CODE_ANALYSIS          = "code_analysis"
    OFFENSIVE_EXPLOITATION = "offensive_exploitation"
    LARGE_REASONING        = "large_reasoning"
    DEEP_THREAT_LOGIC      = "deep_threat_logic"
    RAPID_TRIAGE           = "rapid_triage"
    REPORT_SYNTHESIS       = "report_synthesis"


@dataclass
class RoutedModelSelection:
    model_name: str
    tier: ModelTierPreference
    provider: str  # ollama, gemini, openrouter, local
    context_window: int
    temperature: float
    rationale: str


class AIModelRouter:
    """
    موجه النماذج الذكي (AI Model Router):
    يحلل طبيعة المهمة أو كود المصدر أو التليمتري ويختار النموذج المثالي لإنجازها.
    """

    ROUTING_RULES = [
        (re.compile(r"(?i)(javascript|source code|decompil|ast|function|parse code|regex)"), TaskIntent.CODE_ANALYSIS),
        (re.compile(r"(?i)(bypass|waf|filter|payload|breakout|sql injection|xss|ssrf)"), TaskIntent.OFFENSIVE_EXPLOITATION),
        (re.compile(r"(?i)(sitemap|crawl|recon|domains|openapi|1m tokens|massive)"), TaskIntent.LARGE_REASONING),
        (re.compile(r"(?i)(business logic|multi-tenant|privilege escalation|rbac|idor matrix)"), TaskIntent.DEEP_THREAT_LOGIC),
        (re.compile(r"(?i)(triage|quick rank|parameter list|fast check)"), TaskIntent.RAPID_TRIAGE),
        (re.compile(r"(?i)(explain|summary|remediation|report|cwe|cvss)"), TaskIntent.EXPLAIN_VULNERABILITY),
    ]

    def __init__(self, ollama_host: str = "http://192.168.1.3:11434"):
        self.ollama_host = ollama_host

    def infer_intent(self, task_description: str) -> TaskIntent:
        """Determines the task intent from textual or structured descriptions"""
        for pattern, intent in self.ROUTING_RULES:
            if pattern.search(task_description):
                return intent
        return TaskIntent.RAPID_TRIAGE

    def route_task(
        self,
        task_description: str,
        preferred_tier: Optional[ModelTierPreference] = None
    ) -> RoutedModelSelection:
        """
        Selects the best AI model for the specified task.
        """
        intent = self.infer_intent(task_description)

        if preferred_tier == ModelTierPreference.LOCAL_CODE or intent == TaskIntent.CODE_ANALYSIS:
            return RoutedModelSelection(
                model_name="qwen2.5-coder:14b",
                tier=ModelTierPreference.LOCAL_CODE,
                provider="ollama",
                context_window=32768,
                temperature=0.1,
                rationale="Specialized AST parsing and secure PoC synthesis with Qwen 2.5 Coder 14B."
            )

        elif preferred_tier == ModelTierPreference.LOCAL_OFFENSIVE or intent == TaskIntent.OFFENSIVE_EXPLOITATION:
            return RoutedModelSelection(
                model_name="WhiteRabbitNeo",
                tier=ModelTierPreference.LOCAL_OFFENSIVE,
                provider="ollama",
                context_window=8192,
                temperature=0.2,
                rationale="High-precision defensive attack vector analysis with WhiteRabbitNeo 8B."
            )

        elif preferred_tier == ModelTierPreference.CLOUD_FAST or intent == TaskIntent.LARGE_REASONING:
            return RoutedModelSelection(
                model_name="gemini-2.0-flash",
                tier=ModelTierPreference.CLOUD_FAST,
                provider="gemini",
                context_window=1048576,
                temperature=0.2,
                rationale="1M token context window for massive DOM/Recon asset analysis via Gemini 2.0 Flash."
            )

        elif preferred_tier == ModelTierPreference.CLOUD_DEEP or intent == TaskIntent.DEEP_THREAT_LOGIC:
            return RoutedModelSelection(
                model_name="meta-llama/llama-3.3-70b-instruct",
                tier=ModelTierPreference.CLOUD_DEEP,
                provider="openrouter",
                context_window=131072,
                temperature=0.1,
                rationale="70B parameter deep reasoning for multi-tenant logic and BOLA verification."
            )

        elif intent == TaskIntent.EXPLAIN_VULNERABILITY or intent == TaskIntent.REPORT_SYNTHESIS:
            return RoutedModelSelection(
                model_name="qwen2.5-coder:14b",
                tier=ModelTierPreference.LOCAL_CODE,
                provider="ollama",
                context_window=32768,
                temperature=0.2,
                rationale="Clear vulnerability remediation advice and reproduction steps via Qwen Coder."
            )

        # Default fallback to rapid triager
        return RoutedModelSelection(
            model_name="xploiter/pentester",
            tier=ModelTierPreference.LOCAL_FAST,
            provider="ollama",
            context_window=4096,
            temperature=0.2,
            rationale="Ultra-fast local parameter triager (xploiter 2.8B)."
        )
