"""
Model Router for Security Intelligence Agent
Routes analytical tasks between Fast, Coding, and Deep Reasoning models.
"""
import os
import logging
from enum import Enum
from typing import Dict, Any, Optional
import httpx
from agents.security_intelligence.config import SecurityIntelligenceConfig

log = logging.getLogger("security_intelligence.model_router")


class ModelTier(str, Enum):
    FAST = "fast"                # Classification, tagging, fast extraction
    CODING = "coding"            # Script generation, payload parsing, regex
    REASONING = "reasoning"      # Complex hypotheses, critic, attack chains, teaching


class IntelligenceModelRouter:
    """موجه النماذج الذكي: اختيار النموذج الأنسب لكل مهمة لتوفير الموارد والوقت"""

    def __init__(self):
        self.ollama_host = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")

    def select_model_for_task(self, tier: ModelTier) -> str:
        if tier == ModelTier.FAST:
            return SecurityIntelligenceConfig.LOCAL_FAST_MODEL
        elif tier == ModelTier.CODING:
            return SecurityIntelligenceConfig.LOCAL_CODING_MODEL
        else:
            return SecurityIntelligenceConfig.LOCAL_REASONING_MODEL

    async def execute_prompt(
        self,
        prompt: str,
        system_prompt: str = "You are HunterAI Security Intelligence Core.",
        tier: ModelTier = ModelTier.FAST,
        temperature: float = 0.2
    ) -> str:
        """تنفيذ استعلام مع النموذج المناسب عبر Ollama أو Fallback"""
        model_name = self.select_model_for_task(tier)
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                res = await client.post(
                    f"{self.ollama_host}/api/generate",
                    json={
                        "model": model_name,
                        "prompt": prompt,
                        "system": system_prompt,
                        "stream": False,
                        "options": {"temperature": temperature}
                    }
                )
                if res.status_code == 200:
                    return res.json().get("response", "").strip()
        except Exception as e:
            log.warning(f"Local model '{model_name}' execution error: {e}. Fallback to deterministic logic.")

        return f"[Model Response Fallback for tier {tier}]: {prompt[:100]}..."
