"""
Agent-AI Cognitive Bridge Test Suite
====================================
"""

import pytest
from unittest.mock import AsyncMock, patch

from core.ai_bridge.agent_ai_cognitive_bridge import (
    TaskType, ModelTier, AIModelProfile, AI_MODEL_CATALOG,
    AgentAICognitiveBridge, cognitive_bridge
)


class TestAgentAICognitiveBridge:
    def test_catalog_profiles_exist(self):
        assert "whiterabbitneo" in AI_MODEL_CATALOG
        assert "qwen_coder" in AI_MODEL_CATALOG
        assert "gemini_flash" in AI_MODEL_CATALOG
        assert "openrouter_llama" in AI_MODEL_CATALOG
        assert AI_MODEL_CATALOG["whiterabbitneo"].tier == ModelTier.LOCAL_GPU
        assert AI_MODEL_CATALOG["gemini_flash"].tier == ModelTier.CLOUD_FAST

    def test_select_best_model_when_all_online(self):
        bridge = AgentAICognitiveBridge()
        # Mark all online
        for p in bridge.catalog.values():
            p.is_online = True

        m_off = bridge.select_best_model_for_task(TaskType.OFFENSIVE_STRATEGY)
        assert m_off.model_id == "WhiteRabbitNeo"

        m_poc = bridge.select_best_model_for_task(TaskType.POC_AND_CODE)
        assert m_poc.model_id == "qwen2.5-coder:14b"

        m_recon = bridge.select_best_model_for_task(TaskType.RECON_AND_MAPPING)
        assert m_recon.model_id == "gemini-2.0-flash"

        m_deep = bridge.select_best_model_for_task(TaskType.DEEP_THREAT_LOGIC)
        assert m_deep.model_id == "meta-llama/llama-3.3-70b-instruct"

    def test_select_best_model_fallback_when_local_offline(self):
        bridge = AgentAICognitiveBridge()
        # Local offline, cloud online
        bridge.catalog["whiterabbitneo"].is_online = False
        bridge.catalog["qwen_coder"].is_online = False
        bridge.catalog["openrouter_llama"].is_online = True
        bridge.catalog["gemini_flash"].is_online = True

        m_off = bridge.select_best_model_for_task(TaskType.OFFENSIVE_STRATEGY)
        # Should fallback to OpenRouter 70B
        assert m_off.model_id == "meta-llama/llama-3.3-70b-instruct"

        m_poc = bridge.select_best_model_for_task(TaskType.POC_AND_CODE)
        # Should fallback to Gemini Flash
        assert m_poc.model_id == "gemini-2.0-flash"

    def test_build_agent_to_ai_prompt(self):
        bridge = AgentAICognitiveBridge()
        profile = bridge.catalog["whiterabbitneo"]
        obs = {
            "status_code": 200,
            "body_length": 1420,
            "tech_stack": "Oracle DB, Apache",
            "hypotheses": ["SQLi in category"]
        }
        sys_p, user_p = bridge.build_agent_to_ai_prompt(
            phase="orient",
            target_url="https://target.com/filter?category=gifts",
            param_name="category",
            observed_data=obs,
            model_profile=profile
        )
        assert "WhiteRabbitNeo" in sys_p
        assert "Offensive Security" in sys_p
        assert "TACTICAL AGENT CONTEXT" in user_p
        assert "Oracle DB" in user_p

    def test_format_awareness_summary(self):
        bridge = AgentAICognitiveBridge()
        summary = bridge.format_ai_awareness_summary()
        assert "Agent-AI Neural Awareness Matrix" in summary
        assert "WhiteRabbitNeo" in summary
        assert "Gemini" in summary
