import pytest
import os
from unittest.mock import AsyncMock, patch, MagicMock
from models.ollama_manager import OllamaManager, normalize_ollama_host
from orchestrator.resource_manager import ResourceManager
from orchestrator.router import ModelRouter
from models.api.gemini_provider import GeminiProvider
from models.api.openrouter_provider import OpenRouterProvider
from core.smart_orchestrator import SmartOrchestrator


class TestAIModelConnectivity:
    def test_ollama_host_normalization(self):
        """Verify local Ollama host normalization to prevent connection errors"""
        assert normalize_ollama_host("0.0.0.0:11434") == "http://127.0.0.1:11434"
        assert normalize_ollama_host("http://localhost:11434/") == "http://localhost:11434"
        assert normalize_ollama_host("") == "http://127.0.0.1:11434"

    @pytest.mark.asyncio
    async def test_resource_manager_gpu_lock_cycle(self):
        """Verify exclusive GPU locking and automatic unloading of local models"""
        ollama = OllamaManager()
        ollama.unload_model = AsyncMock(return_value=True)
        rm = ResourceManager(ollama)

        assert rm.is_gpu_free() is True
        async with rm.exclusive_gpu("whiterabbitneo:8b") as gpu:
            assert rm.is_gpu_free() is False
            assert rm.status["current_model"] == "whiterabbitneo:8b"
            assert rm.status["locked"] is True

        assert rm.is_gpu_free() is True
        ollama.unload_model.assert_called_once_with("whiterabbitneo:8b")

    @pytest.mark.asyncio
    async def test_cloud_gemini_provider_integration(self):
        """Verify Google Gemini provider formatting and execution contract"""
        with patch.dict(os.environ, {"GEMINI_API_KEY": "test_gemini_key_123"}):
            gm = GeminiProvider(model="gemini-2.5-flash")
            assert gm.model_name == "gemini-2.5-flash"
            assert await gm.is_available() is True

            # Mock httpx client response
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "candidates": [{"content": {"parts": [{"text": "Gemini security analysis: SQLi verified"}]}}]
            }

            with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
                res = await gm.generate("Test prompt")
                assert res.content == "Gemini security analysis: SQLi verified"
                assert res.error is None

    @pytest.mark.asyncio
    async def test_model_router_fallback_to_cloud_when_local_offline(self):
        """Verify ModelRouter seamlessly falls back to cloud API when local models are unavailable"""
        ollama = OllamaManager()
        # Mock chat_stream returning empty string (Ollama offline)
        ollama.chat_stream = AsyncMock(return_value="")
        rm = ResourceManager(ollama)
        router = ModelRouter(rm)

        # Mock cloud API
        router._call_security_api = AsyncMock(return_value="Cloud AI: Recommended remediation is parameter binding.")

        res = await router.route("Analyze this SQL injection vulnerability")
        assert res["route"] in ("SECURITY", "SECURITY_CLOUD", "MIXED")
        assert "parameter binding" in res["final"]

        # Explicitly test _security_route fallback
        sec_res = await router._security_route("Target is running vulnerable service", "", None)
        assert sec_res["route"] == "SECURITY_CLOUD"
        assert "parameter binding" in sec_res["final"]


    @pytest.mark.asyncio
    async def test_smart_orchestrator_chat_e2e_coordination(self):
        """Verify SmartOrchestrator coordinates chat routing with active agent context"""
        orch = SmartOrchestrator()
        orch.router.route = AsyncMock(return_value={
            "final": "Autonomous Agent analysis complete. High risk finding.",
            "route": "SECURITY",
            "models_used": ["whiterabbitneo"]
        })

        chat_res = await orch.chat("Scan target for XSS vulnerabilities", selected_model="auto")
        assert "Autonomous Agent analysis" in chat_res["answer"]
        assert chat_res["route"] == "SECURITY"
