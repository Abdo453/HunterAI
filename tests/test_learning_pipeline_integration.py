"""
Integration Tests for LearningPipeline and Web Endpoints
Tests: HTTP signal extraction, Burp traffic processing, and Learning REST APIs.
"""
import pytest
import httpx

from core.learning.learning_pipeline import LearningPipeline
from ui.web.app import app


class TestLearningPipelineIntegration:
    def test_extract_signals_from_burp_traffic(self):
        pipeline = LearningPipeline()

        # Request 1: Invoices with numeric ID and Bearer Auth
        signals_1 = pipeline.extract_signals_from_http(
            method="GET",
            url="https://app.corp.local/api/v1/invoices/9941",
            headers={"Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."}
        )
        assert "resource_identifier" in signals_1
        assert "numeric_id" in signals_1
        assert "authenticated_request" in signals_1
        assert "bearer_token" in signals_1
        assert "jwt_structure" in signals_1

        # Request 2: Admin route with query filter
        signals_2 = pipeline.extract_signals_from_http(
            method="POST",
            url="https://app.corp.local/admin/users?filter=all",
            headers={"Cookie": "session=xyz"}
        )
        assert "admin_path" in signals_2
        assert "filter_parameter" in signals_2
        assert "cookies" in signals_2

    def test_process_burp_traffic_end_to_end(self):
        pipeline = LearningPipeline()
        result = pipeline.process_burp_traffic(
            method="GET",
            url="https://app.corp.local/api/v1/invoices/100",
            headers={"Authorization": "Bearer token123"}
        )

        assert "extracted_signals" in result
        assert "resource_identifier" in result["extracted_signals"]
        assert len(result["relevant_knowledge"]) > 0
        assert "recommended_strategy" in result

    @pytest.mark.asyncio
    async def test_rest_api_get_curriculum(self):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            res = await client.get("/api/learning/curriculum")
            assert res.status_code == 200
            data = res.json()
            assert "levels" in data
            assert data["total_levels"] == 10

    @pytest.mark.asyncio
    async def test_rest_api_teach_endpoint(self):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Challenge presentation
            res_chal = await client.post("/api/learning/teach", json={"level": 3})
            assert res_chal.status_code == 200
            data_chal = res_chal.json()
            assert "challenge" in data_chal
            assert data_chal["challenge"]["level"] == 3

            # 2. Reasoning evaluation
            payload_eval = {
                "level": 3,
                "actions": ["unauthenticated_baseline", "cross_tenant_probe"],
                "hypotheses": {"BOLA": 0.95},
                "evidence": ["EVID-01"]
            }
            res_eval = await client.post("/api/learning/teach", json=payload_eval)
            assert res_eval.status_code == 200
            data_eval = res_eval.json()
            assert "evaluation" in data_eval
            assert data_eval["evaluation"]["passed"] is True

    @pytest.mark.asyncio
    async def test_rest_api_experiences_and_rag_query(self):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # Experiences endpoint
            res_exp = await client.get("/api/learning/experiences")
            assert res_exp.status_code == 200
            assert "episodes" in res_exp.json()

            # RAG Query endpoint
            res_rag = await client.post("/api/learning/rag_query", json={"signals": ["numeric_id"], "topic": "authorization"})
            assert res_rag.status_code == 200
            rag_data = res_rag.json()
            assert "matched_knowledge_items" in rag_data
            assert len(rag_data["matched_knowledge_items"]) > 0
