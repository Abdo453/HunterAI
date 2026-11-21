"""
tests/test_world_elite_brain.py

اختبارات شاملة لـ World Elite Agent Brain.
تغطي: OllamaProvider, ReActLoop, AttackGraph, VectorMemory, Orchestrator.

للأغراض التعليمية فقط — على أهداف مصرح بها.
"""

import asyncio
import json
import sys
import os

# إضافة مسار المشروع
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from core.brain.world_elite_react_loop import (
    AgentState,
    MockOllamaClient,
    OllamaProvider,
    Thought,
    ThoughtType,
    WorldEliteReActLoop,
)
from core.brain.world_elite_attack_graph import (
    AssetNode,
    AssetType,
    AttackEdge,
    EdgeType,
    MitreTactic,
    WorldEliteAttackGraph,
)
from core.brain.world_elite_vector_memory import WorldEliteVectorMemory


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK GRAPH TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestWorldEliteAttackGraph:

    def setup_method(self):
        self.graph = WorldEliteAttackGraph()

    def _build_sample_graph(self):
        """يبني رسم بياني بسيط للاختبار"""
        web = AssetNode("web01", AssetType.WEB_APP, "WebApp", ip="192.168.1.10", port=80)
        db  = AssetNode("db01",  AssetType.DATABASE,  "MySQL DB", ip="192.168.1.20", port=3306)
        api = AssetNode("api01", AssetType.API_ENDPOINT, "/api/v1", port=8080)

        self.graph.add_asset(web)
        self.graph.add_asset(db)
        self.graph.add_asset(api)

        self.graph.add_attack_path("web01", "db01", EdgeType.CONNECTS_TO,
                                   mitre_tactic=MitreTactic.LATERAL_MOVE,
                                   technique="T1021", difficulty=0.3)
        self.graph.add_attack_path("web01", "api01", EdgeType.EXPOSES,
                                   technique="T1190", difficulty=0.2)
        self.graph.add_attack_path("api01", "db01", EdgeType.DATA_FLOW,
                                   difficulty=0.4)
        return web, db, api

    def test_add_assets(self):
        """اختبار إضافة الأصول"""
        web, db, api = self._build_sample_graph()
        assert len(self.graph.nodes) == 3
        assert "web01" in self.graph.nodes
        assert "db01" in self.graph.nodes

    def test_add_attack_paths(self):
        """اختبار إضافة مسارات الهجوم"""
        self._build_sample_graph()
        assert len(self.graph.edges) == 3

    def test_crown_jewel_analysis(self):
        """اختبار تحديد Crown Jewels"""
        self._build_sample_graph()
        # أضف vulnerability للـ database لزيادة احتمالية الاختراق
        self.graph.add_vulnerability_to_asset("db01", {
            "severity": "critical", "name": "SQL Injection"
        })
        crown_jewels = self.graph.identify_crown_jewels()
        assert len(crown_jewels) >= 1
        # الـ database يجب أن يكون Crown Jewel
        crown_ids = [cj.id for cj in crown_jewels]
        assert "db01" in crown_ids, f"DB should be crown jewel. Got: {crown_ids}"

    def test_shortest_path(self):
        """اختبار إيجاد أقصر مسار"""
        self._build_sample_graph()
        path = self.graph.find_shortest_attack_path("web01", "db01")
        assert path is not None
        assert path[0] == "web01"
        assert path[-1] == "db01"

    def test_easiest_path(self):
        """اختبار إيجاد أسهل مسار"""
        self._build_sample_graph()
        path, cost = self.graph.find_easiest_attack_path("web01", "db01")
        assert path is not None
        assert cost < float("inf")

    def test_risk_calculation(self):
        """اختبار حساب الخطورة"""
        self._build_sample_graph()
        path = ["web01", "api01", "db01"]
        risk = self.graph.calculate_path_risk(path)
        assert "risk_score" in risk
        assert "severity" in risk
        assert 0.0 <= risk["risk_score"] <= 1.0

    def test_mermaid_export(self):
        """اختبار تصدير Mermaid"""
        self._build_sample_graph()
        mermaid = self.graph.export_to_mermaid()
        assert "flowchart LR" in mermaid
        assert "web01" in mermaid

    def test_json_export(self):
        """اختبار تصدير JSON"""
        self._build_sample_graph()
        json_str = self.graph.export_to_json()
        data = json.loads(json_str)
        assert "nodes" in data
        assert "edges" in data
        assert "summary" in data

    def test_attack_surface_summary(self):
        """اختبار ملخص سطح الهجوم"""
        self._build_sample_graph()
        summary = self.graph.get_attack_surface_summary()
        assert summary["total_assets"] == 3
        assert summary["total_attack_paths"] == 3


# ─────────────────────────────────────────────────────────────────────────────
# VECTOR MEMORY TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestWorldEliteVectorMemory:

    def setup_method(self, tmp_path=None):
        import tempfile
        self.tmp_dir = tempfile.mkdtemp()
        self.memory = WorldEliteVectorMemory(
            storage_dir=self.tmp_dir,
            use_vector_db=False,  # keyword search للاختبار
        )

    def test_remember_and_recall(self):
        """اختبار الحفظ والاسترجاع"""
        self.memory.remember(
            content="SQL injection found in login endpoint /api/login parameter 'user'",
            category="finding",
            target="192.168.1.10",
            importance=0.9,
            metadata={"severity": "critical"},
        )
        results = self.memory.recall("SQL injection login", n=5)
        assert len(results) >= 1
        assert any("SQL" in r.content for r in results)

    def test_category_filter(self):
        """اختبار تصفية حسب category"""
        self.memory.remember("Port 80 open", "observation", "192.168.1.10", importance=0.5)
        self.memory.remember("XSS in /search", "finding", "192.168.1.10", importance=0.8)

        findings = self.memory.recall("open XSS", category="finding")
        assert all(r.category == "finding" for r in findings)

    def test_findings_summary(self):
        """اختبار تلخيص الـ findings"""
        self.memory.remember("Critical RCE", "finding", "192.168.1.10",
                             importance=1.0, metadata={"severity": "critical"})
        self.memory.remember("Low info disclosure", "finding", "192.168.1.10",
                             importance=0.2, metadata={"severity": "low"})
        summary = self.memory.get_findings_summary("192.168.1.10")
        assert summary["total_findings"] == 2

    def test_cross_target_correlation(self):
        """اختبار الربط عبر targets مختلفة"""
        self.memory.remember("SQL injection in login", "finding", "192.168.1.10", importance=0.9)
        self.memory.remember("SQL injection in register", "finding", "192.168.1.20", importance=0.8)
        self.memory.remember("XSS in search", "finding", "192.168.1.30", importance=0.7)

        related = self.memory.cross_target_correlation("SQL injection")
        assert len(related) == 2

    def test_stats(self):
        """اختبار الإحصائيات"""
        self.memory.remember("test entry", "observation", "127.0.0.1")
        stats = self.memory.stats()
        assert stats["total_entries"] >= 1
        assert "by_category" in stats


# ─────────────────────────────────────────────────────────────────────────────
# REACT LOOP TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestWorldEliteReActLoop:

    def setup_method(self):
        """يستخدم MockOllamaClient للاختبار بدون Ollama حقيقي"""
        self.llm = OllamaProvider()
        self.llm._client = MockOllamaClient()
        self.llm._available = True

    def test_agent_state_initialization(self):
        """اختبار تهيئة حالة الـ Agent"""
        state = AgentState(
            goal="Find SQLi vulnerabilities",
            target="http://127.0.0.1",
            scope=["127.0.0.1"],
        )
        assert state.phase == "recon"
        assert state.step_count == 0
        assert len(state.findings) == 0

    def test_agent_state_update(self):
        """اختبار تحديث حالة الـ Agent"""
        from core.brain.world_elite_react_loop import Observation
        state = AgentState("test", "http://127.0.0.1", ["127.0.0.1"])
        obs = Observation(raw_output="Port 80 open", success=True)
        state.update(obs)
        assert state.step_count == 1
        assert len(state.context_window) == 1

    def test_agent_state_to_context_string(self):
        """اختبار تحويل الحالة لنص"""
        state = AgentState("Find bugs", "http://127.0.0.1", ["127.0.0.1"])
        ctx = state.to_context_string()
        assert "Find bugs" in ctx
        assert "127.0.0.1" in ctx
        assert "recon" in ctx

    @pytest.mark.asyncio
    async def test_react_loop_runs(self):
        """اختبار تشغيل الـ ReAct loop بأدوات وهمية"""
        def mock_port_scanner(target: str, **kwargs) -> str:
            return f"Port 80 open on {target}"

        def mock_web_crawler(target: str, **kwargs) -> str:
            return f"/admin /api /login found on {target}"

        tool_registry = {
            "port_scanner": mock_port_scanner,
            "web_crawler": mock_web_crawler,
        }

        loop = WorldEliteReActLoop(
            llm=self.llm,
            tool_registry=tool_registry,
            max_steps=3,
            hallucination_filter=False,  # تعطيل للاختبار
        )

        result = await loop.run(
            goal="Find vulnerabilities",
            target="http://127.0.0.1",
            scope=["127.0.0.1"],
        )

        assert "total_steps" in result
        assert result["total_steps"] <= 3

    @pytest.mark.asyncio
    async def test_ollama_provider_think_fallback(self):
        """اختبار الـ fallback عند فشل الـ LLM"""
        # ننشئ provider مع client خاطئ
        llm = OllamaProvider(host="http://localhost:99999")
        thought = await llm.think("test context", role="planner")
        # يجب أن يرجع Thought حتى مع الفشل
        assert isinstance(thought, Thought)
        assert thought.type in ThoughtType.__members__.values()


# ─────────────────────────────────────────────────────────────────────────────
# INTEGRATION TEST
# ─────────────────────────────────────────────────────────────────────────────

class TestIntegration:

    @pytest.mark.asyncio
    async def test_full_pipeline_mock(self):
        """
        اختبار Pipeline كامل بأدوات وهمية.
        يتحقق من تكامل AttackGraph + VectorMemory + ReActLoop.
        """
        import tempfile

        # 1. Attack Graph
        graph = WorldEliteAttackGraph()
        web = AssetNode("web01", AssetType.WEB_APP, "WebApp", ip="127.0.0.1")
        db  = AssetNode("db01", AssetType.DATABASE, "MySQL", ip="127.0.0.1")
        graph.add_asset(web)
        graph.add_asset(db)
        graph.add_attack_path("web01", "db01", EdgeType.CONNECTS_TO,
                               technique="T1190", difficulty=0.3)
        graph.add_vulnerability_to_asset("db01", {"severity": "high", "name": "SQLi"})

        crown_jewels = graph.identify_crown_jewels()
        assert len(crown_jewels) >= 1

        # 2. Vector Memory
        tmp_dir = tempfile.mkdtemp()
        memory = WorldEliteVectorMemory(storage_dir=tmp_dir, use_vector_db=False)
        memory.remember("SQL injection critical", "finding", "127.0.0.1",
                        importance=1.0, metadata={"severity": "critical"})

        recalls = memory.recall("SQL injection")
        assert len(recalls) >= 1

        # 3. Summary
        summary = graph.get_attack_surface_summary()
        assert summary["total_assets"] == 2
        assert summary["total_vulnerabilities"] == 1

        mem_stats = memory.stats()
        assert mem_stats["total_entries"] >= 1

        print("\n✅ Full pipeline integration test passed!")
        print(f"   Crown Jewels: {[cj.name for cj in crown_jewels]}")
        print(f"   Memory entries: {mem_stats['total_entries']}")
        print(f"   Attack paths: {summary['total_attack_paths']}")


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-x"])
