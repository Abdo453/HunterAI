"""
Unit tests for HunterAI Agent Scaffolding Runtime
"""
import pytest
import asyncio
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

from hunter_ai.runtime import (
    HypothesisTree, HypothesisStatus,
    PersistentWorkingMemory,
    ToolRegistry, ToolRiskLevel,
    SelfCritiqueValidator, CritiqueStatus,
    AgentRuntime
)


# ─── 1. HypothesisTree Tests ──────────────────────────────────────────────────
class TestHypothesisTree:
    def test_create_and_branch_hypotheses(self):
        tree = HypothesisTree()
        root = tree.create_hypothesis(
            category="SQLi",
            variant="boolean_differential",
            title="SQLi on ID",
            description="Testing id param for SQLi",
            target_endpoint="http://example.com/item",
            param_name="id",
            initial_confidence=0.5
        )
        assert root.id.startswith("H1_SQLI")
        assert root.status == HypothesisStatus.PENDING

        child = tree.create_hypothesis(
            category="SQLi",
            variant="union_extract",
            title="Union extraction on ID",
            description="Extract version string",
            target_endpoint="http://example.com/item",
            param_name="id",
            initial_confidence=0.3,
            parent_id=root.id
        )
        assert child.parent_id == root.id
        assert child.id in root.child_ids

    def test_evidence_scoring_and_frontier(self):
        tree = HypothesisTree()
        h1 = tree.create_hypothesis("SQLi", "bool", "H1", "desc", "http://x.com", "p1", 0.5)
        h2 = tree.create_hypothesis("IDOR", "owner", "H2", "desc", "http://x.com", "p2", 0.4)

        # Boost H1
        h1.add_evidence_for("Differential 1=1 vs 1=2 verified", confidence_boost=0.3)
        assert h1.confidence == 0.8
        assert len(h1.evidence_for) == 1

        # Penalize H2
        h2.add_evidence_against("Same output on user switch", confidence_penalty=0.3)
        assert h2.confidence == 0.1

        # Active frontier should have H1 first, and prune should catch H2
        frontier = tree.get_active_frontier(min_confidence=0.2)
        assert len(frontier) == 1
        assert frontier[0].id == h1.id

        pruned = tree.prune_low_confidence(threshold=0.15)
        assert pruned == 1
        assert h2.status == HypothesisStatus.REFUTED

    def test_serialize_deserialize(self):
        tree = HypothesisTree()
        tree.create_hypothesis("SSRF", "metadata", "SSRF test", "desc", "http://x.com", "url", 0.7)
        serialized = tree.serialize()

        loaded = HypothesisTree.deserialize(serialized)
        assert len(loaded.get_all_nodes()) == 1
        node = loaded.get_all_nodes()[0]
        assert node.category == "SSRF"
        assert node.confidence == 0.7


# ─── 2. PersistentWorkingMemory Tests ──────────────────────────────────────────
class TestPersistentWorkingMemory:
    def test_memory_persistence(self, tmp_path):
        mem = PersistentWorkingMemory(agent_dir=str(tmp_path / ".agent"))
        
        # State update
        mem.update_state(target="http://test.com", status="SCANNING")
        state = mem.get_state()
        assert state["target"] == "http://test.com"
        assert state["status"] == "SCANNING"

        # Observation
        mem.record_observation({"type": "reflection", "details": "Found canary in body"})
        obs = mem.get_observations()
        assert len(obs) == 1
        assert obs[0]["type"] == "reflection"

        # Failed test
        mem.record_failed_test("UNION", "' UNION SELECT 1--", "/api", "Status 500", "Try Boolean")
        failed = mem.get_failed_tests()
        assert len(failed) == 1
        assert failed[0]["test_name"] == "UNION"

        # Compact context
        compact = mem.get_compact_working_context()
        assert compact["mission"]["target"] == "http://test.com"


# ─── 3. ToolRegistry Tests ────────────────────────────────────────────────────
class TestToolRegistry:
    @pytest.mark.asyncio
    async def test_tool_registration_and_execution(self):
        registry = ToolRegistry()

        async def sample_tool(text: str, multiplier: int = 1):
            return {"result": text * multiplier}

        registry.register(
            name="echo",
            description="Repeats text",
            input_schema={
                "type": "object",
                "properties": {
                    "text": {"type": "string"},
                    "multiplier": {"type": "integer"}
                },
                "required": ["text"]
            },
            handler=sample_tool,
            risk_level=ToolRiskLevel.SAFE
        )

        # Successful execution
        res = await registry.execute("echo", {"text": "A", "multiplier": 3})
        assert res["success"] is True
        assert res["output"]["result"] == "AAA"

        # Missing required parameter
        err_res = await registry.execute("echo", {})
        assert err_res["success"] is False
        assert "Missing required arguments" in err_res["error"]


# ─── 4. SelfCritiqueValidator Tests ───────────────────────────────────────────
class TestSelfCritiqueValidator:
    def test_challenge_waf_block_as_refuted(self):
        critique = SelfCritiqueValidator()
        verdict = critique.challenge_finding(
            vuln_type="sqli",
            endpoint="http://example.com/api",
            param_name="id",
            claimed_evidence={"probe_status": 403, "boolean_differential": False}
        )
        assert verdict.status == CritiqueStatus.REFUTED
        assert "WAF" in verdict.alternative_explanations[0]

    def test_challenge_boolean_diff_as_confirmed(self):
        critique = SelfCritiqueValidator()
        verdict = critique.challenge_finding(
            vuln_type="sqli",
            endpoint="http://example.com/api",
            param_name="id",
            claimed_evidence={"boolean_differential": True, "probe_status": 200, "control_status": 200}
        )
        assert verdict.status == CritiqueStatus.CONFIRMED
        assert verdict.confidence >= 0.9

    def test_challenge_length_only_as_needs_evidence(self):
        critique = SelfCritiqueValidator()
        verdict = critique.challenge_finding(
            vuln_type="sqli",
            endpoint="http://example.com/api",
            param_name="id",
            claimed_evidence={"length_diff": 150}
        )
        assert verdict.status == CritiqueStatus.NEEDS_MORE_EVIDENCE
        assert "timestamps" in verdict.alternative_explanations[0].lower()


# ─── 5. AgentRuntime Loop Tests ───────────────────────────────────────────────
class TestAgentRuntime:
    @pytest.mark.asyncio
    async def test_agent_runtime_mission_flow(self, tmp_path):
        mock_registry = ToolRegistry()

        # Mock independent_verify to simulate discovering a confirmed boolean SQLi
        async def _mock_verify(target_url: str, param_name: str, vuln_type: str):
            return {
                "verified": True,
                "confidence": 0.95,
                "reason": "Clear differential behavior: OR 1=1 succeeded, AND 1=2 returned 0 items",
                "probe_status": 200,
                "control_status": 200
            }

        mock_registry.register(
            name="independent_verify",
            description="Mock verifier",
            input_schema={"type": "object", "required": ["target_url", "param_name", "vuln_type"]},
            handler=_mock_verify
        )

        async def _mock_probe(url: str):
            return {"status_code": 200, "content_length": 500}

        mock_registry.register(
            name="http_probe",
            description="Mock probe",
            input_schema={"type": "object", "required": ["url"]},
            handler=_mock_probe
        )

        runtime = AgentRuntime(
            agent_dir=str(tmp_path / ".agent"),
            tool_registry=mock_registry
        )

        result = await runtime.run_mission(
            target_url="http://test.local/products",
            initial_params=["category"],
            max_steps=5
        )

        assert result["status"] == "COMPLETED"
        assert result["findings_count"] >= 1
        assert result["findings"][0]["vulnerability"] == "SQLi"
        assert result["findings"][0]["confidence"] >= 0.85
