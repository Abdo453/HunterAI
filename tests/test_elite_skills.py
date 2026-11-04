"""
Hermetic Unit Tests for Elite Bug Bounty Skills:
- Cognitive: threat_modeler, adversarial_planner, exploit_chain_builder
- Browser: dom_xss_hunter, auth_session_extractor, spa_api_extractor
- Burp: burp_traffic_analyzer, burp_browser_fusion, request_mutator
- Meta: full_pipeline_orchestrator
- Agent Vuln: HTTPSmugglingSkill, CachePoisoningSkill, OAuth2AbuseSkill,
              PrototypePollutionSkill, PathTraversalSkill, JWTAdvancedSkill
"""
import pytest
from skills.base_skill import SkillContext
from core.workspace_manager import WorkspaceManager
from tools.tool_manager import ToolManager


# ── 1. Cognitive Brain Skills Tests ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_threat_modeler_skill_hermetic(tmp_path):
    from skills.cognitive.threat_modeler.skill import ThreatModelerSkill
    ws = WorkspaceManager(tmp_path)
    tm = ToolManager()
    ctx = SkillContext(
        target="target.corp",
        session_id="test_sess_tm",
        workspace=ws,
        tool_manager=tm,
        extra={
            "endpoints": [
                {"url": "https://target.corp/api/v1/users/123", "method": "GET", "params": {"user_id": "123"}},
                {"url": "https://target.corp/admin/upload", "method": "POST", "params": {"file": "doc.pdf"}},
                {"url": "https://target.corp/checkout", "method": "POST", "params": {"price": "100"}},
            ],
            "tech_stack": ["Node.js", "Express", "PostgreSQL"],
        }
    )
    skill = ThreatModelerSkill()
    res = await skill.execute(ctx)
    assert res.success is True
    assert "threat_model.json" in res.output_files
    assert "attack_tree.md" in res.output_files
    assert len(res.findings) >= 1


@pytest.mark.asyncio
async def test_adversarial_planner_skill_hermetic(tmp_path):
    from skills.cognitive.adversarial_planner.skill import AdversarialPlannerSkill
    ws = WorkspaceManager(tmp_path)
    tm = ToolManager()
    ctx = SkillContext(
        target="target.corp",
        session_id="test_sess_ap",
        workspace=ws,
        tool_manager=tm,
        extra={
            "findings_so_far": [
                {"title": "IDOR on user profile", "severity": "High", "endpoint": "/api/users/10"},
                {"title": "Reflected XSS on search", "severity": "Medium", "endpoint": "/search?q=test"},
            ]
        }
    )
    skill = AdversarialPlannerSkill()
    res = await skill.execute(ctx)
    assert res.success is True
    assert "attack_plan.md" in res.output_files
    assert "next_actions.json" in res.output_files


@pytest.mark.asyncio
async def test_exploit_chain_builder_skill_hermetic(tmp_path):
    from skills.cognitive.exploit_chain_builder.skill import ExploitChainBuilderSkill
    ws = WorkspaceManager(tmp_path)
    tm = ToolManager()
    ctx = SkillContext(
        target="target.corp",
        session_id="test_sess_ecb",
        workspace=ws,
        tool_manager=tm,
        extra={
            "findings": [
                {"title": "Reflected XSS", "type": "XSS", "severity": "Medium", "endpoint": "/search"},
                {"title": "CORS Wildcard with Credentials", "type": "CORS", "severity": "High", "endpoint": "/api/user"},
            ]
        }
    )
    skill = ExploitChainBuilderSkill()
    res = await skill.execute(ctx)
    assert res.success is True
    assert "exploit_chains.json" in res.output_files
    assert "chain_report.md" in res.output_files


# ── 2. Browser AI Skills Tests ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_dom_xss_hunter_hermetic(tmp_path):
    from skills.browser.dom_xss_hunter.skill import DOMXSSHunterSkill
    ws = WorkspaceManager(tmp_path)
    tm = ToolManager()
    ctx = SkillContext(target="target.corp", session_id="test_dom", workspace=ws, tool_manager=tm)
    skill = DOMXSSHunterSkill()
    res = await skill.execute(ctx)
    assert res.success is True
    assert "dom_xss_findings.json" in res.output_files
    assert "dom_xss_report.md" in res.output_files


@pytest.mark.asyncio
async def test_auth_session_extractor_hermetic(tmp_path):
    from skills.browser.auth_session_extractor.skill import AuthSessionExtractorSkill
    ws = WorkspaceManager(tmp_path)
    tm = ToolManager()
    ctx = SkillContext(target="target.corp", session_id="test_auth", workspace=ws, tool_manager=tm)
    skill = AuthSessionExtractorSkill()
    res = await skill.execute(ctx)
    assert res.success is True
    assert "auth_context.json" in res.output_files
    assert "auth_context" in res.metadata


@pytest.mark.asyncio
async def test_spa_api_extractor_hermetic(tmp_path):
    from skills.browser.spa_api_extractor.skill import SPAAPIExtractorSkill
    ws = WorkspaceManager(tmp_path)
    tm = ToolManager()
    ctx = SkillContext(target="target.corp", session_id="test_spa", workspace=ws, tool_manager=tm)
    skill = SPAAPIExtractorSkill()
    res = await skill.execute(ctx)
    assert res.success is True
    assert "spa_endpoints.json" in res.output_files
    assert "spa_api_map.md" in res.output_files


# ── 3. Burp Suite Skills Tests ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_burp_traffic_analyzer_hermetic(tmp_path):
    from skills.burp.burp_traffic_analyzer.skill import BurpTrafficAnalyzerSkill
    ws = WorkspaceManager(tmp_path)
    tm = ToolManager()
    ctx = SkillContext(target="target.corp", session_id="test_burp_ta", workspace=ws, tool_manager=tm)
    skill = BurpTrafficAnalyzerSkill()
    res = await skill.execute(ctx)
    assert res.success is True
    assert "burp_findings.json" in res.output_files
    assert "burp_analysis_report.md" in res.output_files


@pytest.mark.asyncio
async def test_burp_browser_fusion_hermetic(tmp_path):
    from skills.burp.burp_browser_fusion.skill import BurpBrowserFusionSkill
    ws = WorkspaceManager(tmp_path)
    tm = ToolManager()
    ctx = SkillContext(target="target.corp", session_id="test_fusion", workspace=ws, tool_manager=tm)
    skill = BurpBrowserFusionSkill()
    res = await skill.execute(ctx)
    assert res.success is True
    assert "fusion_endpoints.json" in res.output_files
    assert "fusion_report.md" in res.output_files


@pytest.mark.asyncio
async def test_request_mutator_hermetic(tmp_path):
    from skills.burp.request_mutator.skill import RequestMutatorSkill
    ws = WorkspaceManager(tmp_path)
    tm = ToolManager()
    ctx = SkillContext(target="target.corp", session_id="test_mut", workspace=ws, tool_manager=tm)
    skill = RequestMutatorSkill()
    res = await skill.execute(ctx)
    assert res.success is True
    assert "mutation_results.json" in res.output_files
    assert "mutation_report.md" in res.output_files


# ── 4. Full Master Orchestrator Test ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_full_pipeline_orchestrator_hermetic(tmp_path):
    from skills.meta.full_pipeline_orchestrator.skill import FullPipelineOrchestratorSkill
    ws = WorkspaceManager(tmp_path)
    tm = ToolManager()
    ctx = SkillContext(target="target.corp", session_id="test_master", workspace=ws, tool_manager=tm, extra={"authorized": True})
    skill = FullPipelineOrchestratorSkill()
    res = await skill.execute(ctx)
    assert res.success is True
    assert "pipeline_findings.json" in res.output_files
    assert "pipeline_report.md" in res.output_files
    assert res.metadata["duration"] >= 0


# ── 5. Elite Agent Vuln Skills Tests ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_prototype_pollution_skill_hermetic():
    from agents.skills.prototype_pollution_skill import PrototypePollutionSkill
    skill = PrototypePollutionSkill()
    res = await skill.run("https://hermetic-test.corp/api/settings", "config")
    assert res.vuln_type == "prototype_pollution"
    assert res.cwe == "CWE-1321"


@pytest.mark.asyncio
async def test_path_traversal_skill_hermetic():
    from agents.skills.path_traversal_skill import PathTraversalSkill
    skill = PathTraversalSkill()
    res = await skill.run("https://hermetic-test.corp/view", "file")
    assert res.vuln_type == "path_traversal"
    assert res.cwe == "CWE-22"


@pytest.mark.asyncio
async def test_jwt_advanced_skill_hermetic():
    from agents.skills.jwt_advanced_skill import JWTAdvancedSkill
    skill = JWTAdvancedSkill()
    res = await skill.run("https://hermetic-test.corp/profile", "token")
    assert res.vuln_type == "jwt_advanced"
    assert res.cwe == "CWE-347"


@pytest.mark.asyncio
async def test_http_smuggling_skill_hermetic():
    from agents.skills.http_smuggling_skill import HTTPSmugglingSkill
    skill = HTTPSmugglingSkill()
    res = await skill.run("https://hermetic-test.corp")
    assert res.vuln_type == "http_request_smuggling"


@pytest.mark.asyncio
async def test_cache_poisoning_skill_hermetic():
    from agents.skills.cache_poisoning_skill import CachePoisoningSkill
    skill = CachePoisoningSkill()
    res = await skill.run("https://hermetic-test.corp")
    assert res.vuln_type == "cache_poisoning"


@pytest.mark.asyncio
async def test_oauth2_abuse_skill_hermetic():
    from agents.skills.oauth2_abuse_skill import OAuth2AbuseSkill
    skill = OAuth2AbuseSkill()
    res = await skill.run("https://hermetic-test.corp/oauth/authorize")
    assert res.vuln_type == "oauth2_abuse"
