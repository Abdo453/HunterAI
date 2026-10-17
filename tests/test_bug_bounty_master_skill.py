"""
Bug Bounty Master Skill + GitHub Resources Test Suite
=====================================================
كل الاختبارات offline — httpx.MockTransport بلا أي شبكة حقيقية.
"""
import os

import httpx
import pytest


# ════════════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════════════

def _patch_async_client(monkeypatch, handler):
    """يعيد httpx.AsyncClient كله عبر MockTransport محلي"""
    transport = httpx.MockTransport(handler)
    original = httpx.AsyncClient.__init__

    def patched(self, *a, **kw):
        kw.pop("proxies", None)
        kw["transport"] = transport
        original(self, *a, **kw)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched)
    return transport


def vuln_app_handler(crtsh_names=( "dev.target.com", "stg.target.com", "target.com")):
    """خادم مصاب: crt.sh + تطبيق بسرح open redirect في next"""
    import json as _json

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.startswith("https://crt.sh/"):
            return httpx.Response(200, json=[{"name_value": "\n".join(crtsh_names)}])
        qs = dict(u.split("=", 1) for u in url.split("?", 1)[1].split("&")) if "?" in url else {}
        nxt = qs.get("next")
        if nxt:
            nxt_decoded = nxt.replace("%3A", ":").replace("%2F", "/").replace("%2F%2E", "//")
            if any(m in nxt_decoded for m in ("hunterai-redirect-canary.invalid", "//", "\\/")):
                return httpx.Response(302, headers={"Location": nxt_decoded})
        return httpx.Response(200, text="<html><title>App</title></html>",
                              headers={"server": "nginx"})
    return handler


# ════════════════════════════════════════════════════════════════════════════
# 1. GitHub Resources
# ════════════════════════════════════════════════════════════════════════════

class TestGitHubResources:
    def test_payload_fallback_offline(self, tmp_path):
        """payloads لا تُستهلك من الشبكة أبداً — fallback دائماً"""
        def _boom(*a, **kw):
            raise RuntimeError("network must not be used for payloads")
        import core.bug_bounty.resources as m
        orig = m.httpx.get
        m.httpx.get = _boom
        try:
            res = m.GitHubResources(cache_root=tmp_path)
            data = res.fetch(m.SOURCES["open_redirect_payloads"])
        finally:
            m.httpx.get = orig
        assert data["origin"] == "fallback"
        assert data["count"] > 0
        assert data["sha256"]

    def test_methodology_cache_then_github(self, tmp_path, monkeypatch):
        import core.bug_bounty.resources as m
        res = m.GitHubResources(cache_root=tmp_path)

        # cache أولاً
        cache_file = tmp_path / "bug_bounty_recon_checklist.txt"
        cache_file.write_text("crt.sh\ndnsx  # inline comment\n", encoding="utf-8")
        out_cache = res.fetch(m.SOURCES["bug_bounty_recon_checklist"])
        assert out_cache["origin"] == "cache"
        assert "crt.sh" in out_cache["items"]

        # force_refresh → شبكة (مُحاكاة) → origin=github
        class FakeResp:
            status_code = 200
            text = "# github md\nsubfinder\nhttpx\n"
        monkeypatch.setattr(m.httpx, "get", lambda *a, **kw: FakeResp())
        out_net = res.fetch(m.SOURCES["bug_bounty_recon_checklist"], force_refresh=True)
        assert out_net["origin"] == "github"
        assert out_net["items"] == ["subfinder", "httpx"]
        # تم �aching محلي
        assert "subfinder" in cache_file.read_text(encoding="utf-8")

    def test_provenance(self):
        from core.bug_bounty.resources import get_github_resources
        prov = get_github_resources().provenance("nosql_injection_payloads")
        assert "PayloadsAllTheThings" in prov["source_git"]
        assert prov["category"] == "payloads"


# ════════════════════════════════════════════════════════════════════════════
# 2. BugBountyMasterSkill — Pipeline
# ════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_scope_violation_refuses_pipeline(monkeypatch):
    from agents.skills.bug_bounty_master_skill import BugBountyMasterSkill
    # إجبار إن أي طلب شبكة يفشل فوراً — لا يجوز إصدار أي طلب خارج النطاق
    def forbidden(*a, **kw):
        raise AssertionError("network request issued despite scope violation!")
    transport = httpx.MockTransport(forbidden)
    skill = BugBountyMasterSkill()
    res = await skill.run("https://rogue-domain.com/", param_name="",
                          in_scope=["target.com"], transport=transport)
    assert res.verified is False
    assert "scope" in "\n".join(res.logs).lower()
    assert res.extra["scope_ok"] is False
    assert res.extra["phase_reached"] == "scope"


@pytest.mark.asyncio
async def test_passive_pipeline_recon_and_probe(monkeypatch):
    """authorized=False: recon + probe فقط، بلا أي active testing"""
    _patch_async_client(monkeypatch, vuln_app_handler())
    from agents.skills.bug_bounty_master_skill import BugBountyMasterSkill
    skill = BugBountyMasterSkill()
    res = await skill.run("https://target.com/", param_name="",
                          in_scope=["*.target.com"], authorized=False)
    assert res.extra["scope_ok"] is True
    subs = res.extra["subdomains"]
    assert "dev.target.com" in subs
    assert "target.com" not in subs  # النطاق نفسه لا يُعد subdomain
    assets = res.extra["assets"]
    assert len(assets) >= 2  # base + probe limit
    assert any(a["asset"] == "dev.target.com" and a["reachable"] for a in assets)
    report = res.extra["report_md"]
    assert "# Bug Bounty Report — target.com" in report
    assert "passive-only" in report
    assert "crt.sh" in report                      # منهجية GitHub في التقرير
    assert res.verified is False                   # لا findings في الوضع السلبي


@pytest.mark.asyncio
async def test_active_pipeline_finds_open_redirect(monkeypatch):
    """authorized=True + param_candidates → run_best يكتشف open redirect فعلياً"""
    _patch_async_client(monkeypatch, vuln_app_handler())
    from agents.skills.registry import SkillRegistry
    from agents.skills.open_redirect_skill import OpenRedirectSkill
    SkillRegistry.reset()
    reg = SkillRegistry.instance()
    reg.register_class(OpenRedirectSkill)

    from agents.skills.bug_bounty_master_skill import BugBountyMasterSkill
    skill = BugBountyMasterSkill()
    res = await skill.run("https://dev.target.com/", param_name="",
                          in_scope=["*.target.com"], authorized=True,
                          param_candidates=[("https://dev.target.com/", "next")])
    assert res.verified is True
    findings = res.extra["findings"]
    assert any(f["verified"] and f["type"] == "open_redirect" for f in findings)
    f = [f for f in findings if f["verified"]][0]
    assert "hunterai-redirect-canary.invalid" in f["payload"] + f["evidence"]
    assert f["severity"] == "Medium"
    report = res.extra["report_md"]
    assert "Open Redirect" in report
    assert "verified" in report
    assert "Proof-of-Execution" in report


@pytest.mark.asyncio
async def test_pipeline_is_program_level_not_param_routable():
    from agents.skills.registry import SkillRegistry, bootstrap_builtin_skills
    bootstrap_builtin_skills()
    reg = SkillRegistry.instance()
    assert "bug_bounty_master_skill" in reg
    meta = reg.get("bug_bounty_master_skill")
    assert meta.name == "bug_bounty_master_skill"
    # لا تسرق توجيه البارامترات أبدًا
    assert reg.score_skill(meta, "next") == 0.0
    best = reg.best_for("next")
    assert best is not None and best.name != "bug_bounty_master_skill"


def test_exports():
    from agents.skills import BugBountyMasterSkill  # noqa: F401
    from agents.skills.bug_bounty_master_skill import BugBountyMasterSkill as M
    assert BugBountyMasterSkill is M


# ════════════════════════════════════════════════════════════════════════════
# 4. IVulnRouter → SkillRegistry wiring
# ════════════════════════════════════════════════════════════════════════════

def test_vuln_router_maps_params_to_registry_skills():
    from agents.skills.registry import bootstrap_builtin_skills
    reg = bootstrap_builtin_skills()   # idempotent; يضمن التسجيل بغض النظر عن ترتيب pytest
    assert reg.get("open_redirect_skill") is not None
    from hunter_ai.pipeline.vuln_router import VulnRouter
    from hunter_ai.pipeline.schemas import ParameterRecord

    router = VulnRouter()
    params = [
        ParameterRecord(parameter="returnurl", endpoint="https://example.com/redir", sample_value="http://evil.com"),
        ParameterRecord(parameter="id", endpoint="https://example.com/item", sample_value="42"),
        ParameterRecord(parameter="unknown_xyz_param", endpoint="https://example.com/nope"),
    ]
    tasks = router.route_tasks(params)
    skills = {t["skill"] for t in tasks}
    # returnurl يحتوي "url" → قد تُوجّه إلى OpenRedirect أو SSRF (كلاهما صالح لمعامل روابط)
    assert skills & {"open_redirect_skill", "ssrf_skill"}, skills
    # id → مهارة حقن (SQLi/idor/hpp...)
    assert any(t["param"] == "id" for t in tasks)
    # بارامتر غير معرّف لا يُسقّى لأي مهارة
    assert not any("unknown_xyz_param" == t["param"] for t in tasks)

