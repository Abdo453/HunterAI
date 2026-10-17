"""
Unit Tests for Session Flaws Skill (agents/skills/session_flaws_skill.py)
==========================================================================
Offline فقط عبر httpx.MockTransport — لا شبكة حقيقية.
"""
import httpx
import pytest


def _make_handler(set_cookie_header=None, url_echo_token=False):
    def handler(request: httpx.Request) -> httpx.Response:
        headers = {}
        if set_cookie_header:
            headers["Set-Cookie"] = set_cookie_header
        body = b"<html><body>ok</body></html>"
        if url_echo_token:
            # يُعيد نفس المحتوى مع وبدون التوكن في الرابط
            body = b"<html><body>dashboard</body></html>"
        return httpx.Response(200, headers=headers, content=body)
    return handler


def _patch_client(monkeypatch, handler):
    transport = httpx.MockTransport(handler)
    original = httpx.AsyncClient.__init__

    def patched(self, *a, **kw):
        kw.pop("proxies", None)
        kw["transport"] = transport
        original(self, *a, **kw)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched)


@pytest.mark.asyncio
async def test_session_flaws_weak_cookie_flags(monkeypatch):
    """كويكية جلسة بدون Secure/HttpOnly/SameSite → نتيجة مؤكدة."""
    import agents.skills.session_flaws_skill as mod
    _patch_client(monkeypatch, _make_handler("sessionid=abc123; Path=/"))

    skill = mod.SessionFlawsSkill()
    res = await skill.run("https://target.com/", param_name="sessionid")

    assert res.verified is True
    assert res.vuln_type == "session_flaws"
    assert res.cwe == "CWE-613"
    assert res.severity in ("Medium", "High")
    assert "Secure" in res.evidence or "HttpOnly" in res.evidence or "SameSite" in res.evidence
    assert len(res.logs) >= 1


@pytest.mark.asyncio
async def test_session_flaws_secure_cookie_not_verified(monkeypatch):
    """كويكية جلسة آمنة تماماً → لا نتيجة."""
    import agents.skills.session_flaws_skill as mod
    _patch_client(monkeypatch, _make_handler(
        "sessionid=abc123; Secure; HttpOnly; SameSite=Strict; Max-Age=3600; Path=/"))

    skill = mod.SessionFlawsSkill()
    res = await skill.run("https://target.com/", param_name="sessionid")

    assert res.verified is False


@pytest.mark.asyncio
async def test_session_flaws_token_in_url(monkeypatch):
    """توكن الجلسة داخل عنوان URL → نتيجة مؤكدة (استجابة مطابقة مع وبدون التوكن)."""
    import agents.skills.session_flaws_skill as mod
    _patch_client(monkeypatch, _make_handler(url_echo_token=True))

    skill = mod.SessionFlawsSkill()
    res = await skill.run("https://target.com/page?sessionid=xyz789", param_name="sessionid")

    assert res.verified is True
    assert "URL" in res.evidence or "sessionid" in res.evidence


@pytest.mark.asyncio
async def test_session_flaws_can_handle():
    import agents.skills.session_flaws_skill as mod
    skill = mod.SessionFlawsSkill()
    assert skill.can_handle("sessionid") > 0.5
    assert skill.can_handle("id") == 0.3


def test_session_flaws_registered():
    from agents.skills.registry import bootstrap_builtin_skills
    reg = bootstrap_builtin_skills()
    assert "session_flaws_skill" in reg
    meta = reg.get("session_flaws_skill")
    assert meta.vuln_type == "session_flaws"
    assert meta.cwe == "CWE-613"
