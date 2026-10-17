"""
Skill Registry + New Vulnerability Skills Test Suite (v2 Arsenal)
=================================================================
كل الاختبارات تعمل عبر httpx.MockTransport — محاكاة خوادم مصابة حقيقية
بدون أي حركة شبكة حقيقية (Safe by construction).
"""
import json as _json

import httpx
import pytest

# ════════════════════════════════════════════════════════════════════════════
# Helpers — بناء AsyncClient مراقَب عبر MockTransport
# ════════════════════════════════════════════════════════════════════════════

def _make_patched_asyncclient(handler):
    """يعيد مصنع httpx.AsyncClient الذي يمرر كل الطلبات عبر handler محلي"""
    transport = httpx.MockTransport(handler)
    original_init = httpx.AsyncClient.__init__

    def patched(self, *args, **kwargs):
        kwargs.pop("proxies", None)   # تجاهل البروكسي في الاختبار
        kwargs["transport"] = transport
        original_init(self, *args, **kwargs)

    return patched


# ════════════════════════════════════════════════════════════════════════════
# 1. Skill Registry
# ════════════════════════════════════════════════════════════════════════════

class TestSkillRegistry:
    @pytest.fixture(scope="class", autouse=True)
    def _bootstrap(self):
        from agents.skills.registry import bootstrap_builtin_skills
        bootstrap_builtin_skills()

    def test_registration_count(self):
        from agents.skills.registry import SkillRegistry
        reg = SkillRegistry.instance()
        assert len(reg) >= 22, f"expected >=22 skills, got {len(reg)}"

    def test_metadata_overrides_for_legacy_skills(self):
        from agents.skills.registry import SkillRegistry
        reg = SkillRegistry.instance()
        ssql = reg.get("SQLiSkill")
        assert ssql is not None
        assert ssql.vuln_type == "sqli"
        assert ssql.cwe == "CWE-89"

    def test_best_for_routes_redirect_param(self):
        from agents.skills.registry import SkillRegistry
        reg = SkillRegistry.instance()
        best = reg.best_for("returnurl")
        assert best is not None
        assert "redirect" in best.vuln_type or best.vuln_type in ("open_redirect", "ssrf", "crlf_injection")

    def test_best_for_routes_id_param(self):
        from agents.skills.registry import SkillRegistry
        reg = SkillRegistry.instance()
        best = reg.best_for("user_id")
        assert best is not None
        assert "idor" in best.vuln_type or best.name.lower().startswith(("idor", "sql"))

    def test_unknown_param_below_threshold(self):
        from agents.skills.registry import SkillRegistry
        reg = SkillRegistry.instance()
        assert reg.best_for("random_blob_param_xyz", min_score=0.6) is None

    def test_param_keyword_fallback(self):
        from agents.skills.registry import SkillRegistry
        reg = SkillRegistry.instance()
        # ldap skill لديها keywords لكن can_handle أيضاً — يجب أن يعيد أي شيء معقول
        ranked = reg.rank("uid")
        assert ranked and len(ranked) >= 1

    def test_matrix_shape(self):
        from agents.skills.registry import SkillRegistry
        m = SkillRegistry.instance().matrix()
        assert "ssrf_skill" in m
        entry = m["ssrf_skill"]
        assert {"vuln_type", "cwe", "owasp_top10", "default_severity", "param_keywords"} <= set(entry.keys())

    @pytest.mark.asyncio
    async def test_run_best_returns_result(self, monkeypatch):
        """run_best أفضل مهارة إنشاء skills فاشلة لا يكسر التنفيذ"""
        from agents.skills.registry import SkillRegistry, bootstrap_builtin_skills

        # ضآل registry قبل الاختبار — لعزل أثر autouse
        SkillRegistry.reset()
        reg = bootstrap_builtin_skills()

        # كل الـ HTTP عبر Mock راكض يجعله يستجيب 503 دائماً للاستجابة البحتة
        always_503 = _make_patched_asyncclient(lambda r: httpx.Response(503, text="nope"))
        monkeypatch.setattr("httpx.AsyncClient.__init__", always_503)

        result = await reg.run_best("http://target.local/search?q=x", "q")
        assert result is not None
        assert result.verified is False   # لا يكذب — فقطة إيجابية

        SkillRegistry.reset()


# ════════════════════════════════════════════════════════════════════════════
# 2. SSRF — الإصلاح الجوهري: الطلب عبر الـ target لا محلياً
# ════════════════════════════════════════════════════════════════════════════

class TestSSRFFixed:
    def _vuln_app_handler(self, request: httpx.Request) -> httpx.Response:
        """مخادع: خادم مصاب يجلب URL من بارامتر url ويعيد محتواه كأنه إخراج داخلي"""
        from urllib.parse import urlparse, parse_qs
        u = urlparse(str(request.url))
        qs = parse_qs(u.query)
        fetched = qs.get("url", [""])[0]
        if "169.254.169.254" in fetched or "2852039166" in fetched:
            return httpx.Response(200, text="ami-id: ami-0abcdef123456789")
        if "127.0.0.1" in fetched or "2130706433" in fetched or "0x7f000001" in fetched or "localhost" in fetched:
            return httpx.Response(200, text="apache tomcat server status internal")
        return httpx.Response(200, text="generic page, nothing interesting, 1024 chars padding" * 30)

    @pytest.mark.asyncio
    async def test_ssrf_verified_through_target(self, monkeypatch):
        from agents.skills.ssrf_skill import SSRFSkill
        monkeypatch.setattr("httpx.AsyncClient.__init__",
                            _make_patched_asyncclient(self._vuln_app_handler))
        skill = SSRFSkill()
        result = await skill.run("http://app.local/fetch?url=x", "url")
        assert result.verified, f"expected verified, evidence={result.evidence!r}"

    @pytest.mark.asyncio
    async def test_ssrf_safe_app_not_verified(self, monkeypatch):
        """تطبيق آمن لا نتيجة — يجب أن يكون verified=False دائماً"""
        from agents.skills.ssrf_skill import SSRFSkill
        safe_handler = lambda r: httpx.Response(200, text="static content unchanging" * 50)
        monkeypatch.setattr("httpx.AsyncClient.__init__",
                            _make_patched_asyncclient(safe_handler))
        skill = SSRFSkill()
        result = await skill.run("http://app.local/fetch?url=x", "url")
        assert not result.verified

    def test_metadata_probes_need_authorization(self):
        """probes الـ cloud metadata لا تُرسَل إلا عند التخويل الصريح"""
        from agents.skills.ssrf_skill import SSRFFilterBypasser
        from urllib.parse import urlparse
        variants = SSRFFilterBypasser.generate_localhost_variants(target_port=80)
        # الـ localhost variants проходят приемлем (مستوى اختبار), لكننا نتأكد إن metadata probes ليست مضمنة افتراضياً
        assert all("169.254.169.254" not in v for v in variants)


# ════════════════════════════════════════════════════════════════════════════
# 3. Open Redirect
# ════════════════════════════════════════════════════════════════════════════

class TestOpenRedirectSkill:
    def _redirect_app_handler(self, request: httpx.Request):
        from urllib.parse import urlparse, parse_qs
        u = urlparse(str(request.url))
        qs = parse_qs(u.query)
        next_val = qs.get("next", [""])[0]
        if "hunterai-redirect-canary" in next_val:
            return httpx.Response(302, headers={"Location": "https://hunterai-redirect-canary.invalid/session"})
        return httpx.Response(200, text="stay page")

    @pytest.mark.asyncio
    async def test_open_redirect_verified(self, monkeypatch):
        from agents.skills.open_redirect_skill import OpenRedirectSkill
        monkeypatch.setattr("httpx.AsyncClient.__init__",
                            _make_patched_asyncclient(self._redirect_app_handler))
        skill = OpenRedirectSkill()
        r = await skill.run("http://app.local/login?next=/dash", "next")
        assert r.verified, f"evidence={r.evidence!r}"
        assert "hunterai-redirect-canary" in r.evidence

    @pytest.mark.asyncio
    async def test_open_redirect_ignores_safe_app(self, monkeypatch):
        from agents.skills.open_redirect_skill import OpenRedirectSkill
        safe = lambda r: httpx.Response(200, text="static")
        monkeypatch.setattr("httpx.AsyncClient.__init__", _make_patched_asyncclient(safe))
        skill = OpenRedirectSkill()
        r = await skill.run("http://app.local/login?next=/dash", "next")
        assert not r.verified


# ════════════════════════════════════════════════════════════════════════════
# 4. Host Header Injection
# ════════════════════════════════════════════════════════════════════════════

class TestHostHeaderInjectionSkill:
    def _poisonable_app_handler(self, request: httpx.Request):
        xfh = request.headers.get("x-forwarded-host", "") or request.headers.get("x-host", "")
        if "hostheader-canary" in xfh:
            return httpx.Response(200, headers={"Location": f"https://{xfh}/reset"})
        return httpx.Response(200, text="normal page")

    @pytest.mark.asyncio
    async def test_host_header_verified_via_location(self, monkeypatch):
        from agents.skills.host_header_injection_skill import HostHeaderInjectionSkill
        monkeypatch.setattr("httpx.AsyncClient.__init__",
                            _make_patched_asyncclient(self._poisonable_app_handler))
        skill = HostHeaderInjectionSkill()
        r = await skill.run("http://app.local/reset", "host")
        assert r.verified, f"evidence={r.evidence!r}"
        assert r.extra.get("vector") if isinstance(r.extra, dict) and r.extra else True  # معلومة إضافية إن وُجدت


# ════════════════════════════════════════════════════════════════════════════
# 5. NoSQL Injection
# ════════════════════════════════════════════════════════════════════════════

class TestNoSQLInjectionSkill:
    def _mongo_app_handler(self, request: httpx.Request):
        if request.method != "POST":
            return httpx.Response(405, text="post only")
        try:
            body = _json.loads(request.content.decode() or "{}")
        except Exception:
            body = {}
        user_val = body.get("user", None)
        # $ne/$gt/$regex operators → جلسة مصادقة
        if isinstance(user_val, dict):
            return httpx.Response(200, headers={"Set-Cookie": "session=abc123"}, text="welcome to dashboard")
        return httpx.Response(401, text="invalid credentials")

    @pytest.mark.asyncio
    async def test_nosql_auth_bypass_verified(self, monkeypatch):
        from agents.skills.nosql_injection_skill import NoSQLInjectionSkill
        monkeypatch.setattr("httpx.AsyncClient.__init__",
                            _make_patched_asyncclient(self._mongo_app_handler))
        skill = NoSQLInjectionSkill()
        r = await skill.run("http://app.local/login", "user")
        assert r.verified, f"evidence={r.evidence!r}"
        assert "$ne" in r.payload_used

    @pytest.mark.asyncio
    async def test_nosql_safe_app_not_verified(self, monkeypatch):
        from agents.skills.nosql_injection_skill import NoSQLInjectionSkill
        safe = lambda r: httpx.Response(401, text="unauthorized always")
        monkeypatch.setattr("httpx.AsyncClient.__init__", _make_patched_asyncclient(safe))
        skill = NoSQLInjectionSkill()
        r = await skill.run("http://app.local/login", "user")
        assert not r.verified


# ════════════════════════════════════════════════════════════════════════════
# 6. CRLF Injection
# ════════════════════════════════════════════════════════════════════════════

class TestCRLFSkill:
    def _crlf_vuln_app_handler(self, request: httpx.Request):
        from urllib.parse import urlparse, parse_qs, unquote
        u = urlparse(str(request.url))
        qs = parse_qs(u.query)
        lang = qs.get("lang", [""])[0]
        decoded = unquote(lang)
        if "x-hunter-crlf-canary" in decoded.lower():
            # الخادم يفصل الـ CRLF فعلياً ويعكسها كـ header حقيقي
            return httpx.Response(200, headers={"x-hunter-crlf-canary": "hunter-poe-crlf-4210"}, text="page")
        return httpx.Response(200, text="page")

    @pytest.mark.asyncio
    async def test_crlf_header_split_verified(self, monkeypatch):
        from agents.skills.crlf_injection_skill import CRLFSkill
        monkeypatch.setattr("httpx.AsyncClient.__init__",
                            _make_patched_asyncclient(self._crlf_vuln_app_handler))
        skill = CRLFSkill()
        r = await skill.run("http://app.local/page?lang=en", "lang")
        assert r.verified, f"evidence={r.evidence!r}"


# ════════════════════════════════════════════════════════════════════════════
# 7. HTTP Parameter Pollution
# ════════════════════════════════════════════════════════════════════════════

class TestHPPSkill:
    def _hpp_app_handler(self, request: httpx.Request):
        from urllib.parse import urlparse, parse_qs
        u = urlparse(str(request.url))
        qs = parse_qs(u.query)
        prices = qs.get("price", [])
        # الخادم يلغي أول تكرار (first-wins) — الحقن الثانية تُعلن 0 → فشل فعلياً؟
        # في هذه الحالة نعالج: last occurrence يُستخدم — money 0 → 200
        effective = prices[-1] if prices else ""
        if effective == "0":
            return httpx.Response(200, text="checkout forever free: order confirmed")
        if effective == "":
            return httpx.Response(400, text="missing price")
        return httpx.Response(402, text="payment required (baseline)")

    @pytest.mark.asyncio
    async def test_hpp_state_transition_verified(self, monkeypatch):
        from agents.skills.hpp_skill import HTTPParameterPollutionSkill
        monkeypatch.setattr("httpx.AsyncClient.__init__",
                            _make_patched_asyncclient(self._hpp_app_handler))
        skill = HTTPParameterPollutionSkill()
        r = await skill.run("http://app.local/checkout?price=250", "price")
        assert r.verified, f"evidence={r.evidence!r}"
        assert "402" in r.evidence or "transition" in r.title.lower()


# ════════════════════════════════════════════════════════════════════════════
# 8. LDAP Injection
# ════════════════════════════════════════════════════════════════════════════

class TestLDAPInjectionSkill:
    def _ldap_app_handler(self, request: httpx.Request):
        from urllib.parse import urlparse, parse_qs
        u = urlparse(str(request.url))
        qs = parse_qs(u.query)
        uid = qs.get("uid", [""])[0]
        wildcard_hit = ("*" in uid) and (("uid=" in uid) or ("objectclass" in uid.lower()))
        if wildcard_hit:
            return httpx.Response(200, text="dn: cn=user1\nmail: a@x.local\ndn: cn=user2\nmail: b@x.local\ndn: cn=user3\nmail: c@x.local")
        return httpx.Response(200, text="no records matched the query")

    @pytest.mark.asyncio
    async def test_ldap_wildcard_differential_verified(self, monkeypatch):
        from agents.skills.ldap_injection_skill import LDAPInjectionSkill
        monkeypatch.setattr("httpx.AsyncClient.__init__",
                            _make_patched_asyncclient(self._ldap_app_handler))
        skill = LDAPInjectionSkill()
        r = await skill.run("http://app.local/search?uid=nonexistent", "uid")
        assert r.verified, f"evidence={r.evidence!r}"
