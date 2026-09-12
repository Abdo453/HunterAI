"""
Unit Tests for Scope Guarding, Entity Unescaping, and False Positive Elimination
Verifies:
1. _is_in_scope properly filters 3rd party trackers, CDNs, app stores (GTM, Google Play, etc.)
2. _extract_endpoints_and_params unescapes &amp; to avoid corrupted param names like 'ampslide'
3. CmdInjectionSkill strictly requires arithmetic execution proof and rejects parameter reflection
4. IDORSkill skips UI navigation parameters and does not flag unauthenticated public responses
5. SQLiDetector rejects Cloudflare/WAF 403 block pages and challenges
6. SQLiDBMSFingerprinter ignores CSS/HTML 'column' keywords
7. SmartPoCExecutor does not treat input reflection or Cloudflare challenges as vulnerabilities
"""
import pytest
from unittest.mock import AsyncMock, patch
import httpx

from core.brain.autonomous_brain import AutonomousBrain
from agents.skills.cmd_injection_skill import CmdInjectionSkill
from agents.skills.idor_skill import IDORSkill
from agents.skills.sqli_skill import SQLiSkill, SQLiDetector, SQLiDBMSFingerprinter, SQLiContext, _HTTPProbe, DBMSType
from core.smart_probe_engine import SmartPoCExecutor


def _make_resp(text: str, status_code: int = 200, headers: dict = None) -> httpx.Response:
    req = httpx.Request("GET", "http://test")
    return httpx.Response(status_code=status_code, text=text, headers=headers or {}, request=req)


class TestScopeAndEntityUnescaping:

    def test_scope_guard_filters_external_domains(self):
        brain = AutonomousBrain(resource_manager=AsyncMock(), tool_manager=AsyncMock())
        base_url = "https://bancoplata.mx"

        # In-scope
        assert brain._is_in_scope("https://bancoplata.mx/es/security", base_url) is True
        assert brain._is_in_scope("https://sub.bancoplata.mx/api", base_url) is True
        assert brain._is_in_scope("/es/security?slide=1", base_url) is True

        # Out-of-scope (should be blocked)
        assert brain._is_in_scope("https://www.googletagmanager.com/gtm.js?id=GTM-123", base_url) is False
        assert brain._is_in_scope("https://play.google.com/store/apps/details?id=com.test", base_url) is False
        assert brain._is_in_scope("https://google.com/search?q=bank", base_url) is False
        assert brain._is_in_scope("https://facebook.com/bancoplata", base_url) is False
        assert brain._is_in_scope("https://cloudflare.com", base_url) is False

    def test_extract_endpoints_unescapes_amp_and_filters_external(self):
        brain = AutonomousBrain(resource_manager=AsyncMock(), tool_manager=AsyncMock())
        html = """
        <html>
            <a href="/es/security?modal=terms&amp;slide=2">Terms</a>
            <a href="https://play.google.com/store/apps/details?id=dif.tech.plata">Download App</a>
            <a href="https://www.googletagmanager.com/gtm.js?id=GTM-KK58TBH">GTM</a>
            <form action="/login" method="POST">
                <input name="username" value="" />
            </form>
        </html>
        """
        params, endpoints = brain._extract_endpoints_and_params(html, "https://bancoplata.mx")

        # 'slide' must be parsed, NOT corrupted 'ampslide'
        assert "slide" in params
        assert "ampslide" not in params
        assert "modal" in params

        # Endpoints must only contain bancoplata.mx, never Google Play or GTM
        ep_urls = [ep["url"] for ep in endpoints]
        assert any("slide=2" in u for u in ep_urls)
        assert not any("play.google.com" in u for u in ep_urls)
        assert not any("googletagmanager.com" in u for u in ep_urls)


class TestCmdInjectionReflectionVsExecution:

    @pytest.mark.asyncio
    async def test_nextjs_script_reflection_fails_arithmetic_so_not_verified(self):
        cmd = CmdInjectionSkill()
        mock_client = AsyncMock()

        baseline = '<html><script id="__NEXT_DATA__">{"props":{"pageProps":{"modal":"terms"}}}</script></html>'
        reflected = f'<html><script id="__NEXT_DATA__">{{"props":{{"pageProps":{{"modal":"{CmdInjectionSkill.CANARY}"}}}}}}</script></html>'
        arith_reflected = '<html><script id="__NEXT_DATA__">{"props":{"pageProps":{"modal":"$((53+19))"}}}</script></html>'

        mock_client.get.side_effect = [
            _make_resp(baseline),
            _make_resp(reflected),
            _make_resp(arith_reflected),
            _make_resp(reflected),
            _make_resp(arith_reflected),
            _make_resp(reflected),
            _make_resp(arith_reflected),
            _make_resp(reflected),
            _make_resp(arith_reflected),
            _make_resp(reflected),
            _make_resp(arith_reflected),
            _make_resp(reflected),
            _make_resp(arith_reflected),
            _make_resp(reflected),
            _make_resp(arith_reflected),
            _make_resp(reflected),
            _make_resp(arith_reflected),
        ]

        with patch("httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__.return_value = mock_client
            res = await cmd.run("https://bancoplata.mx/es/security?modal=terms", "modal")
            assert res.verified is False
            assert res.severity == "Info"
            assert "CONFIRMED" not in res.title


class TestIDORNavigationFilter:

    @pytest.mark.asyncio
    async def test_idor_skips_slide_navigation_parameter(self):
        skill = IDORSkill()
        res = await skill.run("https://bancoplata.mx/es/security?modal=terms&slide=2", "slide")
        assert res["verified"] is False
        assert res["state"] == "FAILED"

    @pytest.mark.asyncio
    async def test_idor_skips_ampslide_parameter(self):
        skill = IDORSkill()
        res = await skill.run("https://bancoplata.mx/es/security?modal=terms&ampslide=2", "ampslide")
        assert res["verified"] is False
        assert res["state"] == "FAILED"

    @pytest.mark.asyncio
    async def test_idor_does_not_flag_unauthenticated_public_pages(self):
        skill = IDORSkill()
        mock_client = AsyncMock()
        mock_client.get.side_effect = [
            _make_resp("<html><body>Public Article 1 with 100 bytes of content here</body></html>"),
            _make_resp("<html><body>Public Article 2 with 250 bytes of different text here</body></html>"),
        ]
        with patch("httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__.return_value = mock_client
            res = await skill.run("https://example.com/article?id=1", "id", auth_headers_a=None)
            assert res["verified"] is False
            assert res["state"] == "FAILED"


class TestSQLiWAFAndFingerprintFilters:

    @pytest.mark.asyncio
    async def test_sqli_detector_ignores_cloudflare_403(self):
        detector = SQLiDetector()
        ctx = SQLiContext(target_url="https://bancoplata.mx?id=1", param_name="id")
        http = _HTTPProbe()

        async def mock_get(url, params):
            val = params.get("id", "")
            if "OR 1=1" in val:
                return _make_resp("<html><title>Attention Required! | Cloudflare</title></html>", status_code=403)
            return _make_resp("<html>Normal Page</html>", status_code=200)

        http.get = mock_get
        is_sqli = await detector.detect(ctx, http)
        assert is_sqli is False

    @pytest.mark.asyncio
    async def test_fingerprinter_does_not_flag_postgres_on_word_column(self):
        fingerpr = SQLiDBMSFingerprinter()
        ctx = SQLiContext(target_url="https://bancoplata.mx?id=1", param_name="id")
        http = _HTTPProbe()

        async def mock_get(url, params):
            return _make_resp('<div class="column flex-col">Layout Column</div>', status_code=200)

        http.get = mock_get
        dbms = await fingerpr.fingerprint(ctx, http)
        assert dbms != DBMSType.POSTGRES
        assert dbms == DBMSType.UNKNOWN


class TestSmartPoCExecutorFalsePositiveFilter:

    @pytest.mark.asyncio
    async def test_smart_poc_does_not_flag_cloudflare_challenge(self):
        poc = SmartPoCExecutor()
        decision = await poc.ai_reason_and_classify(
            html_source="<html><title>Just a moment...</title><body>Checking your browser</body></html>",
            param_name="modal",
            test_value="probe_test_val",
            status_code=403
        )
        assert decision["vulnerable"] is False

    @pytest.mark.asyncio
    async def test_smart_poc_does_not_flag_simple_text_reflection(self):
        poc = SmartPoCExecutor()
        decision = await poc.ai_reason_and_classify(
            html_source="<html><body>Search query: probe_test_val</body></html>",
            param_name="search",
            test_value="probe_test_val",
            status_code=200
        )
        assert decision["vulnerable"] is False
