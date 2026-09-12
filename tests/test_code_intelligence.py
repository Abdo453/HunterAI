"""
Unit Tests for HunterAI Code Intelligence Pipeline
==================================================
Tests:
1. PageCollector asset harvesting (HTML, inline scripts, Next.js __NEXT_DATA__, forms)
2. JSInventory SHA-256 deduplication
3. SmartCodeChunker structural decomposition
4. EndpointHunter network route discovery (fetch, axios, xhr)
5. SecretHunter multi-stage entropy and placeholder validation
6. SourceSinkAnalyzer client-side data flow verification
7. FrameworkAnalyzer Next.js deep inspection
8. CodeIntelligenceAgent end-to-end pipeline execution
"""
import pytest
from core.code_intel import (
    PageCollector, JSInventory, SmartCodeChunker, EndpointHunter,
    SecretHunter, SourceSinkAnalyzer, FrameworkAnalyzer, CodeIntelligenceAgent
)


class TestCodeIntelligencePipeline:

    def test_page_collector_extracts_assets_and_next_data(self):
        sample_html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Plata Bank</title>
            <script src="/_next/static/chunks/main.js"></script>
            <script id="__NEXT_DATA__" type="application/json">
                {"props":{"pageProps":{"version":"2.4.1","modal":"terms"}},"page":"/security","buildId":"test_build_881"}
            </script>
        </head>
        <body>
            <script>
                var clientToken = "inline_token_xyz";
                function initPage() { console.log("ready"); }
            </script>
            <form action="/api/v1/login" method="POST">
                <input name="username" type="text" />
                <input name="password" type="password" />
            </form>
            <a href="/es/security?modal=terms&amp;slide=2">Terms</a>
        </body>
        </html>
        """
        bundle = PageCollector.collect_from_html(
            target_url="https://bancoplata.mx",
            raw_html=sample_html
        )

        assert len(bundle.external_js_urls) == 1
        assert "main.js" in bundle.external_js_urls[0]
        assert len(bundle.inline_scripts) == 1
        assert "clientToken" in bundle.inline_scripts[0]
        assert bundle.next_data is not None
        assert bundle.next_data["buildId"] == "test_build_881"
        assert len(bundle.forms) == 1
        assert bundle.forms[0]["method"] == "POST"
        assert len(bundle.forms[0]["inputs"]) == 2

    def test_js_inventory_deduplication(self):
        inv = JSInventory()
        script_a = "function trackEvent() { return 42; }"
        script_b = "function trackEvent() { return 42; }"  # exact duplicate
        script_c = "function uniqueFunc() { return 99; }"

        item_1, is_dup_1 = inv.register("https://target.com/a.js", script_a)
        assert is_dup_1 is False
        assert inv.total_unique_bundles == 1

        item_2, is_dup_2 = inv.register("https://target.com/b.js", script_b)
        assert is_dup_2 is True
        assert item_2.sha256 == item_1.sha256
        assert inv.total_unique_bundles == 1

        item_3, is_dup_3 = inv.register("https://target.com/c.js", script_c)
        assert is_dup_3 is False
        assert inv.total_unique_bundles == 2

    def test_smart_code_chunker_extracts_functions(self):
        code = """
        function calculateTotal(price, tax) {
            return price + (price * tax);
        }

        const fetchUserProfile = async (userId) => {
            return await fetch('/api/user/' + userId);
        };
        """
        chunks = SmartCodeChunker.chunk_javascript(code, file_path="app.js")
        assert len(chunks) >= 2
        chunk_names = [c.name for c in chunks]
        assert "calculateTotal" in chunk_names
        assert "fetchUserProfile" in chunk_names

    def test_endpoint_hunter_finds_routes(self):
        code = """
        function sync() {
            fetch('/api/v2/transactions?limit=10', { method: 'GET' });
            axios.post('/api/v1/transfer', { amount: 100 });
            var xhr = new XMLHttpRequest();
            xhr.open('POST', '/api/auth/refresh');
            var ws = new WebSocket('wss://realtime.target.com/feed');
        }
        """
        endpoints = EndpointHunter.hunt_endpoints(code, source_file="bundle.js")
        paths = [ep.url_or_path for ep in endpoints]
        assert any("/api/v2/transactions" in p for p in paths)
        assert any("/api/v1/transfer" in p for p in paths)
        assert any("/api/auth/refresh" in p for p in paths)
        assert any("realtime.target.com" in p for p in paths)

        tx_ep = next(ep for ep in endpoints if "/api/v2/transactions" in ep.url_or_path)
        assert "limit" in tx_ep.parameters

    def test_secret_hunter_rejects_placeholders_and_validates_real_tokens(self):
        code = """
        const dummyKey = "YOUR_API_KEY_HERE";
        const placeholder = "CHANGEME";
        const realAwsKey = "AKIAI44QH8DHB7XYZ912";
        const highEntropySecret = "api_key = '9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c'";
        """
        secrets = SecretHunter.hunt_secrets(code, source_file="config.js")

        for s in secrets:
            if "YOUR_API_KEY" in s.raw_match or "CHANGEME" in s.raw_match:
                assert s.status.value == "REJECTED"

        aws_cands = [s for s in secrets if "AKIA" in s.raw_match]
        assert len(aws_cands) >= 1
        assert aws_cands[0].status.value == "VALIDATED"

    def test_source_sink_analyzer_distinguishes_sanitized_vs_tainted(self):
        code = """
        // Tainted flow
        var rawParam = location.search;
        document.getElementById('msg').innerHTML = rawParam;

        // Static safe assignment
        document.getElementById('title').innerHTML = "Welcome Back";
        """
        flows = SourceSinkAnalyzer.analyze_flows(code, source_file="view.js")
        assert len(flows) >= 1
        exploitable_flows = [f for f in flows if f.is_exploitable]
        assert len(exploitable_flows) >= 1
        assert exploitable_flows[0].source == "location.search"
        assert exploitable_flows[0].sink == "innerHTML"

    def test_framework_analyzer_nextjs(self):
        next_data = {
            "buildId": "bld_7331_prod",
            "page": "/checkout",
            "props": {
                "pageProps": {
                    "stripe_public_key": "pk_live_test123",
                    "secret_admin_token": "secret_token_val"
                }
            },
            "query": {"id": "101", "step": "confirm"}
        }
        res = FrameworkAnalyzer.analyze_nextjs(next_data, "<html></html>", "https://target.com")
        assert res["detected"] is True
        assert res["build_id"] == "bld_7331_prod"
        assert "id" in res["dynamic_routes"]
        assert any("token" in e.get("key", "").lower() for e in res["exposed_env"])

    @pytest.mark.asyncio
    async def test_code_intelligence_agent_end_to_end(self):
        agent = CodeIntelligenceAgent()
        html = """
        <html>
            <script id="__NEXT_DATA__" type="application/json">
                {"buildId":"bld_99","page":"/app"}
            </script>
            <script>
                function fetchAccount() {
                    fetch('/api/user/account?id=42');
                }
            </script>
        </html>
        """
        res = await agent.analyze_page("https://target.com", html)
        assert res["manifest"]["endpoints_discovered"] >= 1
        assert res["manifest"]["js_analyzed"] >= 1
        assert res["code_map"]["target"] == "https://target.com"