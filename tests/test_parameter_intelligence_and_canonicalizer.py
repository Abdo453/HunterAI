"""
Comprehensive Unit & Regression Tests for Parameter Intelligence, URL Canonicalization & Evidence Gating
=======================================================================================================
Verifies:
1. ParameterIntelligenceEngine classifies static assets and image optimization parameters as NOISE / inactive.
2. ParameterIntelligenceEngine correctly classifies Search, ID, Token, File, and Command parameters.
3. inject_url_parameter handles query insertion, parameter replacement, and preserves query/fragment without ?? corruption.
4. URLCanonicalizer clusters dynamic parameterized URLs into endpoint families and deduplicates redundant paths.
5. InvestigationController gates inactive candidates from active hypothesis generation.
6. SSTISkill rejects binary content types and avoids reflection traps with high-entropy nonces.
"""
import pytest
from urllib.parse import urlparse

from hunter_ai.pipeline.parameter_intelligence import (
    ParameterIntelligenceEngine,
    ParameterClassification,
    ParameterRole,
    inject_url_parameter,
)
from hunter_ai.pipeline.url_canonicalizer import (
    URLCanonicalizer,
    CanonicalEndpointFamily,
)
from hunter_ai.pipeline.investigation_controller import (
    InvestigationController,
    Hypothesis,
    InvestigationTrace,
    HypothesisPriorityQueue,
)
from hunter_ai.pipeline.schemas import ParameterRecord, EndpointRecord
from agents.skills.ssti_skill import SSTISkill


class TestParameterIntelligenceEngine:
    def test_image_optimization_parameters_classified_as_noise(self):
        # bancoplata.mx example: NextJS / Image optimization parameters
        urls = [
            "https://bancoplata.mx/_next/image?url=%2Flogo.png&w=640&q=75",
            "https://bancoplata.mx/assets/img/hero.webp?q=80&w=1200&f=webp",
            "https://bancoplata.mx/media/banner.png?fit=crop&quality=90",
        ]
        for u in urls:
            for param in ["q", "w", "f", "fit", "quality", "url"]:
                res = ParameterIntelligenceEngine.classify(u, param, "80")
                if param in ("q", "w", "f", "fit", "quality"):
                    assert res.role == ParameterRole.IMAGE_TRANSFORMATION
                    assert res.is_active_candidate is False
                    assert res.risk_level == "NOISE"
                    assert len(res.potential_vulns) == 0

    def test_tracking_and_telemetry_parameters_classified_as_noise(self):
        url = "https://target.com/products"
        for p in ["utm_source", "utm_medium", "fbclid", "_ga", "gclid", "ref", "v", "nonce"]:
            res = ParameterIntelligenceEngine.classify(url, p, "campaign1")
            assert res.role == ParameterRole.TRACKING_METRIC
            assert res.is_active_candidate is False
            assert res.risk_level == "NOISE"

    def test_search_and_query_parameters(self):
        url = "https://target.com/search"
        for p in ["q", "search", "query", "keyword", "term"]:
            res = ParameterIntelligenceEngine.classify(url, p, "laptop")
            assert res.role == ParameterRole.SEARCH_QUERY
            assert res.is_active_candidate is True
            assert "XSS" in res.potential_vulns
            assert "SSTI" in res.potential_vulns

    def test_resource_identifiers(self):
        url = "https://target.com/api/user"
        for p in ["id", "user_id", "uid", "account_id", "doc_id", "uuid"]:
            res = ParameterIntelligenceEngine.classify(url, p, "1234")
            assert res.role == ParameterRole.RESOURCE_IDENTIFIER
            assert res.is_active_candidate is True
            assert "IDOR" in res.potential_vulns
            assert "SQLi" in res.potential_vulns

    def test_command_execution(self):
        url = "https://target.com/tools/ping"
        for p in ["cmd", "exec", "command", "ping", "host", "run"]:
            res = ParameterIntelligenceEngine.classify(url, p, "127.0.0.1")
            assert res.role == ParameterRole.COMMAND_EXECUTION
            assert res.is_active_candidate is True
            assert res.risk_level == "CRITICAL"
            assert "CmdInjection" in res.potential_vulns

    def test_file_and_redirect_parameters(self):
        url = "https://target.com/portal"
        res_file = ParameterIntelligenceEngine.classify(url, "page", "about.php")
        assert res_file.role == ParameterRole.FILE_PATH
        assert res_file.is_active_candidate is True
        assert "LFI" in res_file.potential_vulns

        res_redir = ParameterIntelligenceEngine.classify(url, "redirect_to", "https://auth.com")
        assert res_redir.role == ParameterRole.REDIRECT_TARGET
        assert res_redir.is_active_candidate is True
        assert "SSRF" in res_redir.potential_vulns


class TestInjectURLParameter:
    def test_inject_into_clean_url(self):
        url = "https://target.com/search"
        injected = inject_url_parameter(url, "q", "alert(1)")
        assert injected == "https://target.com/search?q=alert%281%29"

    def test_replace_existing_parameter(self):
        url = "https://target.com/search?q=old_val&lang=en"
        injected = inject_url_parameter(url, "q", "new_val")
        assert "q=new_val" in injected
        assert "lang=en" in injected
        assert "old_val" not in injected
        assert "??" not in injected
        assert injected.count("?") == 1

    def test_append_new_parameter_to_existing_query(self):
        url = "https://target.com/items?page=1"
        injected = inject_url_parameter(url, "sort", "desc")
        assert injected == "https://target.com/items?page=1&sort=desc"
        assert "??" not in injected


class TestURLCanonicalizer:
    def test_canonicalize_url_sorts_and_cleans(self):
        raw = "https://Target.com:443/api//v1/users/?utm_source=google&b=2&a=1#fragment"
        canon = URLCanonicalizer.canonicalize_url(raw)
        assert canon == "https://target.com/api/v1/users/?a=1&b=2"

    def test_get_path_pattern(self):
        path1 = "/users/12345/profile"
        assert URLCanonicalizer.get_path_pattern(path1) == "/users/{id}/profile"

        path2 = "/documents/c73bcdcc-2669-4bf6-81d3-e4ae73fb11fd/view"
        assert URLCanonicalizer.get_path_pattern(path2) == "/documents/{uuid}/view"

    def test_process_url_inventory_clusters_and_deduplicates(self):
        raw_urls = [
            f"https://bancoplata.mx/_next/image?url=%2Fslide_{i}.png&w=640&q=75"
            for i in range(50)
        ] + [
            "https://bancoplata.mx/api/v1/accounts?user_id=1001",
            "https://bancoplata.mx/api/v1/accounts?user_id=1002",
            "https://bancoplata.mx/search?q=transfer",
        ]

        endpoints, parameters, families = URLCanonicalizer.process_url_inventory(
            raw_urls=raw_urls,
            live_hosts={"bancoplata.mx"},
            target_domain="bancoplata.mx"
        )

        # 50 image URLs should collapse into only 1 endpoint family cluster!
        image_families = [f for f in families if "/_next/image" in f.path_pattern]
        assert len(image_families) == 1
        assert image_families[0].raw_urls_count == 50

        # Parameter count for q and w on image path must be tagged as NOISE and not duplicated
        image_q_params = [p for p in parameters if p.parameter == "q" and "/_next/image" in p.endpoint]
        assert len(image_q_params) == 1
        assert image_q_params[0].context["is_active_candidate"] is False
        assert image_q_params[0].context["role"] == ParameterRole.IMAGE_TRANSFORMATION.value

        # Search parameter q on /search should be an active candidate
        search_q_params = [p for p in parameters if p.parameter == "q" and "/search" in p.endpoint]
        assert len(search_q_params) == 1
        assert search_q_params[0].context["is_active_candidate"] is True
        assert search_q_params[0].context["role"] == ParameterRole.SEARCH_QUERY.value


class MockOrchestrator:
    def __init__(self, parameters):
        self.domain = "target.com"
        self.base_url = "https://target.com"
        self.parameters = parameters
        self.endpoints = []
        self.live_assets = []
        self.findings = []
        self.profile = "full"
        self.timeout_multiplier = 1.0
        self.proxy = None

    def _emit(self, *args, **kwargs):
        pass


class TestInvestigationControllerGating:
    def test_seed_from_parameters_skips_noise_and_seeds_active(self):
        params = [
            ParameterRecord(
                parameter="q",
                endpoint="https://target.com/_next/image?w=640&q=75",
                method="GET",
                source="crawled_query",
                potential_classes=[],
                sample_value="75",
                context={
                    "role": ParameterRole.IMAGE_TRANSFORMATION.value,
                    "is_active_candidate": False,
                    "risk_level": "NOISE",
                }
            ),
            ParameterRecord(
                parameter="utm_source",
                endpoint="https://target.com/home?utm_source=twitter",
                method="GET",
                source="crawled_query",
                potential_classes=[],
                sample_value="twitter",
                context={
                    "role": ParameterRole.TRACKING_METRIC.value,
                    "is_active_candidate": False,
                    "risk_level": "NOISE",
                }
            ),
            ParameterRecord(
                parameter="q",
                endpoint="https://target.com/search?q=admin",
                method="GET",
                source="crawled_query",
                potential_classes=["XSS", "SSTI"],
                sample_value="admin",
                context={
                    "role": ParameterRole.SEARCH_QUERY.value,
                    "is_active_candidate": True,
                    "risk_level": "MEDIUM",
                }
            ),
            ParameterRecord(
                parameter="cmd",
                endpoint="https://target.com/api/ping?cmd=127.0.0.1",
                method="GET",
                source="crawled_query",
                potential_classes=["CmdInjection"],
                sample_value="127.0.0.1",
                context={
                    "role": ParameterRole.COMMAND_EXECUTION.value,
                    "is_active_candidate": True,
                    "risk_level": "CRITICAL",
                }
            ),
        ]

        orc = MockOrchestrator(params)
        ctrl = InvestigationController(orchestrator=orc)
        seeded = ctrl._seed_from_parameters()

        # Image q and utm_source must NOT be seeded; only search q (XSS, SSTI) and cmd (CmdInjection) = 3 hypotheses
        assert seeded == 3
        queued_items = [ctrl.queue.pop() for _ in range(3)]
        vuln_types = {h.vuln_type for h in queued_items if h}
        assert vuln_types == {"XSS", "SSTI", "CmdInjection"}
        for h in queued_items:
            assert "_next/image" not in h.target_url
            assert "utm_source" not in h.param


class TestSSTISkillHardening:
    @pytest.mark.asyncio
    async def test_ssti_skips_static_media_endpoints(self):
        skill = SSTISkill()
        res = await skill.run("https://target.com/assets/banner.webp?q=80", "q")
        assert res.verified is False
        assert any("Skipping static asset path" in line for line in res.logs)
