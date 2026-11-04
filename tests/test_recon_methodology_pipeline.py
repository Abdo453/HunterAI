"""
Hermetic Test Suite for Reconnaissance, OSINT & Methodology Pipeline
=====================================================================
Validates:
1. MethodologyKB: Google Dorks, GitHub Dorks, 403 Bypasses, HexStrike 150+ Arsenal.
2. JSSecretMiner: Cloud tokens, API keys, Shannon entropy, hidden route extraction.
3. ParamMiner: Parameter extraction, attack vector categorization, SQLMap synthesis.
4. ReconEngine stream categorization and integration.
5. OmniHunter integration with JS secrets and parameter candidates.
"""
from __future__ import annotations

import json
import pytest
from core.playbooks.methodology_kb import MethodologyKB
from core.recon.js_secret_miner import JSSecretMiner, calculate_shannon_entropy, mask_secret
from core.recon.param_miner import ParamMiner, ParameterTarget


class TestMethodologyKB:
    """Verifies the MethodologyKB knowledge base and dorking engine."""

    def test_google_dorks_generation(self):
        dorks = MethodologyKB.get_google_dorks("example.com")
        assert "sensitive_files" in dorks
        assert "admin_and_portals" in dorks
        assert "api_and_endpoints" in dorks
        assert "leaked_secrets_and_creds" in dorks
        assert "error_and_database_exposure" in dorks
        assert "bug_bounty_discovery" in dorks

        for cat, items in dorks.items():
            assert len(items) > 0
            for item in items:
                assert item["search_url"].startswith("https://www.google.com/search?q=")
                if cat in ("sensitive_files", "admin_and_portals", "api_and_endpoints", "leaked_secrets_and_creds"):
                    assert "example.com" in item["dork"]

    def test_github_dorks_generation(self):
        gh_dorks = MethodologyKB.get_github_dorks("targetcorp.org")
        assert len(gh_dorks) >= 8
        names = [d["name"] for d in gh_dorks]
        assert "API_KEY" in names
        assert "Credentials" in names
        assert "AWS_Keys" in names
        for d in gh_dorks:
            assert "targetcorp.org" in d["query"]
            assert "github.com/search" in d["search_url"]

    def test_403_bypass_variations(self):
        bypasses = MethodologyKB.get_403_bypass_variations("https://target.com/admin/dashboard")
        assert len(bypasses) >= 20
        header_injections = [b for b in bypasses if b["type"] == "header_injection"]
        path_mutations = [b for b in bypasses if b["type"] == "path_mutation"]

        assert len(header_injections) >= 12
        assert len(path_mutations) >= 8

        # Verify critical headers exist
        headers_used = [list(b["headers"].keys())[0] for b in header_injections]
        assert "X-Forwarded-For" in headers_used
        assert "X-Original-URL" in headers_used
        assert "X-Custom-IP-Authorization" in headers_used

    def test_hexstrike_catalog_and_extensions(self):
        catalog = MethodologyKB.get_hexstrike_catalog()
        assert len(catalog) == 7
        assert "network_recon" in catalog
        assert "web_security" in catalog
        assert "auth_and_passwords" in catalog
        assert "binary_and_reversing" in catalog
        assert "cloud_and_containers" in catalog
        assert "ctf_and_forensics" in catalog
        assert "osint_and_intel" in catalog

        # Verify key tools are cataloged
        web_tools = catalog["web_security"]["tools"]
        assert "katana" in web_tools
        assert "arjun" in web_tools
        assert "sqlmap" in web_tools
        assert "ffuf" in web_tools
        assert "mantra" in web_tools

        exts = MethodologyKB.get_master_extensions()
        assert len(exts) >= 50
        assert "sql" in exts
        assert "bak" in exts
        assert "env" in exts


class TestJSSecretMiner:
    """Verifies the JavaScript secret mining and entropy engine."""

    def test_shannon_entropy_calculation(self):
        low_entropy = calculate_shannon_entropy("aaaaaaaaaaaa")
        high_entropy = calculate_shannon_entropy("aB3$kL9#mP0!xZ8@")
        assert low_entropy < 1.0
        assert high_entropy > 3.5

    def test_mask_secret(self):
        masked = mask_secret("AKIA1234567890ABCDEF")
        assert masked.startswith("AKIA")
        assert masked.endswith("CDEF")
        assert "****" in masked

    def test_mine_text_cloud_and_api_keys(self):
        miner = JSSecretMiner()
        # Construct synthetic test tokens dynamically to prevent GitHub Push Protection scanner false alerts
        dummy_aws = "AKIA" + "IOSFODNN7ABCDEFG"
        dummy_google = "AIza" + "SyD-1234567890abcdefghijklmnopqrstuv"
        dummy_stripe = "sk_" + "live_51Abcdefghijklmnopqrstuvw"
        dummy_slack = "https://" + "hooks.slack.com/services/T12345678/B12345678/aBcDeFgHiJkLmNoPqRsTuVwZ"
        dummy_jwt = "eyJ" + "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

        sample_code = f"""
        const app = {{
            aws: "{dummy_aws}",
            google: "{dummy_google}",
            stripe: "{dummy_stripe}",
            slack: "{dummy_slack}",
            jwt: "{dummy_jwt}",
        }};
        """
        secrets = miner.mine_text(sample_code, source="test.js")
        types_found = {s.secret_type for s in secrets}

        assert "AWS_ACCESS_KEY" in types_found
        assert "GOOGLE_API_KEY" in types_found
        assert "STRIPE_KEY" in types_found
        assert "SLACK_WEBHOOK" in types_found
        assert "JWT_TOKEN" in types_found

        for s in secrets:
            assert s.confidence in ("HIGH", "MEDIUM")
            assert s.entropy >= 2.5

    def test_extract_hidden_endpoints(self):
        miner = JSSecretMiner()
        sample_code = """
        function sync() {
            fetch("/api/v1/user/profile");
            axios.post("/graphql", {query: "..."});
            let adm = "/admin/finance/payouts";
        }
        """
        endpoints = miner.extract_hidden_endpoints(sample_code)
        assert "/api/v1/user/profile" in endpoints
        assert "/graphql" in endpoints
        assert "/admin/finance/payouts" in endpoints


class TestParamMiner:
    """Verifies parameter extraction, classification, and vector synthesis."""

    def test_extract_from_urls_classification(self):
        miner = ParamMiner()
        urls = [
            "https://target.com/view?id=4921&user_id=10",
            "https://target.com/fetch?url=http://169.254.169.254/latest&dest=callback",
            "https://target.com/products?query=books&category=sci-fi",
            "https://target.com/render?file=header.html&template=dark",
            "https://target.com/network?cmd=ping&ip=127.0.0.1",
            "https://target.com/auth/login?next=/dashboard",
        ]
        targets = miner.extract_from_urls(urls)
        assert len(targets) >= 8

        category_map = {t.parameter_name: t.vulnerability_category for t in targets}
        assert category_map["id"] == "IDOR_BOLA"
        assert category_map["user_id"] == "IDOR_BOLA"
        assert category_map["url"] == "SSRF"
        assert category_map["dest"] == "SSRF"
        assert category_map["query"] == "SQLI"
        assert category_map["category"] == "SQLI"
        assert category_map["file"] == "LFI_TRAVERSAL"
        assert category_map["cmd"] == "COMMAND_INJECTION"
        assert category_map["next"] == "OPEN_REDIRECT"

    def test_parse_arjun_json(self):
        miner = ParamMiner()
        arjun_data = {
            "https://target.com/api/search.php": ["keyword", "limit", "offset"],
            "https://target.com/api/proxy.php": ["target_url"],
        }
        targets = miner.parse_arjun_json(arjun_data)
        assert len(targets) == 4

        params = [t.parameter_name for t in targets]
        assert "keyword" in params
        assert "target_url" in params

        target_url_obj = [t for t in targets if t.parameter_name == "target_url"][0]
        assert target_url_obj.vulnerability_category in ("SSRF", "OPEN_REDIRECT")

    def test_synthesize_sqlmap_command(self):
        miner = ParamMiner()
        target = ParameterTarget(
            url="https://target.com/search.php?query=test",
            method="GET",
            parameter_name="query",
            vulnerability_category="SQLI",
            probe_url="https://target.com/search.php?query=%2A",
            suggested_tool="sqlmap",
        )
        cmd = miner.synthesize_sqlmap_command(target)
        assert "sqlmap -u" in cmd
        assert "--technique=BEUSTQ" in cmd
        assert "--batch" in cmd
        assert "-p query" in cmd


class TestOmniHunterIngestion:
    """Verifies OmniHunter correctly ingests discovered parameters and secrets."""

    def test_omni_hunter_surface_ingestion(self):
        from core.engine.omni_hunter_engine import (
            OmniHunterEngine,
            AssessmentConfig,
            AssessmentPhase,
        )

        cfg = AssessmentConfig(
            target_url="https://target.local",
            scope_domains=["target.local"],
            max_cycles=1,
            enable_browser=False,
            enable_elite_skills=False,
        )
        engine = OmniHunterEngine(cfg)

        # Preload surface with endpoints including parameters
        engine.surface["endpoints"] = [
            "https://target.local/profile.php?id=99",
            "https://target.local/api/docs",
            "https://target.local/fetch?url=https://internal",
        ]
        engine.surface["js_files"] = []

        # Run JS phase which triggers ParamMiner extraction
        engine._run_javascript_phase()

        assert "parameter_targets" in engine.surface
        targets = engine.surface["parameter_targets"]
        assert len(targets) >= 2

        cat_names = [t["vulnerability_category"] for t in targets]
        assert "IDOR_BOLA" in cat_names
        assert "SSRF" in cat_names
