"""
HunterAI V5.0 Cognitive Security Platform Test Suite
===================================================
Comprehensive tests for:
- RootCauseEngine (parameter & controller clustering)
- DeepJSAnalyzer (endpoints, feature flags, microservices, GraphQL, env keys)
- WAFBackoffEngine (WAF detection, rate limiting, human operator intervention)
- SafeLabOrchestrator (presets, docker compose, in-memory benchmark)
- AssetConsentManager (5 independent scope categories, human approval gating)
- AdaptiveRiskSelector (semantic check prioritization for auth, graphql, data)
"""
import pytest
from pathlib import Path
import tempfile

from core.analysis.root_cause_engine import RootCauseEngine, RootCauseCluster, ClusterPatternType
from core.recon.deep_js_analyzer import DeepJSAnalyzer, JSIntelligenceReport
from core.resilience.waf_backoff import WAFBackoffEngine, WAFProvider, InterventionStatus
from core.lab.safe_lab_orchestrator import SafeLabOrchestrator, LabTargetType
from core.recon.asset_consent import AssetConsentManager, AssetCategory, ConsentStatus
from core.profiles.adaptive_risk_selector import AdaptiveRiskSelector, TestCheckClass


class TestRootCauseEngine:
    def test_shared_parameter_clustering(self):
        findings = [
            {"finding_id": "F-01", "vulnerability_type": "SQL_INJECTION", "cwe_id": "CWE-89", "parameter": "user_id", "endpoint": "/api/v1/users/view"},
            {"finding_id": "F-02", "vulnerability_type": "SQL_INJECTION", "cwe_id": "CWE-89", "parameter": "user_id", "endpoint": "/api/v1/users/download"},
            {"finding_id": "F-03", "vulnerability_type": "SQL_INJECTION", "cwe_id": "CWE-89", "parameter": "user_id", "endpoint": "/api/v1/users/export"},
        ]
        clusters = RootCauseEngine.analyze_findings(findings)
        assert len(clusters) == 1
        c = clusters[0]
        assert c.pattern_type == ClusterPatternType.SHARED_PARAMETER_SINK
        assert "user_id" in c.shared_attribute
        assert len(c.affected_findings) == 3
        assert len(c.affected_endpoints) == 3
        assert c.confidence_score >= 0.9

    def test_shared_controller_prefix_clustering(self):
        findings = [
            {"finding_id": "F-10", "vulnerability_type": "BOLA_IDOR", "cwe_id": "CWE-639", "parameter": "p1", "endpoint": "/api/v1/orders/1"},
            {"finding_id": "F-11", "vulnerability_type": "BOLA_IDOR", "cwe_id": "CWE-639", "parameter": "p2", "endpoint": "/api/v1/orders/items/2"},
        ]
        clusters = RootCauseEngine.analyze_findings(findings)
        assert len(clusters) == 1
        c = clusters[0]
        assert c.pattern_type == ClusterPatternType.SHARED_CONTROLLER_PREFIX
        assert "/orders/" in c.shared_attribute

    def test_isolated_finding_handling(self):
        findings = [
            {"finding_id": "F-20", "vulnerability_type": "XSS", "cwe_id": "CWE-79", "parameter": "search", "endpoint": "/search"}
        ]
        clusters = RootCauseEngine.analyze_findings(findings)
        assert len(clusters) == 1
        assert clusters[0].pattern_type == ClusterPatternType.ISOLATED_ANOMALY

    def test_report_formatting(self):
        findings = [
            {"finding_id": "F-30", "vulnerability_type": "SQL_INJECTION", "cwe_id": "CWE-89", "parameter": "id", "endpoint": "/api/v1/products"},
            {"finding_id": "F-31", "vulnerability_type": "SQL_INJECTION", "cwe_id": "CWE-89", "parameter": "id", "endpoint": "/api/v1/catalog"},
        ]
        clusters = RootCauseEngine.analyze_findings(findings)
        report = RootCauseEngine.format_developer_report(clusters)
        assert "Developer Root-Cause Report" in report
        assert "Unified Remediation" in report


class TestDeepJSAnalyzer:
    def test_js_intel_extraction(self):
        sample_code = """
        // Internal route definition
        fetch('/api/v1/admin/users', { method: 'GET' });
        axios.post('/api/v2/payments/charge', { amount: 100 });
        
        // Feature flag toggle
        if (isFeatureEnabled('beta_checkout')) {
            console.log('beta on');
        }
        const FLAG_NEW_PERMISSIONS = true;
        
        // Microservice name
        const targetService = 'auth-backend-worker';
        
        // GraphQL Query
        const query = `
            query FetchAccounts($limit: Int) {
                accounts(limit: $limit) {
                    id
                    balance
                }
            }
        `;
        
        // Leaked env
        const REACT_APP_API_ENDPOINT = 'https://internal.target.local';
        """
        report = DeepJSAnalyzer.analyze_script(sample_code, source_file="main.chunk.js")
        
        assert "/api/v1/admin/users" in report.endpoints
        assert "/api/v2/payments/charge" in report.endpoints
        assert any("beta_checkout" in f for f in report.feature_flags)
        assert "auth-backend-worker" in report.service_names
        assert "FetchAccounts" in report.graphql_operations
        assert "REACT_APP_API_ENDPOINT" in report.env_keys


class TestWAFBackoffEngine:
    def test_cloudflare_header_detection(self):
        waf = WAFBackoffEngine()
        headers = {"server": "cloudflare", "cf-ray": "829381920392"}
        req = waf.inspect_response(403, headers, "Access Denied", "/api/v1/data", "target.local")
        
        assert req is not None
        assert req.detected_waf == WAFProvider.CLOUDFLARE
        assert waf.is_endpoint_blocked("target.local", "/api/v1/data") is True

    def test_http_429_rate_limit(self):
        waf = WAFBackoffEngine()
        req = waf.inspect_response(429, {}, "Too Many Requests", "/api/login", "target.local")
        assert req is not None
        assert req.detected_waf == WAFProvider.GENERIC_RATE_LIMIT

    def test_operator_resolution(self):
        waf = WAFBackoffEngine()
        req = waf.inspect_response(429, {}, "", "/api/login", "target.local")
        assert len(waf.intervention_queue) == 1
        
        resolved = waf.resolve_intervention(req.request_id, InterventionStatus.APPLY_RATE_LIMIT, "Throttled to 1 req/sec")
        assert resolved is True
        assert waf.intervention_queue[0].status == InterventionStatus.APPLY_RATE_LIMIT


class TestSafeLabOrchestrator:
    def test_presets_exist(self):
        assert LabTargetType.BUILTIN_ARENA in SafeLabOrchestrator.PRESETS
        assert LabTargetType.JUICE_SHOP in SafeLabOrchestrator.PRESETS
        assert LabTargetType.DVWA in SafeLabOrchestrator.PRESETS

    def test_docker_compose_generation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            compose_path = SafeLabOrchestrator.export_docker_compose(LabTargetType.JUICE_SHOP, out_dir)
            assert compose_path.exists()
            content = compose_path.read_text(encoding="utf-8")
            assert "juice-shop" in content
            assert "127.0.0.1:3000:3000" in content

    def test_builtin_arena_in_memory(self):
        res = SafeLabOrchestrator.run_builtin_arena_benchmark()
        assert res["executed_cleanly"] is True
        assert res["total_targets"] == 12
        assert len(res["targets"]) == 12


class TestAssetConsentManager:
    def test_asset_discovery_and_consent_isolation(self):
        mgr = AssetConsentManager()
        
        a1 = mgr.discover_asset(AssetCategory.SUBDOMAIN, "api.dev.target.local", "subfinder")
        a2 = mgr.discover_asset(AssetCategory.CLOUD_BUCKET, "s3://company-assets-prod", "js_scan")
        a3 = mgr.discover_asset(AssetCategory.API_ENDPOINT, "/api/internal/debug", "js_scan")
        
        assert len(mgr.get_pending()) == 3
        assert len(mgr.get_approved_scope()) == 0  # Zero requests sent before consent
        
        # Approve only a1 and a3
        mgr.approve_asset(a1.asset_id)
        mgr.approve_asset(a3.asset_id)
        mgr.reject_asset(a2.asset_id, reason="Third-party managed bucket")
        
        assert len(mgr.get_pending()) == 0
        approved_subdomains = mgr.get_approved_scope(AssetCategory.SUBDOMAIN)
        assert "api.dev.target.local" in approved_subdomains
        assert "s3://company-assets-prod" not in mgr.get_approved_scope()


class TestAdaptiveRiskSelector:
    def test_auth_endpoint_selection(self):
        plan = AdaptiveRiskSelector.select_checks("/api/v1/auth/login", method="POST")
        assert plan.detected_semantic == "AUTH_FLOW"
        assert plan.risk_weight == 1
        assert TestCheckClass.RATE_LIMIT_BRUTEFORCE in plan.prioritized_checks
        assert TestCheckClass.SESSION_SECURITY in plan.prioritized_checks
        assert TestCheckClass.PATH_TRAVERSAL in plan.suppressed_checks

    def test_graphql_endpoint_selection(self):
        plan = AdaptiveRiskSelector.select_checks("/v1/graphql", method="POST")
        assert plan.detected_semantic == "GRAPHQL"
        assert TestCheckClass.GRAPHQL_INTROSPECTION in plan.prioritized_checks
        assert TestCheckClass.GRAPHQL_BATCHING_DOS in plan.prioritized_checks
        assert TestCheckClass.CSRF in plan.suppressed_checks

    def test_data_resource_endpoint_selection(self):
        plan = AdaptiveRiskSelector.select_checks("/api/v1/users/42", method="GET")
        assert plan.detected_semantic == "DATA_RESOURCE"
        assert TestCheckClass.BOLA_IDOR in plan.prioritized_checks
        assert TestCheckClass.SQL_INJECTION in plan.prioritized_checks
