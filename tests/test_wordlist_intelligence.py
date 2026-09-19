"""
Tests for Wordlist Intelligence Subsystem
=========================================
Covers:
- Wordlist Models & Enums
- WordlistClassifier (Heuristics, Tech affinities, Phase suitability)
- WordlistInventory (Scanning, indexing, caching)
- ContextAnalyzer (Token extraction, domain parsing)
- CandidateMutator (Subdomains, paths, API mutations, parameters)
- WordlistDeduplicator (Streaming deduplication, file writing)
- WordlistSelector (Scoring, selection, profile tiers)
- AdaptiveFeedbackLoop (Dynamic discovery ingestion)
- WordlistIntelligenceAgent (End-to-end facade orchestration)
"""
import os
import tempfile
from pathlib import Path
import pytest

from core.wordlist_intelligence.models import (
    WordlistCategory,
    AttackPhase,
    WordlistTier,
    WordlistMetadata,
    TargetContext,
    GeneratedCandidate,
)
from core.wordlist_intelligence.classifier import WordlistClassifier
from core.wordlist_intelligence.inventory import WordlistInventory
from core.wordlist_intelligence.context import ContextAnalyzer
from core.wordlist_intelligence.mutator import CandidateMutator
from core.wordlist_intelligence.deduplicator import WordlistDeduplicator
from core.wordlist_intelligence.selector import WordlistSelector
from core.wordlist_intelligence.feedback import AdaptiveFeedbackLoop
from core.wordlist_intelligence.agent import WordlistIntelligenceAgent


def test_models_and_enums():
    ctx = TargetContext(
        domain="api.bancoplata.mx",
        brand_tokens=["banco", "plata"],
        detected_tech=set(),
        discovered_subdomains={"api.bancoplata.mx"},
    )
    assert ctx.domain == "api.bancoplata.mx"
    assert "banco" in ctx.brand_tokens
    assert ctx.to_dict()["domain"] == "api.bancoplata.mx"

    meta = WordlistMetadata(
        path="/tmp/graphql.txt",
        filename="graphql.txt",
        category=WordlistCategory.GRAPHQL if hasattr(WordlistCategory, "GRAPHQL") else WordlistCategory.API,
        line_count=250,
        tier=WordlistTier.SMALL,
        tech_affinity=["graphql", "apollo"],
    )
    assert "apollo" in meta.tech_affinity
    assert meta.to_dict()["line_count"] == 250


def test_classifier_rules(tmp_path):
    # Test GraphQL wordlist
    gql_file = tmp_path / "graphql-endpoints.txt"
    gql_file.write_text("query\nmutation\nschema\n__schema\n", encoding="utf-8")
    meta_gql = WordlistClassifier.classify_file(gql_file)
    assert "graphql" in meta_gql.tech_affinity
    assert meta_gql.line_count == 4
    assert meta_gql.tier == WordlistTier.SMALL

    # Test DNS subdomains wordlist
    dns_file = tmp_path / "subdomains-top1000.txt"
    dns_file.write_text("\n".join([f"sub{i}" for i in range(100)]), encoding="utf-8")
    meta_dns = WordlistClassifier.classify_file(dns_file)
    assert meta_dns.category in (WordlistCategory.DNS, WordlistCategory.SUBDOMAINS)
    assert meta_dns.line_count == 100

    # Test Spring Boot actuator wordlist
    spring_file = tmp_path / "spring-boot-actuator.txt"
    spring_file.write_text("actuator/health\nactuator/env\nactuator/metrics\n", encoding="utf-8")
    meta_spring = WordlistClassifier.classify_file(spring_file)
    assert "spring" in meta_spring.tech_affinity


def test_context_analyzer():
    ctx = ContextAnalyzer.create_initial_context("https://dev-portal.staging.fintech-corp.com:8443/api/v1")
    assert "fintech-corp" in ctx.domain or "dev-portal" in ctx.domain
    assert "fintech" in ctx.brand_tokens
    assert "corp" in ctx.brand_tokens

    # Test token updates
    ContextAnalyzer.ingest_subdomains(ctx, ["api-internal.fintech-corp.com", "auth-v2.fintech-corp.com"])
    ContextAnalyzer.ingest_technology(ctx, "WordPress")
    ContextAnalyzer.ingest_technology(ctx, "Spring")
    ContextAnalyzer.ingest_technology(ctx, "GraphQL")
    ContextAnalyzer.ingest_endpoints(ctx, ["/api/v2/users", "/graphql/query", "/oauth/token"])
    ContextAnalyzer.ingest_parameters(ctx, ["client_id", "redirect_uri", "jwt_token"])

    assert "wordpress" in ctx.detected_tech
    assert "spring" in ctx.detected_tech
    assert "graphql" in ctx.detected_tech
    assert "api-internal.fintech-corp.com" in ctx.discovered_subdomains
    assert "client_id" in ctx.discovered_parameters


def test_candidate_mutator():
    ctx = ContextAnalyzer.create_initial_context("bancoplata.mx")
    ctx.brand_tokens = ["bancoplata", "plata"]
    ctx.discovered_subdomains.add("api")
    ctx.detected_tech.add("graphql")
    ctx.detected_tech.add("spring")

    # Subdomain mutations
    sub_cands = CandidateMutator.generate_subdomain_candidates(ctx, max_candidates=50)
    sub_strings = [c.candidate for c in sub_cands]
    assert len(sub_strings) > 0
    # Should include environment prefixes / brand combinations
    assert any("api" in s or "dev" in s or "admin" in s for s in sub_strings)

    # Path mutations
    path_cands = CandidateMutator.generate_path_candidates(ctx, max_candidates=50)
    path_strings = [c.candidate for c in path_cands]
    assert len(path_strings) > 0
    # Should include tech-specific paths like graphql/actuator
    assert any("graphql" in p or "actuator" in p or "api" in p for p in path_strings)

    # Parameter mutations
    param_cands = CandidateMutator.generate_parameter_candidates(ctx, max_candidates=50)
    param_strings = [c.candidate for c in param_cands]
    assert len(param_strings) > 0
    assert any("token" in p or "key" in p or "id" in p for p in param_strings)


def test_deduplicator(tmp_path):
    items = [
        "ADMIN",
        "admin",
        "  login  ",
        "LOGIN",
        "api/v1",
        "api/v1",
        "# comment line",
        "",
        "secret_key"
    ]
    deduped = WordlistDeduplicator.deduplicate_list(items, lowercase=True)
    assert deduped == ["admin", "login", "api/v1", "secret_key"]

    out_file = tmp_path / "deduped.txt"
    written = WordlistDeduplicator.write_deduplicated_file(
        items,
        out_file,
        header_comment="Cleaned Wordlist",
        lowercase=True
    )
    assert written == 4
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "# Cleaned Wordlist" in content
    assert "admin" in content
    assert "login" in content


def test_wordlist_inventory(tmp_path):
    # Setup mock seclists dir
    mock_root = tmp_path / "SecLists"
    mock_dns = mock_root / "Discovery" / "DNS"
    mock_web = mock_root / "Discovery" / "Web-Content"
    mock_dns.mkdir(parents=True)
    mock_web.mkdir(parents=True)

    (mock_dns / "subdomains-top1000.txt").write_text("www\nmail\napi\n", encoding="utf-8")
    (mock_web / "raft-medium-directories.txt").write_text("admin\nportal\nuploads\n", encoding="utf-8")
    (mock_web / "graphql.txt").write_text("graphql\nschema\n", encoding="utf-8")

    inventory = WordlistInventory(custom_roots=[mock_root])
    inventory.refresh_inventory()
    assert len(inventory.catalog) >= 3

    dns_lists = inventory.find_by_category(WordlistCategory.DNS)
    assert len(dns_lists) >= 1
    assert any("subdomains-top1000" in d.filename for d in dns_lists)

    gql_lists = inventory.find_by_technology("graphql")
    assert len(gql_lists) >= 1


def test_wordlist_selector(tmp_path):
    mock_root = tmp_path / "wordlists"
    mock_root.mkdir()
    (mock_root / "common.txt").write_text("admin\nlogin\n", encoding="utf-8")
    (mock_root / "raft-large-directories.txt").write_text("\n".join([f"path{i}" for i in range(60000)]), encoding="utf-8")
    (mock_root / "spring-boot.txt").write_text("actuator/health\nactuator/beans\n", encoding="utf-8")

    inventory = WordlistInventory(custom_roots=[mock_root])
    inventory.refresh_inventory()
    selector = WordlistSelector(inventory)

    ctx = ContextAnalyzer.create_initial_context("spring-app.enterprise.com")
    ctx.detected_tech.add("spring")

    # In safe profile -> should prefer small/compact
    best_safe = selector.select_best_wordlist(WordlistCategory.DIRECTORIES, context=ctx, profile="safe")
    assert best_safe is not None
    assert best_safe.filename in ("common.txt", "spring-boot.txt")

    # In deep profile with spring detected -> should match spring tech affinity
    tech_matches = selector.select_technology_specific_wordlists(ctx)
    assert len(tech_matches) >= 1
    assert "spring" in tech_matches[0].tech_affinity


def test_adaptive_feedback_loop():
    ctx = ContextAnalyzer.create_initial_context("target.com")
    feedback = AdaptiveFeedbackLoop(ctx)

    # Subdomain discovery feedback
    new_subs = feedback.on_subdomains_discovered(["api-v1.target.com", "auth.target.com"])
    assert len(new_subs) > 0
    assert "api-v1.target.com" in ctx.discovered_subdomains
    assert "auth.target.com" in ctx.discovered_subdomains

    # Technology discovery feedback
    new_tech_mutations = feedback.on_technologies_discovered(["GraphQL", "Next.js", "WordPress"])
    assert "graphql" in ctx.detected_tech
    assert "nextjs" in ctx.detected_tech
    assert "wordpress" in ctx.detected_tech
    assert len(new_tech_mutations) > 0

    # Endpoint discovery feedback
    new_endpoint_mutations = feedback.on_endpoints_discovered(["https://target.com/api/v2/users/export"])
    assert len(new_endpoint_mutations) > 0


def test_agent_facade_end_to_end(tmp_path):
    agent = WordlistIntelligenceAgent(target="https://secure.bancoplata.mx", auto_index=False)
    assert agent.context.domain == "secure.bancoplata.mx"
    assert "bancoplata" in agent.context.brand_tokens

    # Ingest discoveries
    sub_muts = agent.ingest_discovery("subdomain", ["dev-api.bancoplata.mx", "admin-internal.bancoplata.mx"])
    assert len(sub_muts) > 0

    tech_muts = agent.ingest_discovery("technology", ["Spring Boot", "Actuator"])
    assert len(tech_muts) > 0

    agent.ingest_discovery("parameter", ["client_id", "redirect_uri", "user_id"])
    assert "client_id" in agent.context.discovered_parameters

    # Generate custom candidates
    dir_cands = agent.generate_custom_candidates(WordlistCategory.DIRECTORIES, max_candidates=100)
    assert len(dir_cands) > 0

    param_cands = agent.generate_custom_candidates(WordlistCategory.PARAMETERS, max_candidates=100)
    assert len(param_cands) > 0

    # Build custom wordlist file
    out_file = tmp_path / "custom_test_wordlist.txt"
    created_path = agent.build_custom_wordlist_file(
        destination_path=out_file,
        category=WordlistCategory.DIRECTORIES,
        include_base_static=False,
        max_candidates=50
    )
    assert os.path.isfile(created_path)
    assert out_file.stat().st_size > 0

    # Export summary
    summary = agent.export_inventory_summary()
    assert "total_wordlists" in summary
    assert summary["target_context"]["domain"] == "secure.bancoplata.mx"
