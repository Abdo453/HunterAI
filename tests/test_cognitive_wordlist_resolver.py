"""
Hermetic Test Suite for Cognitive SecLists & Wordlist Intelligence Engine
=========================================================================
Validates:
1. Cognitive deliberation across all SecLists categories (AI/LLM Testing, Passwords, Usernames, DNS, API, Fuzzing)
2. Accurate path resolution prioritizing Kali Linux paths (/home/kali/wordlist/SecLists)
3. Zero-failure dynamic fallback synthesis when running offline or outside Kali
4. CLI subcommands (`pentest wordlist`, `pentest seclists`)
5. REST API endpoints (`/api/wordlists/resolve`, `/api/wordlists/roots`)
"""
from pathlib import Path
import tempfile
import pytest
from starlette.testclient import TestClient

from core.wordlist_intelligence.cognitive_resolver import (
    CognitiveWordlistResolver,
    get_cognitive_resolver,
)
from pentest import build_parser, main
from ui.web.app import app


@pytest.fixture
def test_client():
    return TestClient(app)


def test_cognitive_deliberation_ai_llm_categories():
    """Verifies that all AI/LLM safety testing domains are classified accurately."""
    resolver = get_cognitive_resolver()

    # 1. Ethical & Safety Boundaries
    res_eth = resolver.deliberate_and_resolve("ai ethical boundaries")
    assert res_eth.category == "ai_llm"
    assert res_eth.exists_on_disk is True
    assert "ethical_boundaries" in res_eth.selected_path.lower()
    assert len(res_eth.sample_preview) > 0
    assert "الذكاء الاصطناعي" in res_eth.arabic_summary

    # 2. Bias Testing
    res_bias = resolver.deliberate_and_resolve("testing gender and racial bias on llm")
    assert res_bias.category == "ai_llm"
    assert "bias" in res_bias.selected_path.lower()

    # 3. Data Leakage
    res_leak = resolver.deliberate_and_resolve("system prompt and personal data leakage")
    assert res_leak.category == "ai_llm"
    assert "leakage" in res_leak.selected_path.lower()

    # 4. Divergence Attack
    res_div = resolver.deliberate_and_resolve("divergence alignment escape attack")
    assert res_div.category == "ai_llm"
    assert "divergence" in res_div.selected_path.lower()


def test_cognitive_deliberation_passwords_and_usernames():
    """Verifies credential and authentication wordlist selection."""
    resolver = get_cognitive_resolver()

    # Passwords
    res_pwd = resolver.deliberate_and_resolve("passwords", profile="standard")
    assert res_pwd.category == "passwords"
    assert res_pwd.exists_on_disk is True
    assert "passwords" in res_pwd.selected_path.lower()
    assert "كلمات المرور" in res_pwd.arabic_summary

    # Usernames
    res_user = resolver.deliberate_and_resolve("usernames", profile="standard")
    assert res_user.category == "usernames"
    assert "usernames" in res_user.selected_path.lower()
    assert "المستخدمين" in res_user.arabic_summary


def test_cognitive_deliberation_dns_and_api():
    """Verifies discovery wordlists for DNS and APIs."""
    resolver = get_cognitive_resolver()

    res_dns = resolver.deliberate_and_resolve("subdomains", profile="deep")
    assert res_dns.category == "dns"
    assert res_dns.exists_on_disk is True

    res_api = resolver.deliberate_and_resolve("api swagger endpoints")
    assert res_api.category == "api"
    assert res_api.exists_on_disk is True


def test_simulated_kali_seclists_tree_resolution():
    """
    Simulates the exact Kali Linux SecLists structure as seen in the operator's shell:
    /home/kali/wordlist/SecLists/Ai/LLM_Testing/Ethical_and_Safety_Boundaries/harmful_prompts.txt
    and verifies that the resolver automatically locates it.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        mock_root = Path(tmpdir) / "SecLists"
        ai_eth_dir = mock_root / "Ai" / "LLM_Testing" / "Ethical_and_Safety_Boundaries"
        pwd_dir = mock_root / "Passwords" / "Common-Credentials"
        ai_eth_dir.mkdir(parents=True, exist_ok=True)
        pwd_dir.mkdir(parents=True, exist_ok=True)

        mock_ai_file = ai_eth_dir / "harmful_prompts.txt"
        mock_ai_file.write_text("harmful_prompt_probe_1\nharmful_prompt_probe_2\n", encoding="utf-8")

        mock_pwd_file = pwd_dir / "10-million-password-list-top-10000.txt"
        mock_pwd_file.write_text("password123\nadmin2026\n", encoding="utf-8")

        # Initialize resolver with mock SecLists prioritized
        resolver = CognitiveWordlistResolver(custom_roots=[mock_root])

        # Resolve AI Ethical Boundaries
        res_ai = resolver.deliberate_and_resolve("ai ethical boundaries")
        assert Path(res_ai.selected_path).resolve() == mock_ai_file.resolve()
        assert res_ai.exists_on_disk is True
        assert res_ai.source_root == str(mock_root)

        # Resolve Passwords
        res_pwd = resolver.deliberate_and_resolve("passwords", profile="standard")
        assert Path(res_pwd.selected_path).resolve() == mock_pwd_file.resolve()
        assert res_pwd.exists_on_disk is True


def test_cli_wordlist_command():
    """Verifies CLI argument parsing and execution for `pentest wordlist` and `pentest seclists`."""
    parser = build_parser()

    # 1. Parsing wordlist command
    args_wl = parser.parse_args(["wordlist", "ai ethical boundaries", "--think"])
    assert args_wl.command == "wordlist"
    assert args_wl.query == "ai ethical boundaries"
    assert args_wl.think is True

    # 2. Parsing seclists alias
    args_sec = parser.parse_args(["seclists", "passwords", "--profile", "deep"])
    assert args_sec.command == "seclists"
    assert args_sec.query == "passwords"
    assert args_sec.profile == "deep"

    # 3. Direct execution via main
    code_wl = main(["wordlist", "subdomains"])
    assert code_wl == 0

    code_sec = main(["seclists", "passwords"])
    assert code_sec == 0


def test_api_wordlists_endpoints(test_client):
    """Verifies FastAPI REST endpoints for cognitive wordlist resolution."""
    # 1. GET /api/wordlists/resolve
    res_api = test_client.get("/api/wordlists/resolve?query=ai+ethical+boundaries&profile=standard")
    assert res_api.status_code == 200
    data = res_api.json()
    assert data["category"] == "ai_llm"
    assert data["exists_on_disk"] is True
    assert "selected_path" in data
    assert "reasoning_trace" in data
    assert len(data["reasoning_trace"]) > 0

    # 2. GET /api/wordlists/roots
    res_roots = test_client.get("/api/wordlists/roots")
    assert res_roots.status_code == 200
    roots_data = res_roots.json()
    assert "candidate_roots" in roots_data
    assert "active_roots" in roots_data
    assert any("home/kali/wordlist" in r.replace("\\", "/") for r in roots_data["candidate_roots"])
