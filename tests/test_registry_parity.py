"""Phase 4 Registry Parity, MCP Hardening, PentAGI/PentesterFlow Primitives & Hygiene Tests."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Dict

import httpx
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


# ── 1. Canonical Tool Catalog & Manifest Parity ─────────────────────────────

def test_tool_catalog_sync_parity():
    from scripts.sync_tool_manifests import load_catalog, sync_manifests

    catalog = load_catalog()
    assert len(catalog.get("tools", [])) >= 40
    in_sync, messages = sync_manifests(write=False)
    assert in_sync is True, f"Manifest drift detected: {messages}"


def test_tool_registry_loads_catalog_and_validates_argv_paths(tmp_path: Path):
    from core.tool_registry import ToolError, ToolRegistry, validate_argv_paths

    reg = ToolRegistry()
    names = [d.tool_id for d in reg.list_tools()]
    assert len(names) >= 40
    for expected in ("nmap", "httpx", "subfinder", "nuclei", "ffuf"):
        assert expected in names

    # Custom config_path is honored
    custom_cfg = tmp_path / "custom_tools.yaml"
    custom_cfg.write_text(
        yaml.safe_dump({"tools": [{"id": "custom_probe", "executable": "python", "risk": "low"}]}),
        encoding="utf-8",
    )
    custom_reg = ToolRegistry(config_path=str(custom_cfg))
    assert custom_reg.get("custom_probe") is not None

    # Path containment: allows workspace/wordlists, rejects traversal and UNC
    ok_wordlist = str(ROOT / "wordlists" / "pentesterflow" / "README.md")
    validate_argv_paths(["ffuf", "-w", ok_wordlist], tool_id="ffuf")

    with pytest.raises(ToolError):
        validate_argv_paths(["ffuf", "-w", "../../etc/passwd"], tool_id="ffuf")
    with pytest.raises(ToolError):
        validate_argv_paths(["ffuf", "-w", r"\\evil-server\share\wl.txt"], tool_id="ffuf")


# ── 2. Unified Skill Registry & Zero Dangling YAML Refs ─────────────────────

def test_unified_skill_registry_zero_dangling_refs():
    from core.skill_registry import SkillRegistry, _SkillContractAdapter

    reg = SkillRegistry()
    reg.discover(force=True)

    all_names = set(reg.list_names(include_agent_skills=True))
    assert "browser_sensor" in all_names
    assert "safe_sqli_assessment" in all_names
    assert "triage_gate" in all_names

    listed = reg.list_skills(include_agent_skills=True)
    assert len(listed) == len(all_names)

    dangling = []
    for yaml_path in sorted((ROOT / "skills").rglob("skill.yaml")):
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
        for field in ("depends_on", "next_skills", "fallback_skills"):
            for ref in data.get(field) or []:
                if ref not in all_names:
                    dangling.append((yaml_path.relative_to(ROOT).as_posix(), field, ref))
    assert dangling == [], f"Dangling skill.yaml references found: {dangling}"

    # Verify contract adapter bridges agent skills to BaseSkill interface
    inst = reg.instantiate("safe_sqli_assessment")
    assert isinstance(inst, _SkillContractAdapter)
    assert hasattr(inst, "execute") and hasattr(inst, "run")


@pytest.mark.asyncio
async def test_spa_api_extractor_and_exploit_chain_builder_metadata_keys(tmp_path: Path):
    from core.workspace_manager import WorkspaceManager
    from skills.base_skill import SkillContext
    from skills.browser.spa_api_extractor.skill import SPAAPIExtractorSkill
    from skills.cognitive.exploit_chain_builder.skill import ExploitChainBuilderSkill
    from tools.tool_manager import ToolManager

    ws = WorkspaceManager(root=tmp_path)
    ws.create_workspace("example.com", "sess1")
    ctx = SkillContext(
        target="https://example.com",
        session_id="sess1",
        workspace=ws,
        tool_manager=ToolManager(output_dir=str(tmp_path / "out")),
        extra={"findings": []},
    )

    ec_res = await ExploitChainBuilderSkill().execute(ctx)
    assert "chains" in ec_res.metadata
    assert ec_res.metadata["status"] == "UNAVAILABLE"
    assert ec_res.metadata["verified"] is False

    spa = SPAAPIExtractorSkill()
    # Force offline browser crawl failure -> truthful UNAVAILABLE with 'endpoints' key
    async def _offline(*_a, **_kw):
        return [], [], False

    spa._browser_crawl = _offline  # type: ignore[method-assign]
    spa_res = await spa.execute(ctx)
    assert "endpoints" in spa_res.metadata
    assert spa_res.metadata["status"] == "UNAVAILABLE"
    assert spa_res.metadata["verified"] is False


# ── 3. MCP Hardening (PolicyGate, Scope, Fingerprint, boundContent, SSRF) ───

def test_mcp_fingerprint_bound_content_and_bridge_security(monkeypatch):
    from core.arsenal.universal_mcp_bridge import MCPServerRunner, UniversalMCPBridge
    from core.mcp_client import MCPConsentStore, bound_content, mcp_server_fingerprint
    from core.scope_engine import ScopePolicy, StrictScopeEngine

    # SHA-256 fingerprint changes when args/command/env mutate
    cfg1 = {"server_id": "srv1", "command": "python", "args": ["-m", "srv"], "env": {"A": "1"}}
    cfg2 = {"server_id": "srv1", "command": "python", "args": ["-m", "srv", "--evil"], "env": {"A": "1"}}
    fp1 = mcp_server_fingerprint(cfg1)
    fp2 = mcp_server_fingerprint(cfg2)
    assert len(fp1) == 64 and fp1 != fp2

    store = MCPConsentStore()
    store.approve("srv1", fp1)
    assert store.is_approved("srv1", fp1) is True
    assert store.is_approved("srv1", fp2) is False

    # bound_content enforces string cap, block cap, dict key cap, and depth cap
    deep: Any = "leaf"
    for _ in range(40):
        deep = {"nest": deep}
    bounded = bound_content(deep, cap=32, max_depth=8)
    assert "max depth exceeded" in json.dumps(bounded)
    huge_list = ["x" * 200 for _ in range(250)]
    b_list = bound_content(huge_list, cap=20, max_blocks=10)
    assert len(b_list) == 11 and len(b_list[0]) == 20

    # UniversalMCPBridge enforces non-overridable SSRF/scheme invariants EVEN under unrestricted_mode
    monkeypatch.setenv("HUNTER_UNRESTRICTED", "1")
    bridge = UniversalMCPBridge(
        scope_engine=StrictScopeEngine(ScopePolicy(allowed_targets=["example.com"], fail_closed=True))
    )
    for blocked_target in (
        "http://169.254.169.254/latest/meta-data/",
        "http://[::ffff:169.254.169.254]/",
        "http://0x7f000001/",
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_INFO",
    ):
        res = bridge.handle_tool_call("kali_httpx", {"target": blocked_target})
        assert res["success"] is False, f"Expected SSRF/scheme block for {blocked_target}"
        assert res.get("error_category") == "SCOPE_VIOLATION"

    # MCPServerRunner handles notifications/initialized silently (returns None)
    runner = MCPServerRunner(bridge=bridge)
    assert runner.process_rpc_request(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})) is None
    assert runner.initialized is True


# ── 4. PentAGI Tools (file_diff, state_guard, sploitus, web_search) ─────────

def test_file_diff_and_state_guard(tmp_path: Path):
    from core.tools.file_diff import DiffApplyError, apply_unified_diff, apply_unified_diff_to_file
    from core.tools.state_guard import ErrFlowStateGuard, is_state_guard, state_guard, unwrap_state_guard

    # Context-anchored diff succeeds even with stale line number
    src = "alpha\nbeta\ngamma\ndelta\n"
    stale_diff = "@@ -99,3 +99,3 @@\n beta\n-gamma\n+GAMMA\n delta\n"
    patched, count = apply_unified_diff(src, stale_diff)
    assert count == 1
    assert patched == "alpha\nbeta\nGAMMA\ndelta\n"

    # Atomic fail-closed on missing context
    f = tmp_path / "sample.txt"
    f.write_text(src, encoding="utf-8")
    with pytest.raises(DiffApplyError):
        apply_unified_diff_to_file(f, "@@ -1,2 +1,2 @@\n-nonexistent\n+new\n", allowed_root=tmp_path)
    assert f.read_text(encoding="utf-8") == src

    # Root escape rejected
    with pytest.raises(PermissionError):
        apply_unified_diff_to_file(tmp_path.parent / "outside.txt", stale_diff, allowed_root=tmp_path)

    # State guard sentinel
    orig = RuntimeError("task already running")
    wrapped = state_guard(orig)
    assert is_state_guard(wrapped) is True
    assert is_state_guard(ErrFlowStateGuard) is True
    assert is_state_guard(ValueError("bad arg")) is False
    assert str(wrapped) == "task already running"
    assert unwrap_state_guard(wrapped) is orig


@pytest.mark.asyncio
async def test_sploitus_and_web_search_ssrf_and_local_only():
    from core.tools.sploitus import FatalSearchError, SearchRequest, SploitusSearcher
    from core.tools.web_search import EngineID, WebSearchOrchestrator

    # Sploitus blocks SSRF/scheme targets fail-closed
    for bad_url in (
        "http://169.254.169.254/latest/meta-data",
        "http://127.0.0.1:8080/search",
        "file:///etc/passwd",
    ):
        searcher = SploitusSearcher(api_url=bad_url)
        with pytest.raises(FatalSearchError):
            await searcher.search(SearchRequest(query="openssl"))

    # Valid mocked Sploitus query succeeds
    def _mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "exploits_total": 1,
                "exploits": [{"id": "EXP-1", "title": "Sample CVE", "score": 7.5, "href": "https://sploitus.com/x"}],
            },
        )

    ok_searcher = SploitusSearcher(transport=httpx.MockTransport(_mock_handler))
    out = await ok_searcher.search(SearchRequest(query="nginx"))
    assert "Sample CVE" in out

    # WebSearchOrchestrator respects local_only
    orch = WebSearchOrchestrator(local_only=True, engines={EngineID.SPLOITUS: ok_searcher})
    res = await orch.search("nginx", mode="exploit")
    assert res["ok"] is False and res["blocked_by_scope"] is True


# ── 5. BugHunter Package Imports, Non-Stub Scanners & PentesterFlow Corpora ─

def test_bughunter_imports_non_stub_scanners_and_corpora(tmp_path: Path):
    import bughunter.memory  # noqa: F401
    import bughunter.tools.verifiers  # noqa: F401
    from hunter_ai.tools.abh_bridge import ABHToolBridge
    from hunter_ai.tools.takeover_scanner import scan_takeover
    from hunter_ai.tools.web3_audit import audit_contract
    from hunter_ai.tools.web_scanners import SASTScanner

    # Never fabricates findings for missing/empty inputs
    empty_dir = tmp_path / "empty_recon"
    empty_dir.mkdir()
    assert scan_takeover(str(empty_dir)) == []

    clean_sol = tmp_path / "Safe.sol"
    clean_sol.write_text("pragma solidity ^0.8.20;\ncontract Safe { uint256 public x; }\n", encoding="utf-8")
    audit = audit_contract(str(clean_sol))
    assert audit["status"] == "OK" and audit["findings"] == []

    # SSRF blocked cleanly through ABHToolBridge
    cors_blocked = ABHToolBridge.scan_cors("http://169.254.169.254/latest/meta-data/")
    assert cors_blocked["status"] == "BLOCKED" and cors_blocked["findings"] == []

    # SASTScanner does not emit fake findings for a nonexistent path
    sast_missing = SASTScanner().scan(str(tmp_path / "does_not_exist"))
    assert sast_missing["findings"] == []

    # PentesterFlow 8 corpora + README exist with Apache-2.0 provenance
    pf_root = ROOT / "wordlists" / "pentesterflow"
    assert (pf_root / "README.md").is_file()
    expected_corpora = [
        "graphql/field-suggestion-probes.txt",
        "jwt/alg-none-variants.txt",
        "jwt/kid-injection.txt",
        "jwt/weak-secrets.txt",
        "ssti/fingerprint-polyglot.txt",
        "ssti/jinja2.txt",
        "supabase/common-tables.txt",
        "takeover/fingerprints.json",
    ]
    for rel in expected_corpora:
        p = pf_root / rel
        assert p.is_file(), f"Missing corpus: {rel}"
        txt = p.read_text(encoding="utf-8")
        assert "Apache-2.0" in txt
        assert "0759d873a07350a70283c9751f7d136905f777c7" in txt
        if p.suffix == ".json":
            parsed = json.loads(txt)
            assert parsed["_provenance"]["license"] == "Apache-2.0"
            assert len(parsed["fingerprints"]) >= 50


def test_scripts_hygiene_no_stale_paths_or_hardcoded_lan_ip():
    files_to_check = [
        "sync.sh",
        "setup_windows_ollama.ps1",
        "setup_kali.sh",
        "install_tools_kali.sh",
        "setup_windows.bat",
        "kali.bat",
        "kali_monitor.sh",
        "master.sh",
        "network.sh",
        "run_hunter.sh",
        "scripts/pentest_launcher.sh",
        "scripts/setup_kali.sh",
        "scripts/setup_kali_desktop.py",
    ]
    for rel in files_to_check:
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert "/mnt/e/Agant/PentestAI-Unified" not in text, f"Stale path still in {rel}"
        assert "192.168.1.3" not in text, f"Hardcoded LAN IP 192.168.1.3 still in {rel}"
    assert "127.0.0.1:11434" in (ROOT / "setup_windows_ollama.ps1").read_text(encoding="utf-8")
