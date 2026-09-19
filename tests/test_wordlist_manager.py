"""
Unit tests for WordlistManager and Kali SecLists prioritization.
"""
import os
import shutil
import tempfile
from pathlib import Path
import pytest

from core.wordlist_manager import WordlistManager, resolve_wordlist


def test_candidate_roots_include_seclists():
    wm = WordlistManager()
    root_strs = [str(r).replace("\\", "/") for r in wm.roots]
    
    # Must prioritize Kali SecLists
    assert any("/home/kali/wordlist/SecLists" in r for r in root_strs)
    assert any("/home/kali/wordlist" in r for r in root_strs)
    assert any("/usr/share/wordlists/seclists" in r for r in root_strs)
    assert any("/usr/share/wordlists" in r for r in root_strs)


def test_ensure_fallbacks_creates_clean_defaults():
    wm = WordlistManager()
    wm.ensure_fallbacks()
    
    fallback_dir = wm.local_fallback_dir
    assert fallback_dir.exists()
    
    common = fallback_dir / "common.txt"
    subs = fallback_dir / "subdomains.txt"
    params = fallback_dir / "parameters.txt"
    fuzz = fallback_dir / "fuzzing.txt"
    
    for f in [common, subs, params, fuzz]:
        assert f.exists()
        content = f.read_text(encoding="utf-8")
        assert len(content.strip()) > 0


def test_fallback_resolution_on_test_machine():
    wm = WordlistManager()
    
    dir_wl = wm.get_wordlist("directories", profile="safe")
    assert os.path.isfile(dir_wl)
    
    dns_wl = wm.get_wordlist("dns", profile="deep")
    assert os.path.isfile(dns_wl)
    
    param_wl = wm.get_wordlist("parameters", profile="standard")
    assert os.path.isfile(param_wl)


def test_simulated_kali_seclists_priority():
    """
    Simulate the exact filesystem tree found on the user's Kali VM
    at /home/kali/wordlist/SecLists and verify dynamic selection.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        mock_seclists = Path(tmpdir) / "SecLists"
        dns_dir = mock_seclists / "Discovery" / "DNS"
        web_dir = mock_seclists / "Discovery" / "Web-Content"
        dns_dir.mkdir(parents=True, exist_ok=True)
        web_dir.mkdir(parents=True, exist_ok=True)
        
        # Populate files as seen in Kali screenshots
        f_dns_deep = dns_dir / "subdomains-top1million-110000.txt"
        f_dns_quick = dns_dir / "subdomains-top1million-5000.txt"
        f_web_med = web_dir / "directory-list-2.3-medium.txt"
        f_web_com = web_dir / "common.txt"
        f_params = web_dir / "burp-parameter-names.txt"
        
        f_dns_deep.write_text("deep.subdomain.test\n", encoding="utf-8")
        f_dns_quick.write_text("quick.subdomain.test\n", encoding="utf-8")
        f_web_med.write_text("medium_dir\n", encoding="utf-8")
        f_web_com.write_text("common_dir\n", encoding="utf-8")
        f_params.write_text("param_test\n", encoding="utf-8")
        
        # Initialize manager with mock SecLists prioritized
        wm = WordlistManager(custom_roots=[mock_seclists])
        
        # 1. DNS Deep Profile must pick 110,000 list
        res_dns_deep = wm.get_wordlist("dns", profile="deep")
        assert Path(res_dns_deep).resolve() == f_dns_deep.resolve()
        
        # 2. DNS Safe Profile must pick 5,000 list
        res_dns_safe = wm.get_wordlist("dns", profile="safe")
        assert Path(res_dns_safe).resolve() == f_dns_quick.resolve()
        
        # 3. Directory Deep Profile must pick directory-list-2.3-medium.txt
        res_dir_deep = wm.get_wordlist("directories", profile="deep")
        assert Path(res_dir_deep).resolve() == f_web_med.resolve()
        
        # 4. Directory Safe Profile must pick common.txt
        res_dir_safe = wm.get_wordlist("directories", profile="safe")
        assert Path(res_dir_safe).resolve() == f_web_com.resolve()
        
        # 5. Parameters must pick burp-parameter-names.txt
        res_params = wm.get_wordlist("parameters")
        assert Path(res_params).resolve() == f_params.resolve()


def test_convenience_function():
    wl = resolve_wordlist("directories", "safe")
    assert os.path.isfile(wl)


@pytest.mark.asyncio
async def test_recon_agent_wordlist_integration():
    from tools.tool_manager import ToolManager
    from agents.recon_agent import ReconAgent
    from agents.base_agent import AgentTask
    
    tm = ToolManager()
    agent = ReconAgent(tm)
    assert hasattr(agent.osint, "gobuster_dns")
    assert hasattr(agent.osint, "dnsx_brute")
    assert hasattr(agent.osint, "amass_brute")
    assert hasattr(agent.osint, "puredns_brute")


@pytest.mark.asyncio
async def test_web_agent_wordlist_integration():
    from tools.tool_manager import ToolManager
    from agents.web_agent import WebAgent
    from agents.base_agent import AgentTask
    
    tm = ToolManager()
    agent = WebAgent(tm)
    assert hasattr(agent.web, "gobuster_dir")

