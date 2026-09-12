"""
Test Suite for GHDB Dorking, OSINT Hub & 13-Step Bug Bounty Methodology Engine
"""
from __future__ import annotations

import pytest
from core.playbooks.dorking_and_osint_knowledge import (
    DorkingAndOSINTKnowledge,
    GHDB_DORK_TEMPLATES,
    OSINT_SERVICES_DIRECTORY,
    BUG_BOUNTY_13_STEP_WORKFLOW,
    MASTER_WORDLISTS
)


def test_target_dork_generation():
    target = "example.com"
    dorks = DorkingAndOSINTKnowledge.generate_dorks_for_target(target)

    # 1. Verify all categories are present
    assert "sensitive_files" in dorks
    assert "admin_and_auth_panels" in dorks
    assert "api_and_developer_endpoints" in dorks
    assert "credential_and_secret_leaks" in dorks
    assert "cloud_and_infrastructure" in dorks
    assert "bug_bounty_and_scope" in dorks

    # 2. Check content of generated dorks
    assert any("site:example.com filetype:env" in d for d in dorks["sensitive_files"])
    assert any("inurl:admin" in d and "site:example.com" in d for d in dorks["admin_and_auth_panels"])
    assert any("inurl:graphql" in d and "site:example.com" in d for d in dorks["api_and_developer_endpoints"])
    assert any("site:docs.google.com/spreadsheets" in d and "example.com" in d for d in dorks["credential_and_secret_leaks"])
    assert any("site:github.com" in d and "example.com" in d for d in dorks["credential_and_secret_leaks"])
    assert any("site:hackerone.com \"example.com\"" in d for d in dorks["bug_bounty_and_scope"])


def test_osint_lookup_directory():
    target = "mycorp.org"
    osint_links = DorkingAndOSINTKnowledge.get_osint_lookup_directory(target)

    # Core tools & services
    assert "c99_subdomain_finder" in osint_links
    assert "shrewdeye" in osint_links
    assert "securitytrails" in osint_links
    assert "censys" in osint_links
    assert "shodan" in osint_links
    assert "crt_sh" in osint_links
    assert "netlas" in osint_links
    assert "urlscan" in osint_links
    assert "matthewfl_unpacker" in osint_links
    assert "origin_ip_hunter" in osint_links

    # Check formatted URLs
    assert "mycorp.org" in osint_links["securitytrails"]["url"]
    assert "mycorp.org" in osint_links["crt_sh"]["url"]
    assert "mycorp.org" in osint_links["shodan"]["url"]


def test_recon_playbook_13_steps():
    target = "vulnlab.local"
    steps = DorkingAndOSINTKnowledge.get_recon_playbook_steps(target)

    assert len(steps) == 13

    # Step 1: Subdomain gathering
    step1 = steps[0]
    assert step1["step"] == 1
    assert "subfinder" in step1["tools"]
    assert "theHarvester" in step1["tools"]
    assert any("subfinder -d vulnlab.local" in cmd for cmd in step1["commands"])

    # Step 2: Anew deduplication
    assert steps[1]["step"] == 2
    assert "anew" in steps[1]["tools"]

    # Step 3: Nmap port scan
    assert steps[2]["step"] == 3
    assert "nmap" in steps[2]["tools"]

    # Step 4: Subzy takeover
    assert steps[3]["step"] == 4
    assert "subzy" in steps[3]["tools"]

    # Step 5: Httpx alive
    assert steps[4]["step"] == 5
    assert "httpx" in steps[4]["tools"]

    # Step 6: Request smuggling
    assert steps[5]["step"] == 6
    assert "smuggler.py" in steps[5]["tools"]

    # Step 7: Dirsearch & 403 bypass
    assert steps[6]["step"] == 7
    assert "dirsearch" in steps[6]["tools"]

    # Step 8: Nuclei
    assert steps[7]["step"] == 8
    assert "nuclei" in steps[7]["tools"]

    # Step 9: URLs
    assert steps[8]["step"] == 9
    assert "katana" in steps[8]["tools"]

    # Step 10: JS mining
    assert steps[9]["step"] == 10
    assert "mantra" in steps[9]["tools"]

    # Step 11: Arjun parameters
    assert steps[10]["step"] == 11
    assert "arjun" in steps[10]["tools"]

    # Step 12: WordPress
    assert steps[11]["step"] == 12
    assert "wpscan" in steps[11]["tools"]

    # Step 13: SQLMap
    assert steps[12]["step"] == 13
    assert "sqlmap" in steps[12]["tools"]


def test_wordlists_catalog():
    catalog = DorkingAndOSINTKnowledge.get_wordlists_catalog()
    assert "dns" in catalog
    assert "web_content" in catalog
    assert "kiterunner_routes" in catalog
    assert any("raft-large-directories.txt" in w for w in catalog["web_content"])
    assert any("bitquark" in w for w in catalog["dns"])


def test_knowledge_base_registration():
    class MockKB:
        def __init__(self):
            self.saved_techniques = []

        def save_technique(self, technique_name, category, description, tools, steps, affected_tech):
            self.saved_techniques.append({
                "name": technique_name,
                "category": category,
                "tools": tools,
                "steps": steps
            })

        def flush_vectors(self):
            pass

    mock_kb = MockKB()
    registered_count = DorkingAndOSINTKnowledge.register_in_knowledge_base(mock_kb)

    assert registered_count == 3
    assert len(mock_kb.saved_techniques) == 3
    names = [t["name"] for t in mock_kb.saved_techniques]
    assert "Google Hacking Database (GHDB) Dorking" in names
    assert "External OSINT & Origin IP Enumeration" in names
    assert "Full 13-Step Bug Bounty Workflow Playbook" in names
