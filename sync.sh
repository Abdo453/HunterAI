#!/bin/bash
set -e
echo "[*] Creating required directories..."
mkdir -p core/brain agents/skills ui/cli scripts hunter_ai/protocol tests

echo "[*] Downloading all updated and new components from 192.168.1.3:9999..."
curl -s -o agents/skills/base_skill.py http://192.168.1.3:9999/agents/skills/base_skill.py
curl -s -o agents/skills/lfi_skill.py http://192.168.1.3:9999/agents/skills/lfi_skill.py
curl -s -o agents/skills/cmd_injection_skill.py http://192.168.1.3:9999/agents/skills/cmd_injection_skill.py
curl -s -o agents/skills/sqli_skill.py http://192.168.1.3:9999/agents/skills/sqli_skill.py
curl -s -o core/vuln_engine.py http://192.168.1.3:9999/core/vuln_engine.py
curl -s -o core/orchestrator.py http://192.168.1.3:9999/core/orchestrator.py
curl -s -o core/brain/autonomous_brain.py http://192.168.1.3:9999/core/brain/autonomous_brain.py
curl -s -o ui/cli/cli.py http://192.168.1.3:9999/ui/cli/cli.py
curl -s -o scripts/solve_portswigger_sqli.py http://192.168.1.3:9999/scripts/solve_portswigger_sqli.py
curl -s -o tests/test_vuln_engine.py http://192.168.1.3:9999/tests/test_vuln_engine.py

echo "[+] Sync completed! All skills, VulnerabilityEngine, and Fallbacks ready."
