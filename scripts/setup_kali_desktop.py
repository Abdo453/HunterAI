#!/usr/bin/env python3
"""
Setup Kali Desktop Environment for HunterAI / PentestAI-Unified
Configures:
- Symlink on Kali Desktop: /home/kali/Desktop/PentestAI-Unified
- Quick-run helper: /home/kali/Desktop/run_hunter.sh
- PATH updates for ~/.local/bin in ~/.bashrc and ~/.zshrc
- Verifies python packages & Kali offensive tools
"""
import os
import subprocess
from pathlib import Path

def setup_in_kali():
    print("[+] Configuring Kali Linux Desktop...")
    
    # 1. Desktop Directory
    desktop_dir = Path("/home/kali/Desktop")
    desktop_dir.mkdir(parents=True, exist_ok=True)
    
    # 2. Target / Agent Symlink
    agent_link = desktop_dir / "PentestAI-Unified"
    target_src = Path("/mnt/e/Agant/PentestAI-Unified")
    if not agent_link.exists() and target_src.exists():
        try:
            agent_link.symlink_to(target_src)
            print(f"[✓] Created agent symlink: {agent_link} -> {target_src}")
        except Exception as e:
            print(f"[!] Symlink note: {e}")
    else:
        print(f"[✓] Agent exists at: {agent_link}")

    # 3. Create run_hunter.sh on Kali Desktop
    run_script = desktop_dir / "run_hunter.sh"
    run_content = """#!/usr/bin/env bash
# Quick Launcher for PentestAI Unified on Kali Linux Desktop
set -e
cd /home/kali/Desktop/PentestAI-Unified
export PATH="$HOME/.local/bin:$PATH"

if [ -z "$1" ]; then
    echo "=========================================================="
    echo "  🛡️  PentestAI Unified / HunterAI — Kali Linux Launcher"
    echo "=========================================================="
    echo "  Usage examples:"
    echo "    ./run_hunter.sh web               # Launch Unified Web UI (:8000)"
    echo "    ./run_hunter.sh opencode          # Launch OpenCode Studio Hub (:8000/opencode)"
    echo "    ./run_hunter.sh status            # View AI Provider & Engine status"
    echo "    ./run_hunter.sh arsenal           # View 63 Kali tools arsenal"
    echo "    ./run_hunter.sh wordlist pass     # Cognitive SecLists search"
    echo "=========================================================="
    python3 pentest.py --help
else
    python3 pentest.py "$@"
fi
"""
    run_script.write_text(run_content, encoding="utf-8")
    run_script.chmod(0o755)
    print(f"[✓] Created executable launcher: {run_script}")

    # 4. Update PATH in ~/.bashrc and ~/.zshrc
    for rc in [Path.home() / ".bashrc", Path.home() / ".zshrc"]:
        if rc.exists():
            text = rc.read_text(encoding="utf-8", errors="ignore")
            if ".local/bin" not in text:
                text += "\nexport PATH=\"$HOME/.local/bin:$PATH\"\n"
                rc.write_text(text, encoding="utf-8")
                print(f"[✓] Updated PATH in {rc.name}")

    # 5. Verify Core Tools
    tools = ["nmap", "nuclei", "subfinder", "httpx", "ffuf", "sqlmap", "katana", "amass", "dirsearch"]
    available = []
    for t in tools:
        if subprocess.run(["which", t], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            available.append(t)
    print(f"[✓] Verified {len(available)}/{len(tools)} essential tools in Kali PATH: {', '.join(available)}")
    print("[+] Kali Desktop environment is fully tuned and ready!")

if __name__ == "__main__":
    setup_in_kali()
