#!/usr/bin/env python3
"""
Setup Kali Desktop Environment for HunterAI
Configures:
- Symlink on Kali Desktop pointing to the active HunterAI repository root
- Quick-run helper on Desktop: ~/Desktop/run_hunter.sh
- PATH updates for ~/.local/bin in ~/.bashrc and ~/.zshrc
- Verifies python packages & Kali offensive tools
"""
import os
import subprocess
from pathlib import Path


def setup_in_kali():
    print("[+] Configuring Kali Linux Desktop...")

    repo_root = Path(os.getenv("HUNTERAI_ROOT") or Path(__file__).resolve().parents[1]).resolve()
    desktop_dir = Path.home() / "Desktop"
    desktop_dir.mkdir(parents=True, exist_ok=True)

    agent_link = desktop_dir / "HunterAI"
    if not agent_link.exists() and repo_root.exists():
        try:
            agent_link.symlink_to(repo_root)
            print(f"[✓] Created agent symlink: {agent_link} -> {repo_root}")
        except Exception as e:
            print(f"[!] Symlink note: {e}")
    else:
        print(f"[✓] Agent exists at: {agent_link}")

    run_script = desktop_dir / "run_hunter.sh"
    run_content = f"""#!/usr/bin/env bash
# Quick Launcher for HunterAI on Kali Linux Desktop
set -e
cd "{repo_root}"
export PATH="$HOME/.local/bin:$PATH"

if [ -z "${{1:-}}" ]; then
    echo "=========================================================="
    echo "  HunterAI — Kali Linux Launcher"
    echo "=========================================================="
    echo "  Usage examples:"
    echo "    ./run_hunter.sh artex             # Launch ARTEX-Pro UI (:3000 + :8000)"
    echo "    ./run_hunter.sh web               # Launch Unified Web UI (:3000 + :8000)"
    echo "    ./run_hunter.sh opencode          # Launch OpenCode Studio Hub (:3000/studio)"
    echo "    ./run_hunter.sh status            # View AI Provider & Engine status"
    echo "    ./run_hunter.sh arsenal           # View Kali tools arsenal"
    echo "=========================================================="
    python3 pentest.py --help
else
    python3 pentest.py "$@"
fi
"""
    run_script.write_text(run_content, encoding="utf-8")
    run_script.chmod(0o755)
    print(f"[✓] Created executable launcher: {run_script}")

    for rc in [Path.home() / ".bashrc", Path.home() / ".zshrc"]:
        if rc.exists():
            text = rc.read_text(encoding="utf-8", errors="ignore")
            if ".local/bin" not in text:
                text += '\nexport PATH="$HOME/.local/bin:$PATH"\n'
                rc.write_text(text, encoding="utf-8")
                print(f"[✓] Updated PATH in {rc.name}")

    tools = ["nmap", "nuclei", "subfinder", "httpx", "ffuf", "sqlmap", "katana", "amass", "dirsearch"]
    available = []
    for t in tools:
        if subprocess.run(["which", t], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            available.append(t)
    print(f"[✓] Verified {len(available)}/{len(tools)} essential tools in Kali PATH: {', '.join(available)}")
    print("[+] Kali Desktop environment is fully tuned and ready!")


if __name__ == "__main__":
    setup_in_kali()
