"""
HunterAI Tool Arsenal — Installed External Tools Registry
=========================================================
Lists installed scanning tools (subfinder, httpx, nuclei, katana, ffuz, nmap, etc.)
"""
from __future__ import annotations

import shutil
from typing import Any, Dict, List


KNOWN_TOOLS = [
    "subfinder", "httpx", "nuclei", "katana", "ffuf", "nmap",
    "gobuster", "dirsearch", "dalfox", "sqlmap", "amass",
    "gau", "waybackurls", "hakrawler", "assetfinder", "wpscan",
    "trivy", "wafw00f", "arjun", "naabu", "masscan",
]


def list_tools() -> List[Dict[str, Any]]:
    """Return list of tools with availability status."""
    result = []
    for tool in KNOWN_TOOLS:
        path = shutil.which(tool)
        result.append({
            "name": tool,
            "status": "INSTALLED" if path else "MISSING",
            "path": path or "",
        })
    return result


__all__ = ["list_tools"]
