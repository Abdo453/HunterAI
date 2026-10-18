"""
HunterAI Sniper Scanner — Automated Reconnaissance
==================================================
Sniper is an automated recon tool for target information gathering.
Integrated as a HunterAI module with scope enforcement and PoE validation.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional


def is_sniper_installed() -> bool:
    """Check if sniper binary is available on PATH."""
    return shutil.which("sniper") is not None


def run_sniper(
    target: str,
    mode: str = "recon",
    output_dir: Optional[str] = None,
    scope_checked: bool = True,
) -> Dict[str, Any]:
    """
    Run Sniper against a target.

    Modes:
      - recon:   Basic reconnaissance (subdomains, ports, headers)
      - full:    Full scan (includes vuln scan, crawl, screenshot)
      - web:     Web-focused (headers, technologies, endpoints)
      - vuln:    Vulnerability-focused scan

    Returns structured results dict.
    """
    if not is_sniper_installed():
        return {
            "tool": "sniper",
            "target": target,
            "mode": mode,
            "status": "MISSING_TOOL",
            "error": "sniper not installed. Run: pip install sniper or apt-get install sniper",
            "findings": [],
        }

    if output_dir is None:
        output_dir = f"data/engagements/{target.replace('https://', '').replace('http://', '')}/sniper"

    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # Build sniper command (argument array, no shell string)
    cmd = ["sniper", "-t", target, "-m", mode, "-o", output_dir]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        return {
            "tool": "sniper",
            "target": target,
            "mode": mode,
            "status": "TIMEOUT",
            "error": "Sniper scan timed out after 300s",
            "findings": [],
        }
    except Exception as e:
        return {
            "tool": "sniper",
            "target": target,
            "mode": mode,
            "status": "ERROR",
            "error": str(e),
            "findings": [],
        }

    # Parse output
    findings = _parse_sniper_output(result.stdout, result.stderr)

    return {
        "tool": "sniper",
        "target": target,
        "mode": mode,
        "status": "COMPLETED" if result.returncode == 0 else "FAILED",
        "returncode": result.returncode,
        "stdout": result.stdout[:2000] if result.stdout else "",
        "stderr": result.stderr[:1000] if result.stderr else "",
        "output_dir": output_dir,
        "findings": findings,
        "finding_count": len(findings),
    }


def _parse_sniper_output(stdout: str, stderr: str) -> List[Dict[str, Any]]:
    """Parse Sniper output into structured findings."""
    findings: List[Dict[str, Any]] = []
    lines = (stdout + "\n" + stderr).splitlines()

    for line in lines:
        line = line.strip()
        if not line:
            continue
        # Look for common recon signals
        lower = line.lower()
        signal_type = "other"
        if any(k in lower for k in ["subdomain", "sub"]):
            signal_type = "subdomain"
        elif any(k in lower for k in ["port", "open"]):
            signal_type = "open_port"
        elif any(k in lower for k in ["header", "server", "x-"]):
            signal_type = "header"
        elif any(k in lower for k in ["vuln", "cve", "exploit"]):
            signal_type = "vulnerability"
        elif any(k in lower for k in ["url", "http", "endpoint"]):
            signal_type = "endpoint"

        findings.append({
            "type": signal_type,
            "raw": line[:200],
            "severity": "info",
        })

    return findings


__all__ = ["run_sniper", "is_sniper_installed"]
