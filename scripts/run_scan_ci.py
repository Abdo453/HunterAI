"""CI runner for PentestAI scans.
Runs a scan on a given target with JSON output and exits with status code
based on severity thresholds.
"""
import argparse
import sys
import os
import asyncio

# Ensure project root is on PYTHONPATH
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, project_root)

from ui.cli.cli import run_scan
from core.exporters import export_json

SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}

async def main_async(args):
    result = await run_scan(
        target=args.target,
        mode=args.mode,
        browser=args.browser,
        proxy=args.proxy,
        max_concurrent=args.max_concurrent,
    )
    findings = result.get("findings", [])
    # Export JSON report for CI artifacts
    reports_dir = os.path.abspath(os.path.join("reports"))
    os.makedirs(reports_dir, exist_ok=True)
    export_json(findings, os.path.join(reports_dir, "ci_scan.json"))
    # Determine exit code: 0 if no finding with severity >= Medium
    for f in findings:
        sev = f.get("severity", "Info")
        if SEVERITY_ORDER.get(sev, 0) >= SEVERITY_ORDER["Medium"]:
            return 1
    return 0

def parse_args():
    parser = argparse.ArgumentParser(description="PentestAI CI scan runner")
    parser.add_argument("target", help="Target URL or domain")
    parser.add_argument("-m", "--mode", default="full", choices=["recon", "web", "full", "ctf"], help="Scanning mode")
    parser.add_argument("-b", "--browser", action="store_true", help="Enable browser agent")
    parser.add_argument("-p", "--proxy", default=None, help="Proxy URL")
    parser.add_argument("--max-concurrent", type=int, default=8, help="Maximum concurrent probes")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    exit_code = asyncio.run(main_async(args))
    sys.exit(exit_code)
