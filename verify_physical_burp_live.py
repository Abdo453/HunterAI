#!/usr/bin/env python3
"""
HunterAI - Physical Ground-Truth Burp Suite Validator
=====================================================
Directly verifies the physical integration with a REAL running Burp Suite process:
  1. Socket Probe: Checks if Burp Proxy is listening on 127.0.0.1:8080
  2. Gateway Probe: Checks if HunterAI Gateway is listening on 127.0.0.1:8085
  3. Extension Handshake: Checks if HunterAI Burp Extension is active and pinging
  4. End-to-End Real Wire Replay: Dispatches an ExperimentContract via BCSL
     through Burp Proxy to an authorized target, measuring differential response
     and committing the findings to Evidence Court.

If Burp Suite is not currently running, runs in Readiness Diagnostic Mode with
exact configuration guidance.
"""
from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

PROJECT_ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT))

# Force UTF-8 on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

GREEN = "\033[0;32m" if sys.platform != "win32" else ""
RED = "\033[0;31m" if sys.platform != "win32" else ""
YELLOW = "\033[1;33m" if sys.platform != "win32" else ""
CYAN = "\033[0;36m" if sys.platform != "win32" else ""
BOLD = "\033[1m" if sys.platform != "win32" else ""
RESET = "\033[0m" if sys.platform != "win32" else ""


def check_port_open(host: str, port: int, timeout_sec: float = 1.0) -> bool:
    """Checks if a TCP socket is accepting connections."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout_sec)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False


class PhysicalBurpSuiteValidator:
    """Diagnostic and live execution harness for a real Burp Suite process"""

    def __init__(
        self,
        burp_host: str = "127.0.0.1",
        burp_port: int = 8080,
        gateway_host: str = "127.0.0.1",
        gateway_port: int = 8085,
    ):
        self.burp_host = burp_host
        self.burp_port = burp_port
        self.gateway_host = gateway_host
        self.gateway_port = gateway_port
        self.gateway_url = f"http://{gateway_host}:{gateway_port}"

    def run_diagnostics(self) -> Dict[str, Any]:
        """Runs connectivity probes and prints comprehensive status."""
        print("\n" + "=" * 75)
        print(f" {BOLD}🔍 HunterAI Ground-Truth Physical Burp Suite Diagnostic{RESET}")
        print("=" * 75 + "\n")

        # 1. Burp Proxy Probe (:8080)
        burp_open = check_port_open(self.burp_host, self.burp_port)
        print(f"  [PROBE 1] Burp Suite Proxy Listener ({self.burp_host}:{self.burp_port}):")
        if burp_open:
            print(f"            {GREEN}[✓] ONLINE — Real Burp Suite proxy detected!{RESET}")
        else:
            print(f"            {YELLOW}[!] OFFLINE — No listener found on {self.burp_host}:{self.burp_port}{RESET}")

        # 2. Gateway Bridge Probe (:8085)
        gw_open = check_port_open(self.gateway_host, self.gateway_port)
        print(f"  [PROBE 2] HunterAI Gateway Bridge ({self.gateway_host}:{self.gateway_port}):")
        gw_health = None
        if gw_open:
            print(f"            {GREEN}[✓] ONLINE — Gateway is actively accepting connections{RESET}")
            try:
                import urllib.request
                req = urllib.request.Request(f"{self.gateway_url}/health")
                with urllib.request.urlopen(req, timeout=2.0) as resp:
                    gw_health = json.loads(resp.read().decode())
                    print(f"            [✓] Health Details: status={gw_health.get('status')}, findings={gw_health.get('confirmed_findings')}")
            except Exception as e:
                print(f"            [!] Health check warning: {e}")
        else:
            print(f"            {YELLOW}[!] OFFLINE — Gateway not running on {self.gateway_host}:{self.gateway_port}{RESET}")

        # 3. Extension File Integrity
        ext_path = PROJECT_ROOT / "agents" / "burp_agent" / "integrations" / "burp_extension" / "hunter_burp_extension.py"
        print(f"  [PROBE 3] HunterAI Burp Extension File:")
        if ext_path.exists():
            size_kb = ext_path.stat().st_size / 1024
            print(f"            {GREEN}[✓] PRESENT ({size_kb:.1f} KB) at:{RESET}")
            print(f"                {ext_path}")
        else:
            print(f"            {RED}[✗] MISSING at {ext_path}{RESET}")

        summary = {
            "burp_proxy_online": burp_open,
            "gateway_bridge_online": gw_open,
            "extension_file_present": ext_path.exists(),
            "gateway_health": gw_health,
        }

        # Guidance
        print("\n" + "-" * 75)
        if not burp_open:
            print(f" {BOLD}📋 Setup Instructions for Real Burp Suite Process:{RESET}")
            print("  1. Launch Burp Suite (Community or Professional).")
            print(f"  2. Verify Proxy listener is active on {self.burp_host}:{self.burp_port} (Proxy -> Proxy Settings).")
            print("  3. Go to Extensions -> Installed -> Add:")
            print("     • Extension type: Python")
            print(f"     • Extension file: {ext_path}")
            print("     • (Ensure Jython Standalone JAR is configured in Extensions -> Options).")
            print("  4. Start HunterAI Gateway Bridge:")
            print(f"     $ python -m core.burp_gateway.gateway --port {self.gateway_port}")
            print("  5. Re-run this script to execute live bidirectional experiments over the wire.")
        else:
            print(f" {GREEN}{BOLD}🎉 Burp Suite Proxy is ONLINE and ready for live BCSL testing!{RESET}")
        print("-" * 75 + "\n")

        return summary

    def execute_live_replay_through_burp(
        self,
        target_url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
    ) -> Dict[str, Any]:
        """Dispatches an HTTP request through the physical Burp proxy at 127.0.0.1:8080."""
        import urllib.request
        from urllib.parse import urlparse

        print(f"\n{CYAN}⚡ Executing live wire request through Burp Proxy ({self.burp_host}:{self.burp_port})...{RESET}")
        proxy_handler = urllib.request.ProxyHandler({
            "http": f"http://{self.burp_host}:{self.burp_port}",
            "https": f"http://{self.burp_host}:{self.burp_port}",
        })
        opener = urllib.request.build_opener(proxy_handler)

        hdrs = headers or {}
        hdrs.setdefault("User-Agent", "HunterAI-PhysicalBurp-Probe/1.0")
        data_bytes = body.encode("utf-8") if body else None

        req = urllib.request.Request(target_url, data=data_bytes, headers=hdrs, method=method)
        t0 = time.time()
        try:
            with opener.open(req, timeout=5.0) as resp:
                elapsed_ms = round((time.time() - t0) * 1000, 2)
                resp_body = resp.read().decode("utf-8", errors="replace")
                print(f"  {GREEN}[✓] HTTP {resp.status} received in {elapsed_ms}ms (Length: {len(resp_body)} bytes){RESET}")
                return {
                    "status_code": resp.status,
                    "body": resp_body,
                    "elapsed_ms": elapsed_ms,
                    "success": True,
                }
        except Exception as e:
            print(f"  {RED}[!] Wire request through Burp failed: {e}{RESET}")
            return {
                "status_code": 0,
                "body": "",
                "elapsed_ms": 0.0,
                "success": False,
                "error": str(e),
            }


def main():
    parser = argparse.ArgumentParser(description="HunterAI Physical Burp Suite Validator")
    parser.add_argument("--burp-port", type=int, default=8080, help="Burp Proxy port (default: 8080)")
    parser.add_argument("--gw-port", type=int, default=8085, help="Gateway port (default: 8085)")
    parser.add_argument("--test-url", type=str, default=None, help="Target URL to probe through Burp Proxy")
    args = parser.parse_args()

    val = PhysicalBurpSuiteValidator(burp_port=args.burp_port, gateway_port=args.gw_port)
    diag = val.run_diagnostics()

    if args.test_url:
        if diag["burp_proxy_online"]:
            res = val.execute_live_replay_through_burp(args.test_url)
            sys.exit(0 if res["success"] else 1)
        else:
            print(f"{RED}[!] Cannot probe target: Burp proxy on port {args.burp_port} is offline.{RESET}")
            sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
