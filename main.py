#!/usr/bin/env python3
"""
PentestAI Unified — Entry Point

  python main.py              -> Web UI  http://localhost:7070
  python main.py --cli        -> CLI
  python main.py -t 192.168.1.1 --mode full  -> direct scan
"""
import argparse, sys, os
from pathlib import Path
from dotenv import load_dotenv

# Fix Windows Unicode encoding
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"

load_dotenv()
sys.path.insert(0, str(Path(__file__).parent))

for d in ["data/sessions","data/reports","data/wordlists","data/screenshots"]:
    Path(d).mkdir(parents=True, exist_ok=True)


def main():
    p = argparse.ArgumentParser(description="PentestAI Unified")
    p.add_argument("--web",  action="store_true")
    p.add_argument("--cli",  action="store_true")
    p.add_argument("--target", "-t")
    p.add_argument("--mode", "-m", default="full", choices=["recon","web","full","ctf","hunter","bugbounty"])
    p.add_argument("--browser", "-b", action="store_true")
    p.add_argument("--port", type=int, default=int(os.getenv("WEB_PORT","7070")))
    p.add_argument("--host", default=os.getenv("WEB_HOST", "127.0.0.1"), help="Host to bind Web UI")
    # Keep the dashboard local by default. This does not affect Burp Suite or
    # outbound scan traffic; set WEB_HOST=0.0.0.0 only for remote dashboard access.
    p.add_argument("--hunter", action="store_true", help="Launch via HunterAI Agentic Scaffolding Runtime")
    p.add_argument("--authorized", action="store_true", help="Authorize active verification and vulnerability testing")
    p.add_argument("--workflow", "-w", default=None, help="HunterAI workflow: full, recon, enum, vuln, passive, active")
    p.add_argument("--profile", default="safe", choices=["safe", "passive", "active-safe"], help="Execution profile: safe (default), passive (zero active probes), active-safe")
    p.add_argument("--scope-file", default=None, help="Path to scope.yaml or scope.json policy definition file")
    p.add_argument("--rate-limit", type=float, default=2.0, help="Per-domain token bucket rate limit in requests per second (default: 2.0 rps)")
    p.add_argument("--no-destructive-tests", action="store_true", default=True, help="Block all potentially destructive payloads (enabled by default)")
    p.add_argument("--require-human-approval", action="store_true", help="Require interactive human confirmation before executing test payloads")
    p.add_argument("--dry-run", action="store_true", help="Simulate pipeline plan without sending active network packets")
    p.add_argument("--lab-mode", "--allow-private-ips", dest="lab_mode", action="store_true", help="Allow RFC1918 private IP subnets (10.x, 172.16.x, 192.168.x) for authorized local labs")
    p.add_argument("--triad", action="store_true", help="Run with 100%% Local AI Triad (WhiteRabbitNeo + xploiter + Qwen 2.5 Coder)")
    p.add_argument("--proxy", "--burp", dest="proxy", default=None, help="Upstream HTTP/Burp Suite proxy (e.g. http://127.0.0.1:8080)")
    p.add_argument("--ask", help="Directly query the Local Triad Agent with a security question, code snippet, or target")
    p.add_argument("--max-steps", type=int, default=15, help="Max steps budget for HunterAI runtime")
    args = p.parse_args()

    if args.ask:
        import asyncio
        from hunter_ai.brain.local_triad_agent import triad_agent
        print(f"\n[*] Routing prompt through Local Triad Agent (WhiteRabbitNeo + xploiter + Qwen Coder)...")
        res = asyncio.run(triad_agent.process_prompt(args.ask))
        print(f"[*] Assigned Specialist: {res['role']}\n")
        print(res.get("response", ""))
        print("")
        return

    if args.target:
        import asyncio
        if args.hunter or args.workflow or args.mode in ("hunter", "bugbounty") or args.profile != "safe" or args.scope_file or args.triad or args.lab_mode or args.proxy:
            from hunter_ai.pipeline import HunterPipelineOrchestrator
            orch = HunterPipelineOrchestrator(
                target=args.target,
                authorized=args.authorized,
                workflow=args.workflow or "full",
                mode=args.mode,
                profile=args.profile,
                scope_file=args.scope_file,
                rate_limit_rps=args.rate_limit,
                require_human_approval=args.require_human_approval,
                no_destructive_tests=args.no_destructive_tests,
                dry_run=args.dry_run,
                use_triad=args.triad,
                allow_private_ips=args.lab_mode,
                proxy=args.proxy,
            )
            res = asyncio.run(orch.run())
            if res.get("status") == "aborted":
                print(f"\n[!] HunterAI Pipeline Aborted: {res.get('reason')} (Target: {res.get('target')})")
                return
            print(f"\n[*] HunterAI Pipeline Complete! Status: {res['status']}")
            print(f"[*] Profile: {args.profile} | Rate Limit: {args.rate_limit} rps")
            print(f"[*] Subdomains: {res['subdomains_count']} | Live Hosts: {res['live_assets_count']} | Endpoints: {res['endpoints_count']}")
            print(f"[*] Confirmed Findings: {res['findings_count']}")
            print(f"[*] Artifacts & Reports: {res['artifact_directory']}")
            if res.get("diff_md"):
                print(f"[*] Temporal Diff Report: {res['diff_md']}")
            if res.get("tool_logs"):
                print(f"[*] Tool Logs Saved ({len(res['tool_logs'])} files in data/tool_outputs/):")
                for tl in res['tool_logs'][:5]:
                    print(f"    - {tl}")
            return
        from ui.cli.cli import run_scan
        asyncio.run(run_scan(args.target, args.mode, args.browser))
        return

    if args.cli:
        from ui.cli.cli import main as cli
        cli()
        return

    # Automatic AI Engine & Local Models Diagnostic on Startup
    try:
        from core.ai_diagnostics import run_startup_ai_diagnostic
        run_startup_ai_diagnostic(verbose=True)
    except Exception as e:
        print(f"[*] AI Diagnostics notice: {e}")

    # Web UI (default)
    try:
        import uvicorn
        print(f"\n[*] PentestAI Unified - Web UI Server Starting...")
        print(f"    🟢 Dashboard URL -> http://localhost:{args.port}")
        print(f"    🟢 Remote Access -> http://{args.host}:{args.port}")
        print(f"    Taskade: {'ENABLED' if os.getenv('TASKADE_API_KEY') else 'disabled'}")
        print(f"    👉 افتح المتصفح الآن على: http://localhost:{args.port}")
        print(f"    (الخادم شغال وينتظر طلبات المتصفح - اضغط Ctrl+C للإيقاف)\n")
        uvicorn.run("ui.web.app:app", host=args.host, port=args.port,
                    reload=False, log_level="info")

    except ImportError:
        print("[!] uvicorn not found - pip install uvicorn")
        from ui.cli.cli import main as cli

        cli()


if __name__ == "__main__":
    main()
