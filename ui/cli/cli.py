# CLI — Rich Terminal Interface
import argparse, json, csv, os
import asyncio, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    # Disable Rich on Windows consoles with limited codepages (e.g., cp1256)
    if sys.platform.startswith('win') and sys.stdout.encoding and sys.stdout.encoding.lower().startswith('cp'):
        RICH = False
    else:
        RICH = True
except ImportError:
    RICH = False

console = Console() if RICH else None

BANNER = """
██████╗ ███████╗███╗   ██╗████████╗███████╗███████╗████████╗ █████╗ ██╗
██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔══██╗██║
██████╔╝█████╗  ██╔██╗ ██║   ██║   █████╗  ███████╗   ██║   ███████║██║
██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══╝  ╚════██║   ██║   ██╔══██║██║
██║     ███████╗██║ ╚████║   ██║   ███████╗███████║   ██║   ██║  ██║██║
╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝
                    UNIFIED  v1.0  🔥  Multi-Model AI Pentest
"""

async def run_scan(target: str, mode: str = "web", browser: bool = False, proxy: str = None, max_concurrent: int = 8):
    from core.brain.autonomous_brain import AutonomousBrain
    from tools.tool_manager import ToolManager
    try:
        from orchestrator.resource_manager import ResourceManager
    except ImportError:
        from core.resource_manager import ResourceManager

    tools = ToolManager()
    try:
        from models.ollama_manager import OllamaManager
        ollama_mgr = OllamaManager()
    except Exception:
        ollama_mgr = None
    res_mgr = ResourceManager(ollama_manager=ollama_mgr)

    async def cb(ev):
        e = ev.get("event", "")
        if e == "phase":
            msg = ev.get("message") or ev.get("phase", "")
            # Remove non‑ASCII characters to avoid console encoding errors on Windows
            safe_msg = msg.encode("ascii", errors="ignore").decode()
            if RICH:
                console.print(f"[bold cyan]▶ [{e.upper()}][/bold cyan] {msg}")
            else:
                print(f"> [{e.upper()}] {safe_msg}")
        elif e == "finding":
            title = ev.get("title", "Finding")
            sev = ev.get("severity", "Info")
            color = {"Critical": "bold red", "High": "orange1", "Medium": "yellow", "Low": "green"}.get(sev, "white")
            if RICH:
                console.print(f"  [{color}]🔥 [{sev.upper()}][/] {title}")
            else:
                print(f"  * [{sev.upper()}] {title}")
        elif e == "log":
            msg = ev.get("message", "")
            # Remove non‑ASCII characters to avoid console encoding errors on Windows
            safe_msg = msg.encode("ascii", errors="ignore").decode()
            if RICH:
                console.print(f"  [dim]{safe_msg}[/dim]")
            else:
                print(f"  {safe_msg}")

    brain = AutonomousBrain(
        resource_manager=res_mgr,
        tool_manager=tools,
        progress_callback=cb
    )
    # Set concurrency on the brain (will be used by VulnerabilityEngine)
    brain.max_concurrent = max_concurrent

    if RICH:
        console.rule(f"[red]🎯 {target} | {mode}[/red]")
        result = await brain.run_scan(target=target, mode=mode, use_browser=browser, proxy=proxy)
    else:
        print(f"\nScanning: {target} [{mode}]")
        result = await brain.run_scan(target=target, mode=mode, use_browser=browser, proxy=proxy)

    findings = result.get("findings", [])
    code_intel = result.get("code_intelligence", {})
    manifest = code_intel.get("manifest", {})

    browser_exp = result.get("browser_exploration", {})
    b_manifest = browser_exp.get("manifest", {})

    if RICH:
        if b_manifest:
            b_summary = (
                f"[bold blue]Human-Like Stateful Exploration:[/bold blue]\n"
                f"• Pages Explored: [bold]{b_manifest.get('pages_visited', 0)}[/bold] | Stop Reason: [yellow]{b_manifest.get('stop_reason', 'N/A')}[/yellow]\n"
                f"• Application States Discovered: [green]{b_manifest.get('states_discovered', 0)}[/green]\n"
                f"• API Endpoints Intercepted: [cyan]{b_manifest.get('api_endpoints', 0)}[/cyan]\n"
                f"• Live Network Requests Recorded: [magenta]{b_manifest.get('network_requests', 0)}[/magenta]\n"
                f"• Scope Firewall: [bold green]Active (Zero Out-of-Scope Probes)[/bold green]"
            )
            console.print(Panel(b_summary, title="🌐 Browser Sensor & Application Explorer", border_style="blue"))

        if manifest:
            techs = ", ".join(manifest.get("technologies", [])) or "None detected"
            summary_text = (
                f"[bold cyan]Client-Side Code & API Inventory:[/bold cyan]\n"
                f"• Detected Technologies: [bold]{techs}[/bold]\n"
                f"• JavaScript Bundles Analyzed: [yellow]{manifest.get('js_analyzed', 0)}[/yellow]\n"
                f"• In-Scope Endpoints Discovered: [green]{manifest.get('endpoints_discovered', 0)}[/green]\n"
                f"• Validated Hardcoded Secrets: [red]{manifest.get('secrets_discovered', 0)}[/red]"
            )
            console.print(Panel(summary_text, title="🧠 Code Intelligence Summary", border_style="cyan"))

        t = Table(title=f"PentestAI Results ({len(findings)} Findings Adjudicated)", border_style="red")
        t.add_column("Verdict", justify="center")
        t.add_column("Severity", justify="center")
        t.add_column("Vulnerability Title")
        t.add_column("Target Param / Path")
        t.add_column("Engine / Fallback")
        t.add_column("Evidence Summary")
        for f in findings:
            sev = f.get("severity", "Info")
            c = {"Critical": "red", "High": "orange1", "Medium": "yellow", "Low": "green"}.get(sev, "white")
            verdict = f.get("lifecycle_verdict", "CONFIRMED")
            vc = "bold green" if verdict == "CONFIRMED" else "bold yellow"
            tool_str = f.get("tool", "")
            if f.get("fallback_used"):
                tool_str += f" (⚙️ {f.get('fallback_engine')})"
            evidence_str = str(f.get("evidence", ""))[:60].replace("\n", " ")
            t.add_row(
                f"[{vc}]{verdict}[/{vc}]",
                f"[{c}]{sev}[/{c}]",
                f.get("title", ""),
                str(f.get("param_name") or f.get("endpoint") or "-"),
                tool_str,
                evidence_str,
            )
        console.print(t)
    else:
        if manifest:
            print(f"\n--- Code Intelligence Summary ---")
            print(f"  Technologies: {', '.join(manifest.get('technologies', []))}")
            print(f"  JS Analyzed: {manifest.get('js_analyzed', 0)} | Endpoints: {manifest.get('endpoints_discovered', 0)} | Secrets: {manifest.get('secrets_discovered', 0)}")
        print(f"\nDone! Total Findings: {len(findings)}")
        for f in findings:
            fb = f" [Fallback: {f.get('fallback_engine')}]" if f.get("fallback_used") else ""
            verdict = f.get("lifecycle_verdict", "CONFIRMED")
            print(f"  [{verdict}] [{f.get('severity')}] {f.get('title')} | param={f.get('param_name')}{fb} | tool={f.get('tool')}")

    return result

def main():
    parser = argparse.ArgumentParser(description="PentestAI Unified CLI")
    parser.add_argument("target", help="Target URL or domain")
    parser.add_argument("-m", "--mode", default="full", choices=["recon", "web", "full", "ctf"], help="Scanning mode")
    parser.add_argument("-b", "--browser", action="store_true", help="Enable browser agent")
    parser.add_argument("-p", "--proxy", default=None, help="Proxy URL")
    parser.add_argument("--max-concurrent", type=int, default=8, help="Maximum concurrent probes")
    parser.add_argument("--output", choices=["json", "html", "csv", "dashboard"], default="dashboard", help="Report output format")
    args = parser.parse_args()

    if RICH:
        console.print(Panel(Text(BANNER, style="bold red"), border_style="red"))
    else:
        # Simple ASCII banner to avoid encoding errors on Windows consoles with non‑UTF‑8 codepages
        print("PentestAI Unified CLI")

    findings_result = asyncio.run(run_scan(
        args.target,
        mode=args.mode,
        browser=args.browser,
        proxy=args.proxy,
        max_concurrent=args.max_concurrent,
    ))
    findings = findings_result.get("findings", [])
    # Export reports
    from core.exporters import export_json, export_html, export_csv, export_interactive_dashboard
    reports_dir = os.path.abspath(os.path.join("reports"))
    os.makedirs(reports_dir, exist_ok=True)
    if args.output == "json":
        export_json(findings, os.path.join(reports_dir, "scan.json"))
    elif args.output == "html":
        export_html(findings, os.path.join(reports_dir, "scan.html"))
    elif args.output == "csv":
        export_csv(findings, os.path.join(reports_dir, "scan.csv"))
    elif args.output == "dashboard":
        export_interactive_dashboard(args.target, findings_result, os.path.join(reports_dir, "dashboard.html"))

    # Always generate interactive dashboard for visual review
    dashboard_file = os.path.join(reports_dir, "dashboard.html")
    export_interactive_dashboard(args.target, findings_result, dashboard_file)
    if RICH:
        console.print(f"[bold green]📊 Interactive Dashboard exported to: {dashboard_file}[/bold green]")
    else:
        print(f"Interactive Dashboard exported to: {dashboard_file}")

if __name__ == "__main__":
    main()
