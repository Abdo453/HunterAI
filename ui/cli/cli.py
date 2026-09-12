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
    if RICH:
        t = Table(title=f"PentestAI Results ({len(findings)} Confirmed Findings)", border_style="red")
        t.add_column("Severity", justify="center")
        t.add_column("Vulnerability Title")
        t.add_column("Target Param / Path")
        t.add_column("Engine / Fallback")
        t.add_column("Evidence Summary")
        for f in findings:
            sev = f.get("severity", "Info")
            c = {"Critical": "red", "High": "orange1", "Medium": "yellow", "Low": "green"}.get(sev, "white")
            tool_str = f.get("tool", "")
            if f.get("fallback_used"):
                tool_str += f" (⚙️ {f.get('fallback_engine')})"
            evidence_str = str(f.get("evidence", ""))[:60].replace("\n", " ")
            t.add_row(
                f"[{c}]{sev}[/{c}]",
                f.get("title", ""),
                str(f.get("param_name") or f.get("endpoint") or "-"),
                tool_str,
                evidence_str,
            )
        console.print(t)
    else:
        print(f"\nDone! Total Findings: {len(findings)}")
        for f in findings:
            fb = f" [Fallback: {f.get('fallback_engine')}]" if f.get("fallback_used") else ""
            print(f"  [{f.get('severity')}] {f.get('title')} | param={f.get('param_name')}{fb} | tool={f.get('tool')}")

    return result

def main():
    parser = argparse.ArgumentParser(description="PentestAI Unified CLI")
    parser.add_argument("target", help="Target URL or domain")
    parser.add_argument("-m", "--mode", default="full", choices=["recon", "web", "full", "ctf"], help="Scanning mode")
    parser.add_argument("-b", "--browser", action="store_true", help="Enable browser agent")
    parser.add_argument("-p", "--proxy", default=None, help="Proxy URL")
    parser.add_argument("--max-concurrent", type=int, default=8, help="Maximum concurrent probes")
    parser.add_argument("--output", choices=["json", "html", "csv"], default="json", help="Report output format")
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
    from core.exporters import export_json, export_html, export_csv
    reports_dir = os.path.abspath(os.path.join("reports"))
    os.makedirs(reports_dir, exist_ok=True)
    if args.output == "json":
        export_json(findings, os.path.join(reports_dir, "scan.json"))
    elif args.output == "html":
        export_html(findings, os.path.join(reports_dir, "scan.html"))
    elif args.output == "csv":
        export_csv(findings, os.path.join(reports_dir, "scan.csv"))

if __name__ == "__main__":
    main()
