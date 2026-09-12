#!/usr/bin/env python3
"""
HunterAI Agentic Scaffolding Mission Launcher
=============================================
Runs an autonomous security research mission using the Claude-style Agent Scaffolding:
- Persistent Working Memory (.agent/)
- Hierarchical Hypothesis Tree
- MCP-style Tool Registry
- Skeptical Self-Critique Validator (zero false positives)
- Differential analysis & dynamic adaptive testing
"""
import sys
import os
import asyncio
import argparse
from pathlib import Path

# Ensure project root is in sys.path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir))

# Fix Windows Unicode encoding
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"

from hunter_ai.runtime import AgentRuntime


async def main():
    parser = argparse.ArgumentParser(description="HunterAI Agentic Scaffolding Launcher")
    parser.add_argument("target", help="Target URL to assess (e.g. http://example.com/item?id=1)")
    parser.add_argument("--params", "-p", nargs="+", help="Specific parameter names to focus on (e.g. -p id category user)")
    parser.add_argument("--max-steps", "-s", type=int, default=15, help="Maximum number of autonomous steps (default: 15)")
    parser.add_argument("--agent-dir", default=".agent", help="Directory for persistent working memory (default: .agent)")
    args = parser.parse_args()

    print("=" * 70)
    print(" 🚀 HunterAI Autonomous Agentic Scaffolding Runtime")
    print("=" * 70)
    print(f" Target Endpoint:   {args.target}")
    print(f" Focus Parameters:  {args.params or 'Auto-discover'}")
    print(f" Max Steps Budget:  {args.max_steps}")
    print(f" Working Memory:    {args.agent_dir}/")
    print("=" * 70 + "\n")

    async def on_event(ev: dict):
        event_name = ev.get("event")
        if event_name == "step_start":
            print(f"[*] [Step {ev.get('step')}] Testing hypothesis {ev.get('hypothesis_id')} ({ev.get('category')}) [Confidence: {ev.get('confidence')}]")
        elif event_name == "finding_confirmed":
            print(f"\n🎯 [!] VULNERABILITY CONFIRMED: {ev.get('vulnerability')} on param '{ev.get('parameter')}'")
            print(f"    Confidence: {ev.get('confidence')}")
            print(f"    Reasoning:  {ev.get('reasoning')}\n")

    runtime = AgentRuntime(
        agent_dir=args.agent_dir,
        event_callback=on_event
    )

    result = await runtime.run_mission(
        target_url=args.target,
        initial_params=args.params,
        max_steps=args.max_steps
    )

    print("\n" + "=" * 70)
    print(" 📋 MISSION SUMMARY")
    print("=" * 70)
    print(f" Status:          {result['status']}")
    print(f" Duration:        {result['duration_seconds']}s")
    print(f" Steps Executed:  {result['steps_executed']}")
    print(f" Total Hypotheses:{result['hypotheses_tested']}")
    print(f" Verified Findings:{result['findings_count']}")
    print("=" * 70)

    if result['findings']:
        print("\nVerified Findings:")
        for idx, f in enumerate(result['findings'], 1):
            print(f"  {idx}. [{f.get('vulnerability')}] Endpoint: {f.get('endpoint')} (param: {f.get('parameter')})")
            print(f"     Confidence: {f.get('confidence')}")
            print(f"     Reasoning:  {f.get('reasoning')}")
    else:
        print("\nNo verified vulnerabilities found. Check `.agent/failed_tests.json` for details.")

    # Mission DNA Output
    dna = result.get("mission_dna", {})
    if dna:
        cov = dna.get("coverage_metrics", {})
        nba = dna.get("next_best_action", {})
        print("\n" + "-" * 70)
        print(" 🧬 SROS MISSION DNA & AUTONOMOUS REASONING")
        print("-" * 70)
        print(f" Endpoint Coverage: {cov.get('endpoint_coverage_pct', 0)}% (Tested: {cov.get('total_tested_endpoints', 0)}/{cov.get('total_discovered_endpoints', 0)})")
        print(f" Parameter Coverage:{cov.get('param_coverage_pct', 0)}%")
        print(f" Dead Zones Left:   {cov.get('dead_zones_count', 0)}")
        print(f" Next Best Action:  [{nba.get('action_kind')}] -> {nba.get('rationale')}")
        print("-" * 70)


if __name__ == "__main__":
    asyncio.run(main())
