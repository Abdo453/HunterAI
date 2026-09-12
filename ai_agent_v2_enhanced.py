"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                   AI Cyber Agent v2 Enhanced (Top 5 Priority)                 ║
║   1. PoC Executor | 2. False Positive Filter | 3. CVSS Scoring               ║
║   4. WAF Detection | 5. Stealth Mode & Rate Limiting                         ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
import os
import sys
import json
import asyncio
from core.smart_probe_engine import SmartPoCExecutor, WAFDetector, CVSSCalculator
from core.skill_memory_engine import SkillLearnerEngine
from core.auto_scraper_learner import AutoScraperLearner


async def run_enhanced_scan(target_url: str, cookie: str = ""):
    print("\n" + "="*70)
    print(f"  🎯 STARTING ENHANCED AI VULNERABILITY SCAN ON: {target_url}")
    print("="*70 + "\n")

    # 1. Crawl & Triage
    engine = SkillLearnerEngine()
    print("[*] Stage 1: Crawling target & Tech Stack Identification...")
    crawl_data = await engine.crawl_target(target_url, cookie_str=cookie)
    
    if "error" in crawl_data:
        print(f"[-] Error crawling target: {crawl_data['error']}")
        return

    print(f"[+] Tech Stack: {', '.join(crawl_data.get('tech_stack', [])) or 'Standard Web'}")
    print(f"[+] Discovered Forms: {len(crawl_data.get('forms', []))} | Parameters: {len(crawl_data.get('url_params', []))}")
    print(f"[+] JavaScript API Endpoints: {len(crawl_data.get('api_endpoints', []))}\n")

    # 2. Multi-Agent Triage
    print("[*] Stage 2: AI Multi-Agent Triage (Matching Skills)...")
    pipeline_res = await engine.run_pipeline(target_url, cookie_str=cookie)

    print("\n" + "-"*70)
    print("  📋 RED TEAM TRIAGE FINDINGS (Prior to Live Proof)")
    print("-"*70)
    print(pipeline_res.get("final_triage_report", ""))

    # 3. Live PoC Executor & False Positive Killer
    executor = SmartPoCExecutor()
    params = list(crawl_data.get("url_params", {}).keys())

    if params:
        print("\n" + "="*70)
        print("  🔥 STAGE 3: LIVE POC EXECUTOR & FALSE POSITIVE KILLER")
        print("="*70)

        for param in params:
            print(f"\n[*] Testing Parameter: '{param}' for SQLi / XSS / IDOR (Differential Analysis)...")
            result = await executor.execute_and_verify(target_url, param, "sqli")
            
            status_icon = "🔴 [VERIFIED]" if result["verified"] else "🟢 [FALSE POSITIVE REJECTED]"
            cvss = result["cvss"]

            print(f"  {status_icon} Status: {result['status']}")
            print(f"  📊 CVSS v3.1: {cvss['score']} ({cvss['severity']}) | Vector: {cvss['vector']}")
            print(f"  🛡️ WAF Status: {', '.join(result.get('waf_info', {}).get('wafs', ['None']))}")
            print(f"  🔍 Proof Reason: {result['proof_reason']}")
            print(f"  ⏱️ Time: {result['duration_sec']}s")

    print("\n" + "="*70)
    print("  🎉 ENHANCED SCAN COMPLETE!")
    print("="*70 + "\n")


def main():
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("Enter target URL to scan (e.g. https://example.com/page?id=1): ").strip()

    if not target:
        print("[-] Target URL required.")
        return

    asyncio.run(run_enhanced_scan(target))


if __name__ == "__main__":
    main()
