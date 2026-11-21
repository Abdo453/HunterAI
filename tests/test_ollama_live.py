"""
اختبار الربط الحقيقي بين الـ Brain و Ollama المحلي.
يشغّل ReAct loop حقيقي على 127.0.0.1 (localhost).
"""
import asyncio
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.brain.ollama_bridge import OllamaBridge

async def main():
    print("=" * 60)
    print("🧠 World Elite Agent — Live Ollama Test")
    print("=" * 60)

    bridge = OllamaBridge()

    # 1. قائمة النماذج
    print("\n📋 Available Models:")
    models = await bridge.list_available_models()
    for m in models:
        print(f"   ✅ {m}")

    # 2. اختبار التخطيط (planner)
    print("\n💭 Testing Planner (qwen2.5-coder:14b-tools)...")
    plan = await bridge.think_and_plan(
        context="""
=== CURRENT PENTEST STATE ===
GOAL:   Find vulnerabilities in local web server
TARGET: http://127.0.0.1
PHASE:  recon (Step 1)
SCOPE:  127.0.0.1, localhost

RECENT OBSERVATIONS:
  - Target is reachable
  - No services discovered yet

FINDINGS SO FAR: 0
ASSETS FOUND:   0

What is the optimal next action?
""",
        available_tools=["port_scanner", "web_crawler", "nuclei_scan", "web_fingerprint"],
    )
    print(f"   Type:       {plan.get('type')}")
    print(f"   Confidence: {plan.get('confidence')}")
    print(f"   Tools:      {plan.get('suggested_tools')}")
    print(f"   Content:    {str(plan.get('content',''))[:120]}...")

    # 3. اختبار تحليل الثغرات (analyst)
    print("\n🔍 Testing Analyst (xploiter/pentester)...")
    analysis = await bridge.analyze_finding(
        finding="SQL injection detected in parameter 'id' at http://127.0.0.1/users?id=1' OR '1'='1",
        context="Target: http://127.0.0.1 - Educational local test environment",
    )
    print(f"   Is Real:    {analysis.get('is_real')}")
    print(f"   Severity:   {analysis.get('severity')}")
    print(f"   Confidence: {analysis.get('confidence')}")
    print(f"   CVSS:       {analysis.get('cvss_estimate')}")

    print("\n" + "=" * 60)
    print("✅ ALL SYSTEMS CONNECTED — World Elite Agent is LIVE!")
    print("=" * 60)
    print(f"\n🎯 Dual-Model Strategy Active:")
    print(f"   🧠 Planner:  qwen2.5-coder:14b-tools")
    print(f"   🔍 Analyst:  xploiter/pentester")
    print(f"   💡 Reasoner: qwen3:8b")
    print(f"   💻 Coder:    qwen2.5-coder:14b")

asyncio.run(main())
