import sys, asyncio, os
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, 'E:/Agant/PentestAI-Unified')
os.chdir('E:/Agant/PentestAI-Unified')
from dotenv import load_dotenv
load_dotenv()

from core.confidence_checker import ConfidenceChecker

async def run_confidence_test():
    async def cb(ev):
        t = ev.get('event', '')
        if t == 'model_verdict':
            icon = '+' if ev['verdict'] == 'CONFIRMED' else '-' if ev['verdict'] == 'FALSE_POSITIVE' else '?'
            name = ev["model"]
            verdict = ev["verdict"]
            conf = ev["confidence"]
            rt = ev["time"]
            print(f"  [{icon}] {name:20} {verdict:15} ({conf:.0%}) {rt:.1f}s")
        elif t == 'confidence_phase':
            ph = ev["phase"]
            msg = ev["message"]
            print(f"  [Phase {ph}] {msg}")
        elif t == 'confidence_result':
            v = ev["verdict"]
            s = ev["score"]
            a = ev["agreed"]
            d = ev["disagreed"]
            print(f"  FINAL: {v} | {s:.0%} | agreed={a} disagreed={d}")

    checker = ConfidenceChecker(progress_cb=cb)
    print('[*] Testing Confidence Checker with OpenRouter...')
    print(f'    Key: {os.getenv("OPENROUTER_API_KEY","MISSING")[:25]}...')
    print('[*] Running 5 models in parallel...\n')

    result = await checker.verify(
        claim="The application appears to potentially have SQL injection via 'id' param - needs verification",
        target="http://testphp.vulnweb.com",
        context="Response differs with and without quote: id=1 vs id=1'",
        use_browser=False
    )

    print()
    print(checker.format_report(result))

if __name__ == "__main__":
    asyncio.run(run_confidence_test())
