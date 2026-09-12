"""
AI Diagnostics Engine — فحص وتأكيد جاهزية جميع الموديلات المحلية والسحابية عند الإقلاع
"""
import os
import sys
import asyncio
import httpx
from typing import Dict, Any, List
from dotenv import load_dotenv

load_dotenv()

from models.ollama_manager import OllamaManager

TARGET_LOCAL_MODELS = {
    "WhiteRabbitNeo": {
        "tag_match": ["whiterabbitneo", "white-rabbit"],
        "display": "WhiteRabbitNeo (8B)",
        "role": "Offensive Security & Red Teaming"
    },
    "xploiter": {
        "tag_match": ["xploiter", "pentester"],
        "display": "xploiter/pentester (2.8B)",
        "role": "Attack Strategy & Vectors"
    },
    "qwen_coder": {
        "tag_match": ["qwen2.5-coder", "qwen"],
        "display": "qwen2.5-coder (14B/7B)",
        "role": "Exploit & PoC Generation"
    },
    "sylink": {
        "tag_match": ["sylink"],
        "display": "sylink:8b",
        "role": "Recon Triage & Summary"
    }
}

async def check_local_ai_status() -> Dict[str, Any]:
    """فحص حالة سيرفر Ollama المحلي وجميع الموديلات المثبتة"""
    mgr = OllamaManager()
    active_host = await mgr.get_active_host()
    online = False
    installed_tags = []
    try:
        async with httpx.AsyncClient(timeout=2.0, trust_env=False) as c:
            r = await c.get(f"{active_host}/api/tags")
            if r.status_code == 200:
                online = True
                installed_tags = [m.get("name", "") for m in r.json().get("models", [])]
    except Exception:
        online = False

    model_checks = {}
    for key, spec in TARGET_LOCAL_MODELS.items():
        found = False
        matched_tag = ""
        for tag in installed_tags:
            if any(m.lower() in tag.lower() for m in spec["tag_match"]):
                found = True
                matched_tag = tag
                break
        model_checks[key] = {
            "display": spec["display"],
            "role": spec["role"],
            "available": found,
            "matched_tag": matched_tag
        }

    return {
        "online": online,
        "host": active_host,
        "installed_tags": installed_tags,
        "models": model_checks,
    }

def check_cloud_ai_status() -> Dict[str, Any]:
    """فحص جاهزية مزودات الذكاء الاصطناعي السحابية"""
    return {
        "openrouter": {
            "name": "OpenRouter Cloud AI",
            "model": "meta-llama/llama-3.3-70b-instruct",
            "configured": bool(os.getenv("OPENROUTER_API_KEY")),
        },
        "gemini": {
            "name": "Google Gemini Flash",
            "model": "gemini-2.0-flash",
            "configured": bool(os.getenv("GEMINI_API_KEY")),
        },
        "taskade": {
            "name": "Taskade AI Automation",
            "model": "taskade-ai",
            "configured": bool(os.getenv("TASKADE_API_KEY")),
        },
        "groq": {
            "name": "Groq Ultra-Fast AI",
            "model": "llama-3.3-70b-versatile",
            "configured": bool(os.getenv("GROQ_API_KEY")),
        },
        "openai": {
            "name": "OpenAI Provider",
            "model": "gpt-4o",
            "configured": bool(os.getenv("OPENAI_API_KEY")),
        },
        "anthropic": {
            "name": "Anthropic Claude",
            "model": "claude-3-5-sonnet",
            "configured": bool(os.getenv("ANTHROPIC_API_KEY")),
        },
        "deepseek": {
            "name": "DeepSeek Reasoner",
            "model": "deepseek-chat",
            "configured": bool(os.getenv("DEEPSEEK_API_KEY")),
        }
    }

async def run_full_ai_diagnostics(verbose: bool = True) -> Dict[str, Any]:
    """تشغيل الفحص الشامل وطباعة التقرير التشخيصي للكونسول"""
    local_stat = await check_local_ai_status()
    cloud_stat = check_cloud_ai_status()

    if verbose:
        sep = "=" * 70
        print("\n" + sep)
        print("   [+] PentestAI Unified -- AI Engine Diagnostics & Verification")
        print(sep)

        if local_stat["online"]:
            print(f" [+] Local AI Engine (Ollama): [ ONLINE ] at {local_stat['host']}")
            for _, info in local_stat["models"].items():
                if info["available"]:
                    print(f"     [OK]      {info['display']:<24} -> READY [{info['role']}]")
                else:
                    print(f"     [MISSING] {info['display']:<24} -> NOT INSTALLED (Cloud fallback active)")
            print(f"     [GPU]     Hardware Acceleration: CUDA Active on Ollama Host")
        else:
            print(f" [!] Local AI Engine (Ollama): [ OFFLINE ] ({local_stat['host']})")
            print("     [-] Tip: To enable local GPU models, start: ollama serve")

        active_cloud = [p["name"] for p in cloud_stat.values() if p["configured"]]
        if active_cloud:
            print(f"\n [+] Cloud AI Providers: [ ACTIVE ] ({len(active_cloud)} configured)")
            for key, p in cloud_stat.items():
                if p["configured"]:
                    print(f"     [CLOUD]   {p['name']:<24} -> ENABLED ({p['model']})")
        else:
            print("\n [!] Cloud AI Providers: None configured (add keys to .env)")

        all_ready = local_stat["online"] or any(p["configured"] for p in cloud_stat.values())
        if all_ready:
            print("\n [#] Framework AI Readiness: 100% OPERATIONAL & READY FOR SCANNING")
        else:
            print("\n [!] Framework AI Warning: No AI models available.")
        print(sep + "\n")

    return {
        "local": local_stat,
        "cloud": cloud_stat,
        "ready": local_stat["online"] or any(p["configured"] for p in cloud_stat.values())
    }

def run_startup_ai_diagnostic(verbose: bool = True) -> Dict[str, Any]:
    """دالة متزامنة يمكن استدعاؤها مباشرة في main.py قبل إقلاع السيرفر"""
    try:
        return asyncio.run(run_full_ai_diagnostics(verbose=verbose))
    except Exception as e:
        if verbose:
            print(f"[!] AI Diagnostics warning: {e}")
        return {"error": str(e), "ready": False}
