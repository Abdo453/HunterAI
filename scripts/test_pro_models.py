#!/usr/bin/env python3
"""
Test & Verify Specialized Local Models in Ollama
"""
import json
import urllib.request
import subprocess
import time

TESTS = [
    {
        "model": "qwen3-deep:8b",
        "name_ar": "المفكر العميق (qwen3-deep:8b)",
        "prompt": "ما هي المنهجية الاستراتيجية لتحليل مسار هجوم إلكتروني معقد باستخدام MITRE ATT&CK و Grill-Me؟ أجب في فقرة تحليلية مكثفة.",
        "role": "الاستدلال المنطقي والتهديدات الاستراتيجية"
    },
    {
        "model": "qwen-dialogue:8b",
        "name_ar": "المحاور وموجه المتصفح (qwen-dialogue:8b)",
        "prompt": "كيف تدير عملية استكشاف الويب والزحف الذكي عبر المتصفح الآلي (agent-browser) لكشف الأسطح الخفية؟ أجب بفصاحة وإيجاز.",
        "role": "قيادة المتصفح والاستكشاف المعرفي"
    },
    {
        "model": "wrn-forensics:8b",
        "name_ar": "خبير الثغرات و CVEs (wrn-forensics:8b)",
        "prompt": "Explain how to identify vulnerable Active Directory Certificate Services (ADCS) templates and correlated network CVEs concisely.",
        "role": "فحص الخدمات والثغرات المعروفة"
    },
    {
        "model": "qwen-coder-pro:14b",
        "name_ar": "كبير مهندسي البرمجيات (qwen-coder-pro:14b)",
        "prompt": "اشرح في نقاط سريعة كيف تضمن كتابة كود برمجى 'Zero Defects' عالي الأمان والأداء ومطابق لمعايير TDD في الأنظمة الحساسة.",
        "role": "هندسة البرمجيات والأكواد النظيفة"
    },
    {
        "model": "xploiter-chains:latest",
        "name_ar": "خبير سلاسل الاستغلال (xploiter-chains:latest)",
        "prompt": "How do you chain an IDOR information disclosure with a privilege escalation vulnerability into a complete compromise path?",
        "role": "بناء سلاسل الاستغلال المتقدمة"
    },
    {
        "model": "redteam-pro:8b",
        "name_ar": "قائد صيد الثغرات والفريق الأحمر (redteam-pro:8b)",
        "prompt": "ما هي المبادئ الأساسية لبوابة الأسئلة السبعة (7-Question Gate) وتقنيات فحص الـ APIs و WAF Bypass في Bug Bounty؟ أجب باحترافية.",
        "role": "منهجية صيد الثغرات ومراقبة الترافيك"
    }
]

def get_ollama_base_url() -> str:
    import os
    from pathlib import Path
    host = os.getenv("OLLAMA_HOST")
    if host:
        if not host.startswith("http"):
            host = f"http://{host}"
        return host.rstrip("/")

    try:
        with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=1):
            return "http://127.0.0.1:11434"
    except Exception:
        pass

    try:
        import platform, subprocess
        if "microsoft" in platform.release().lower() or Path("/proc/version").exists():
            out = subprocess.check_output(["ip", "route", "show", "default"], text=True, timeout=2)
            parts = out.split()
            if "via" in parts:
                gw = parts[parts.index("via") + 1]
                gw_url = f"http://{gw}:11434"
                with urllib.request.urlopen(f"{gw_url}/api/tags", timeout=2):
                    return gw_url
    except Exception:
        pass

    return "http://127.0.0.1:11434"

def unload_model(base_url: str, model: str):
    try:
        req = urllib.request.Request(
            f"{base_url}/api/generate",
            data=json.dumps({"model": model, "keep_alive": 0}).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        try:
            subprocess.run(["ollama", "stop", model], capture_output=True)
        except Exception:
            pass

def query_model(model_info):
    model = model_info["model"]
    base_url = get_ollama_base_url()
    print(f"\n🚀 جاري اختبار: {model_info['name_ar']} ({model_info['role']})...")
    print(f"   الخادم النشط: {base_url}")
    
    url = f"{base_url}/api/generate"
    payload = json.dumps({
        "model": model,
        "prompt": model_info["prompt"],
        "stream": False,
        "options": {"num_ctx": 2048, "temperature": 0.5}
    }).encode("utf-8")
    
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    try:
        t0 = time.time()
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            elapsed = time.time() - t0
            response_text = data.get("response", "").strip()
            print(f"⏱️ زمن الاستجابة: {elapsed:.1f} ثانية")
            print(f"📝 الرد:\n{response_text[:350]}...\n")
            return {"status": "SUCCESS", "elapsed": elapsed, "response": response_text}
    except Exception as e:
        print(f"❌ خطأ أثناء الاختبار: {e}")
        return {"status": "ERROR", "error": str(e)}
    finally:
        # تفريغ الموديل من كارت الشاشة لتوفير VRAM للموديل التالي
        unload_model(base_url, model)

if __name__ == "__main__":
    results = {}
    for test in TESTS:
        res = query_model(test)
        results[test["model"]] = res
        time.sleep(2)
        
    with open("scripts/test_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print("✅ اكتملت الاختبارات وتم حفظ النتائج.")
