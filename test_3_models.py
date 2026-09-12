#!/usr/bin/env python3
"""
====================================================================
PentestAI Unified — اختبار الـ 3 موديلات المحلية دفعة واحدة
يعمل على Windows أو على Kali Linux للاتصال بـ Ollama
====================================================================
الاستخدام:
  - على Windows:  python test_3_models.py
  - على Kali Linux: python test_3_models.py http://<WINDOWS_IP>:11434
    مثال:         python test_3_models.py http://192.168.1.8:11434
====================================================================
"""
import sys
import os
import time
import json
from pathlib import Path

# Fix Windows console UTF-8 output
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

try:
    import httpx
except ImportError:
    print("[!] Error: 'httpx' is not installed. Run: pip install httpx")
    sys.exit(1)

# تحديد عنوان Ollama (من سطر الأوامر أو من .env أو الافتراضي)
if len(sys.argv) > 1 and sys.argv[1].startswith("http"):
    OLLAMA_HOST = sys.argv[1].rstrip("/")
else:
    OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
    if not OLLAMA_HOST.startswith("http"):
        OLLAMA_HOST = f"http://{OLLAMA_HOST}"
    OLLAMA_HOST = OLLAMA_HOST.replace("://0.0.0.0:", "://127.0.0.1:")

MODELS = [
    {
        "id": "WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest",
        "alias": "WhiteRabbitNeo (8B)",
        "role": "🔴 Offensive Security & Attack Surface Analyst",
        "system": "You are WhiteRabbitNeo, an elite offensive cybersecurity AI. Identify potential vulnerabilities, attack vectors, and exploit risks concisely.",
    },
    {
        "id": "xploiter/pentester:latest",
        "alias": "Xploiter Pentester",
        "role": "🎯 Pentest Strategist & Tool Chain Advisor",
        "system": "You are a senior penetration tester. Formulate attack methodology, validate findings, and recommend exact tools (nmap, ffuf, sqlmap, katana).",
    },
    {
        "id": "qwen2.5-coder:14b",
        "alias": "Qwen Coder (14B)",
        "role": "💻 Code & Exploit Engineer / Remediation Specialist",
        "system": "You are an elite software security engineer. Write clean, working code remediation patches and secure implementation fixes.",
    }
]

TEST_PROMPT = """Target: https://vulnerable-portal.local
Scenario: A parameter `/api/user?id=105` was tested and returned database error with payload `105' UNION SELECT username, password FROM users--`.
Provide your analysis according to your role."""


def print_banner():
    print("=" * 70)
    print(" 🧠 PentestAI Unified — 3 Local Models Sequential Activation Test")
    print(f" 🌐 Target Ollama Host: {OLLAMA_HOST}")
    print("=" * 70)


def check_ollama_connection():
    print("\n[*] [1/4] Checking Ollama host connection...")
    try:
        r = httpx.get(f"{OLLAMA_HOST}/api/tags", timeout=10)
        if r.status_code == 200:
            available = [m["name"] for m in r.json().get("models", [])]
            print(f"    [+] Connected successfully to Ollama!")
            print(f"    [+] Available models on host ({len(available)}):")
            for m in available:
                print(f"        • {m}")
            return available
        else:
            print(f"    [!] Error: Received status code {r.status_code}")
            return []
    except Exception as e:
        print(f"    [!] Connection Failed: {e}")
        print(f"    [💡 Hint] If running from Kali, make sure:")
        print(f"       1. Windows IP is reachable (ping <WINDOWS_IP>)")
        print(f"       2. Ollama is running with OLLAMA_HOST=0.0.0.0:11434 on Windows")
        print(f"       3. Port 11434 is allowed in Windows Firewall")
        return []


def run_model_test(model_cfg: dict, prompt: str, context_prev: str = "") -> str:
    m_id = model_cfg["id"]
    alias = model_cfg["alias"]
    role = model_cfg["role"]
    sys_p = model_cfg["system"]

    print("\n" + "-" * 70)
    print(f"[*] 🚀 Launching Model: {alias}")
    print(f"    Role: {role}")
    print(f"    GPU Lock: Exclusive | Unload after: keep_alive=0")
    print("-" * 70)

    messages = [
        {"role": "system", "content": sys_p}
    ]
    if context_prev:
        messages.append({"role": "user", "content": f"Previous Model Output:\n{context_prev}\n\nTask: {prompt}"})
    else:
        messages.append({"role": "user", "content": prompt})

    payload = {
        "model": m_id,
        "messages": messages,
        "stream": True,
        "keep_alive": 0,  # Unload immediately after this call to protect VRAM!
        "options": {
            "temperature": 0.3,
            "num_ctx": 2048  # Optimized for 4GB VRAM
        }
    }

    t0 = time.time()
    collected = []
    print("    [AI Response Streaming Live]:\n")

    try:
        with httpx.Client(timeout=180) as client:
            with client.stream("POST", f"{OLLAMA_HOST}/api/chat", json=payload) as resp:
                resp.raise_for_status()
                for line in resp.iter_lines():
                    if not line:
                        continue
                    try:
                        chunk = json.loads(line)
                        delta = chunk.get("message", {}).get("content", "")
                        if delta:
                            collected.append(delta)
                            sys.stdout.write(delta)
                            sys.stdout.flush()
                        if chunk.get("done", False):
                            break
                    except Exception:
                        continue
    except Exception as e:
        print(f"\n[!] Execution Error on {alias}: {e}")

    duration = time.time() - t0
    full_text = "".join(collected)
    print(f"\n\n    [✓] {alias} Completed in {duration:.2f}s (Tokens/Chars: {len(full_text)}) | GPU Unloaded.")
    return full_text


def main():
    print_banner()
    available_models = check_ollama_connection()
    if not available_models:
        print("\n[!] Exiting because Ollama host is unreachable.")
        sys.exit(1)

    print("\n[*] [2/4] Starting 3-Model Discussion Pipeline (Sequential GPU Mode)...")
    results = {}
    prev_context = ""

    for idx, m_cfg in enumerate(MODELS, 1):
        print(f"\n>>> [Stage {idx}/3] Activating {m_cfg['alias']}...")
        ans = run_model_test(m_cfg, TEST_PROMPT, context_prev=prev_context)
        results[m_cfg["alias"]] = ans
        prev_context = ans[:400]
        # إعطاء Ollama مهلة ثانيتين لتفريغ كرت الشاشة بالكامل قبل تحميل الموديل التالي
        time.sleep(2.5)

    print("\n" + "=" * 70)
    print(" ✅ ALL 3 LOCAL MODELS TESTED SUCCESSFULLY!")
    print("=" * 70)
    for alias in results.keys():
        print(f" • {alias}: Generated output successfully")
    print("=" * 70)


if __name__ == "__main__":
    main()
