#!/usr/bin/env python3
"""
PentestAI Unified — Pre-Flight & Connection Verification for Kali Linux
=======================================================================
Verifies:
1. Ollama Host & Model Council Availability (WhiteRabbitNeo, xploiter, Qwen Coder)
2. Burp Suite Proxy Connectivity (127.0.0.1:8080 or custom proxy)
3. Playwright & Browser Automation Engine
4. Kali Linux Security CLI Tools (nmap, subfinder, httpx, ffuf, etc.)
"""
import os
import sys
import shutil
import urllib.request
import json

# Fix Windows/Linux UTF-8 output
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

GREEN = "\033[0;32m" if sys.platform != "win32" else ""
RED = "\033[0;31m" if sys.platform != "win32" else ""
YELLOW = "\033[1;33m" if sys.platform != "win32" else ""
CYAN = "\033[0;36m" if sys.platform != "win32" else ""
RESET = "\033[0m" if sys.platform != "win32" else ""


def check_ollama(host_url: str):
    if not host_url.startswith("http://") and not host_url.startswith("https://"):
        host_url = f"http://{host_url}"
    host_url = host_url.replace("://0.0.0.0:", "://127.0.0.1:")
    print(f"\n[*] [1/4] Checking Ollama AI Connection ({host_url})...")
    url = f"{host_url.rstrip('/')}/api/tags"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "HunterAI-Verifier"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                models = [m.get("name", "") for m in data.get("models", [])]
                print(f"    {GREEN}[✓] SUCCESS:{RESET} Ollama is reachable! Found {len(models)} models:")
                for m in models:
                    print(f"        • {m}")

                # Check for the 3 target models
                needed = [
                    ("WhiteRabbitNeo", "WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B"),
                    ("xploiter", "xploiter/pentester"),
                    ("qwen2.5-coder", "qwen2.5-coder:14b"),
                ]
                for label, target_str in needed:
                    has_model = any(target_str.lower() in m.lower() for m in models)
                    if has_model:
                        print(f"        {GREEN}[✓] Model Council Member Active:{RESET} {label}")
                    else:
                        print(f"        {YELLOW}[!] Notice:{RESET} {label} ({target_str}) not listed in Ollama tags.")
                return True
    except Exception as e:
        print(f"    {RED}[!] FAILED:{RESET} Cannot reach Ollama at {host_url}: {e}")
        print(f"    {YELLOW}Hint:{RESET} On Windows host, verify 'OLLAMA_HOST=0.0.0.0:11434' is active and Firewall allows port 11434.")
        return False


def check_burp_proxy(proxy_url: str = "http://127.0.0.1:8080"):
    print(f"\n[*] [2/4] Checking Burp Suite Proxy ({proxy_url})...")
    try:
        import urllib.request
        handler = urllib.request.ProxyHandler({'http': proxy_url, 'https': proxy_url})
        opener = urllib.request.build_opener(handler)
        with opener.open("http://burp", timeout=3) as resp:
            print(f"    {GREEN}[✓] SUCCESS:{RESET} Burp Suite Proxy is ACTIVE and reachable at {proxy_url}!")
            return True
    except Exception:
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect(("127.0.0.1", 8080))
            s.close()
            print(f"    {GREEN}[✓] SUCCESS:{RESET} Port 8080 is listening (Burp Suite proxy reachable).")
            return True
        except Exception:
            print(f"    {YELLOW}[~] INFO:{RESET} Burp Suite proxy not active on port 8080 (optional; Playwright will run directly if Burp is closed).")
            return False


def check_playwright():
    print(f"\n[*] [3/4] Checking Playwright & Browser Worker...")
    try:
        import playwright
        try:
            import importlib.metadata
            version = importlib.metadata.version("playwright")
        except Exception:
            version = "installed"
        print(f"    {GREEN}[✓] SUCCESS:{RESET} Playwright Python library is ready (v{version}).")

        # Test launching headless browser
        import asyncio
        from playwright.async_api import async_playwright

        async def _test():
            async with async_playwright() as p:
                try:
                    b = await p.chromium.launch(headless=True)
                    await b.close()
                    return True, None
                except Exception as e:
                    return False, str(e)

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            ok, err = loop.run_until_complete(_test())
            loop.close()

            if ok:
                print(f"    {GREEN}[✓] SUCCESS:{RESET} Playwright Chromium browser worker is operational.")
                return True
            else:
                print(f"    {YELLOW}[!] Notice:{RESET} Playwright browser binary is not downloaded yet.")
                print(f"    {CYAN}Fix command:{RESET} Run in terminal: {GREEN}playwright install chromium{RESET}")
                return False
        except Exception as e:
            print(f"    {YELLOW}[!] Notice:{RESET} Browser test skipped: {e}")
            return True
    except ImportError:
        print(f"    {RED}[!] FAILED:{RESET} Playwright library is not installed. Run: pip install playwright && playwright install chromium")
        return False


def check_kali_tools():
    print(f"\n[*] [4/4] Checking Security Tools Availability...")
    tools = ["nmap", "subfinder", "httpx", "katana", "nuclei", "ffuf", "sqlmap", "wpscan", "curl"]
    found = 0
    for t in tools:
        path = shutil.which(t)
        if path:
            print(f"    {GREEN}[✓]{RESET} {t:<10} -> {path}")
            found += 1
        else:
            print(f"    {YELLOW}[-]{RESET} {t:<10} -> not in PATH")
    print(f"    Status: {found}/{len(tools)} tools detected.")
    return found


def main():
    print("=" * 70)
    print(f" 🔍 PentestAI Unified — Pre-Flight Environment & Connection Check")
    print("=" * 70)

    # 1. Determine Ollama Host
    if len(sys.argv) > 1 and sys.argv[1].startswith("http"):
        host = sys.argv[1]
    else:
        # Check .env first
        try:
            from dotenv import load_dotenv
            load_dotenv()
        except Exception:
            pass
        env_host = os.getenv("OLLAMA_HOST")

        # Check platform/kali.json if on Linux
        kali_host = None
        if sys.platform != "win32":
            try:
                from pathlib import Path
                kj = Path(__file__).parent / "platform" / "kali.json"
                if kj.exists():
                    data = json.loads(kj.read_text(encoding="utf-8"))
                    kali_host = data.get("default_ollama_host")
            except Exception:
                pass

        if env_host and "127.0.0.1" not in env_host and "localhost" not in env_host:
            host = env_host
        elif kali_host:
            host = kali_host
        else:
            host = env_host or "http://192.168.1.3:11434"

    # Run checks
    check_ollama(host)
    check_burp_proxy()
    check_playwright()
    check_kali_tools()

    print("\n" + "=" * 70)
    print(f" 🚀 Ready for Assessment Workflow!")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
