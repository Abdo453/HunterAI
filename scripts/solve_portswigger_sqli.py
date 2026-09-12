#!/usr/bin/env python3
"""
PortSwigger SQLi Lab Automated Solver — PentestAI Unified
=========================================================
Solves PortSwigger Web Security Academy SQLi Labs autonomously in seconds.

Usage:
  python scripts/solve_portswigger_sqli.py --url "https://<lab-id>.web-security-academy.net/"
  python scripts/solve_portswigger_sqli.py --url "https://<lab-id>.web-security-academy.net/filter?category=Gifts"
  python scripts/solve_portswigger_sqli.py --url "https://<lab-id>.web-security-academy.net/filter?category=Gifts" --proxy "http://127.0.0.1:8080"
"""
import sys
import os
import re
import asyncio
import argparse
from urllib.parse import urlparse, parse_qs, urljoin
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx
from agents.skills.sqli_skill import SQLiSkill, SQLiContext, DBMSType


def print_banner():
    print(r"""
 ══════════════════════════════════════════════════════════════════
  🏹 PentestAI-Unified — PortSwigger SQLi Autonomous Solver 🎯
 ══════════════════════════════════════════════════════════════════
""")


async def resolve_target_url(raw_url: str, proxy: str = None) -> tuple[str, str]:
    """
    يتأكد من وجود endpoint يحتوي على query parameter (مثل /filter?category=Gifts).
    إذا تم إدخال الرابط الرئيسي فقط، يقوم بجلب الصفحة واستخراج رابط التصنيف آلياً.
    """
    parsed = urlparse(raw_url)
    qs = parse_qs(parsed.query)
    
    if qs:
        param = list(qs.keys())[0]
        return raw_url, param

    print(f"[*] Crawling target homepage to discover filter endpoints: {raw_url}")
    transport = None
    if proxy:
        transport = httpx.AsyncHTTPTransport(proxy=proxy, verify=False)
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"
    }
    
    try:
        async with httpx.AsyncClient(headers=headers, transport=transport, verify=False, timeout=10.0) as client:
            resp = await client.get(raw_url)
            matches = re.findall(r'href=[\'"]([^\'"]*filter\?[^\'"]+)[\'"]', resp.text, re.I)
            if matches:
                discovered = urljoin(raw_url, matches[0])
                discovered_qs = parse_qs(urlparse(discovered).query)
                param = list(discovered_qs.keys())[0] if discovered_qs else "category"
                print(f"[+] Auto-discovered vulnerable endpoint: {discovered} (param={param!r})")
                return discovered, param
    except Exception as e:
        print(f"[!] Notice during crawler: {e}")

    fallback_url = urljoin(raw_url, "/filter?category=Gifts")
    print(f"[*] Defaulting to standard PortSwigger filter endpoint: {fallback_url}")
    return fallback_url, "category"


async def main():
    parser = argparse.ArgumentParser(description="PortSwigger SQLi Autonomous Solver")
    parser.add_argument("--url", "-u", required=True, help="Target URL (domain or /filter?category=...)")
    parser.add_argument("--proxy", "-p", default=None, help="HTTP Proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--objective", "-o", default="retrieve_db_version", help="Objective: retrieve_db_version")
    args = parser.parse_args()

    print_banner()
    
    target_url, param = await resolve_target_url(args.url, args.proxy)
    
    print(f"[*] Starting SQLi Autonomous State Machine...")
    print(f"    🎯 Target Endpoint: {target_url}")
    print(f"    🔑 Target Param:    {param}")
    print(f"    📡 Proxy:           {args.proxy or 'None (Direct)'}")
    print(f"    🎯 Objective:       {args.objective}\n")

    skill = SQLiSkill(proxy=args.proxy, objective=args.objective)
    
    loop = asyncio.get_running_loop()
    t0 = loop.time()
    result = await skill.run(target_url=target_url, param_name=param, objective=args.objective)
    duration = round(loop.time() - t0, 2)

    print("\n" + "═" * 66)
    print(" 📋 EXECUTION SUMMARY & LAB STATUS")
    print("═" * 66)
    
    state = result.get("state")
    obj_met = result.get("objective_met")
    dbms = result.get("dbms", "unknown").upper()
    col_count = result.get("col_count", 0)
    text_cols = result.get("text_cols", [])
    union_payload = result.get("union_payload", "")
    extracted = result.get("extracted_data", "")

    print(f"  State:            {state}")
    print(f"  DBMS Identified:  {dbms}")
    print(f"  Columns Count:    {col_count}")
    print(f"  Text Columns:     {text_cols}")
    print(f"  Winning Payload:  {union_payload}")
    print(f"  Extracted Data:   {extracted}")
    print(f"  Time Elapsed:     {duration}s")
    
    if obj_met or "Oracle" in extracted or "Database" in extracted:
        print("\n" + "🎉" * 25)
        print("  ✅ LAB SOLVED SUCCESSFULLY!")
        print(f"  Database Version Extracted: {extracted}")
        print("🎉" * 25 + "\n")
    else:
        print("\n[!] Lab could not be solved automatically. Check logs below:")
        for log_line in result.get("logs", []):
            print(f"   {log_line}")


if __name__ == "__main__":
    asyncio.run(main())
