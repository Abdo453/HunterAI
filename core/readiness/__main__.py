"""CLI: python -m core.readiness [--strict] [--timeout N] [--output report.json]"""
from __future__ import annotations

import argparse
import sys
import asyncio
from pathlib import Path


def main() -> int:
    # cp1256/GBK consoles → طباعة التقرير العربي/Unicode بسلام
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            pass
    parser = argparse.ArgumentParser(
        description="فحص جاهزية موحّد — Kali tools + Ollama + Burp + Playwright + wordlists (محلي فقط)")
    parser.add_argument("--strict", action="store_true",
                        help="الخروج برمز 2 إذا فشل عنصر أساسي")
    parser.add_argument("--timeout", type=float, default=6.0,
                        help="مهلة كل probe محلي (ثانية)")
    parser.add_argument("--output", type=Path, help="مسار حفظ التقرير JSON")
    parser.add_argument("--target", default="", help="الهدف (للتقارير فقط — لا يُلامس)")
    args = parser.parse_args()

    from core.readiness import ReadinessChecker, enforce_strict, save_readiness_artifact

    async def _run():
        checker = ReadinessChecker(kali_timeout=args.timeout)
        return await checker.run_all(target=args.target, session_id="cli", strict=args.strict)

    report = asyncio.run(_run())
    rendered = report.to_json()
    print(rendered)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
        print(f"[saved] {args.output}", file=sys.stderr)
    else:
        save_readiness_artifact(report)

    if args.strict:
        try:
            enforce_strict(report)
        except Exception as exc:
            print(f"[GATE] {exc}", file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
