#!/usr/bin/env python3
"""waf_response_analyzer.py — classify WAF/filter behavior from response pairs.

Compare BASELINE vs VARIANT responses (status, length, title/body markers) to
deduce what actually blocked a payload:

  RESP DIFF -> interpretation
  status 406/403/418 + short body  -> edge WAF block (retry with encoder matrix)
  200 + payload reflected raw      -> NO filtering — straight lead
  200, encoded only                -> encoder-aware filter -> try polyglot case
  400 w/ framework page            -> backend filter (not WAF) — target its parser
(body length |Δ| and marker sets are printed so the agent can adjudicate fast)

Usage:
  python scripts/waf_response_analyzer.py --baseline 200,120 --variant 403,48
  python scripts/waf_response_analyzer.py --compare baseline.html variant.html
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

WAF_STATUSES = {403: "edge-WAF block", 406: "edge-WAF block (mimic)",
                418: "teapot/custom block", 429: "rate/bot control",
                405: "method filter", 400: "backend parser rejection"}


def classify(b_status: int, b_len: int, v_status: int, v_len: int) -> dict:
    out: dict = {"baseline": [b_status, b_len], "variant": [v_status, v_len],
                 "len_delta": v_len - b_len, "verdict": None, "next": []}
    if v_status == b_status and abs(out["len_delta"]) < 64:
        out["verdict"] = "NO FILTER — payload likely reflected/processed"
        out["next"] = ["grep payload in response content", "escalate to a real proof"]
    elif v_status in WAF_STATUSES:
        out["verdict"] = f"WAF/filter block ({WAF_STATUSES[v_status]})"
        if v_status == 400:
            out["next"] = ["backend filter — probe its parser quirks (HPP, JSON strictness)"]
        else:
            out["next"] = ["fire waf_encoder.py matrix", "climb waf-bypass-ladder L1→L7"]
    elif v_status == 200 and abs(out["len_delta"]) >= max(200, b_len // 10):
        out["verdict"] = "partial — content mutated/absorbed (encoded-only?)"
        out["next"] = ["check which chars survived", "try case/unicode variants"]
    else:
        out["verdict"] = "ambiguous — read bodies manually"
        out["next"] = ["--compare with saved bodies"]
    return out


def _parse(spec: str) -> tuple[int, int]:
    s, l = spec.replace(" ", "").split(",")
    return int(s), int(l)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--baseline", help="status,length  e.g. 200,120")
    p.add_argument("--variant", help="status,length")
    p.add_argument("--compare", nargs=2, metavar=("BL", "VR"),
                   help="two saved response body files")
    a = p.parse_args()
    if a.compare:
        b, v = [Path(x).read_text(encoding="utf-8", errors="replace") for x in a.compare]
        print(json.dumps({"b_len": len(b), "v_len": len(v),
                          "delta": len(v) - len(b)}, indent=2))
        return 0
    if a.baseline and a.variant:
        bs, bl = _parse(a.baseline)
        vs, vl = _parse(a.variant)
        res = classify(bs, bl, vs, vl)
        print(json.dumps(res, indent=2))
        return 0
    p.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
