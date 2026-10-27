"""
HunterAI Hunt Engine — Vulnerability Testing
============================================
Tests IDOR, auth bypass, SSRF, XSS, SQLi, logic flaws and more.

مبدأ صارم: **لا نتائج وهمية إطلاقاً**.
المحرك الحقيقي هو ``HunterPipelineOrchestrator`` (21 مرحلة + بوابة تأهيل
الأدلة). هذا الملف واجهة خفيفة فوقه: يفرض التصريح، يوجّه الـ profile،
ويحفظ النتائج الحقيقية.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

# mode (من CLI) -> profile (inside the orchestrator)
_MODE_TO_PROFILE = {
    "web": "safe",
    "full": "full",
    "ctf": "full",
    "recon": "safe",
}


def _domain_of(target: str) -> str:
    t = (target or "").strip().lower()
    if "://" in t:
        t = urlparse(t).netloc
    return t.split("/")[0].split("@")[-1].split(":")[0].strip(".")


def _allow_no_ai_default() -> bool:
    """
    هل نسمح للـ pipeline بالعمل بلا LLM؟
    الافتراضي نعم: التقديرات الحتمية (skills + qualification gate) تنتج
    نتائج حقيقية، بينما الـ AI يضيف طبقة تفسير فقط. يُ-earthed عن طريق env.
    """
    v = os.getenv("HUNTERAI_ALLOW_NO_AI", "1").strip().lower()
    return v not in ("0", "false", "no", "off")


async def run_hunt(
    target: str,
    mode: str = "full",
    authorized: bool = False,
    profile: Optional[str] = None,
    allow_no_ai: Optional[bool] = None,
) -> Dict[str, Any]:
    """Run vulnerability hunt against target — real pipeline only."""
    if not authorized:
        print("⚠️  Not authorized. Use --authorized to enable active testing.")
        return {
            "target": target,
            "findings": [],
            "authorized": False,
            "status": "blocked",
            "reason": "Active testing requires explicit authorization (--authorized).",
        }

    domain = _domain_of(target)
    if not domain:
        return {
            "target": target,
            "findings": [],
            "authorized": True,
            "status": "error",
            "reason": f"Could not parse a domain from {target!r}",
        }

    started = time.time()

    # ── recon-only mode: real recon, no vulnerability testing ────────────────
    if mode == "recon":
        from hunter_ai.pipeline.recon_engine import run_recon
        recon = await run_recon(target)
        return {
            "target": target,
            "domain": domain,
            "mode": mode,
            "authorized": True,
            "status": "recon_only",
            "findings": [],
            "recon": recon,
            "duration_s": round(time.time() - started, 2),
        }

    resolved_profile = profile or _MODE_TO_PROFILE.get(mode, "safe")
    no_ai = _allow_no_ai_default() if allow_no_ai is None else allow_no_ai

    print(f"[+] Starting hunt for {target} (mode={mode}, profile={resolved_profile})")

    from hunter_ai.pipeline.pipeline_orchestrator import HunterPipelineOrchestrator

    orchestrator = HunterPipelineOrchestrator(
        target,
        profile=resolved_profile,
        mode=mode,
        workflow=mode,
        authorized=True,
        allow_no_ai=no_ai,
        dry_run=False,
    )

    try:
        result = await orchestrator.run()
    except Exception as exc:
        reason = f"Pipeline raised {type(exc).__name__}: {exc}"
        print(f"[!] {reason}")
        return {
            "target": target,
            "domain": domain,
            "mode": mode,
            "authorized": True,
            "status": "error",
            "reason": reason,
            "findings": [],
            "duration_s": round(time.time() - started, 2),
        }

    findings: List[Dict[str, Any]] = list(result.get("findings") or [])
    status = result.get("status", "completed")

    # حفظ النتائج الحقيقية فقط
    out_dir = Path("data/engagements") / domain
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "target": target,
        "domain": domain,
        "mode": mode,
        "profile": resolved_profile,
        "authorized": True,
        "status": status,
        "findings": findings,
        "pipeline": {
            k: result.get(k)
            for k in (
                "session_id", "duration", "subdomains_count", "live_assets_count",
                "endpoints_count", "parameters_count", "findings_count",
                "artifact_directory", "engagement_directory", "manifest_file",
                "coverage_summary", "tool_failures",
            )
        },
        "reason": result.get("reason"),
        "duration_s": round(time.time() - started, 2),
        "generated_at": time.time(),
    }
    out_path = out_dir / "hunt_results.json"
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str),
                        encoding="utf-8")

    if status != "completed":
        print(f"[!] Pipeline did not complete: status={status} "
              f"reason={result.get('reason') or 'n/a'}")
        print(f"    No findings are reported for an incomplete run.")
        return payload

    print(f"[+] Hunt complete: {len(findings)} verified findings "
          f"({result.get('duration', 0)}s)")
    print(f"[+] Results saved to {out_path}")
    return payload
