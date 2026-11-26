"""
HunterAI Bypass 403 — Real Read-Only Header / Method Differential Probes
========================================================================
Sends real read-only HTTP differential probes gated by ``validate_http_url_target``
with ``trust_env=False`` and ``follow_redirects=False``.
"""
from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import urlsplit

import httpx

from core.scope_engine import validate_http_url_target


def bypass(url: str, *, allow_loopback: bool = False, timeout: float = 8.0) -> Dict[str, Any]:
    """Probe read-only 403/401 bypass headers/methods against ``url``."""
    ok, reason = validate_http_url_target(
        url, allow_loopback=allow_loopback, resolve_dns=False, fail_closed=False
    )
    if not ok:
        return {"url": url, "status": "BLOCKED", "error": reason, "bypassed": False, "methods": []}

    parsed = urlsplit(url)
    path = parsed.path or "/"
    probes = [
        ("X-Original-URL", "GET", {"X-Original-URL": path}),
        ("X-Rewrite-URL", "GET", {"X-Rewrite-URL": path}),
        ("X-Forwarded-For", "GET", {"X-Forwarded-For": "127.0.0.1"}),
        ("HEAD method", "HEAD", {}),
    ]
    methods: List[Dict[str, Any]] = []
    try:
        with httpx.Client(timeout=timeout, verify=False, follow_redirects=False, trust_env=False) as client:
            base_resp = client.get(url)
            base_status = base_resp.status_code
            for name, verb, headers in probes:
                resp = client.request(verb, url, headers=headers)
                if base_status in (401, 403) and 200 <= resp.status_code < 300:
                    methods.append({
                        "technique": name,
                        "baseline_status": base_status,
                        "probe_status": resp.status_code,
                        "verified": False,
                    })
    except Exception as exc:
        return {"url": url, "status": "ERROR", "error": str(exc), "bypassed": False, "methods": []}

    res = {
        "url": url,
        "status": "OK",
        "bypassed": len(methods) > 0,
        "methods": methods,
    }
    print(f"[Bypass 403] {url} — candidate bypasses: {len(methods)}")
    return res


__all__ = ["bypass"]
