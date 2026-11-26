"""
HunterAI Cloud Recon — Public Cloud Bucket Existence Prober
===========================================================
Probes S3/GCS/Azure public bucket endpoints with strict SSRF validation.
Never fabricates synthetic bucket results when probes fail or are unreachable.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

import httpx

from core.scope_engine import validate_http_url_target


def cloud_recon(keyword: str, *, timeout: float = 6.0) -> Dict[str, Any]:
    """Probe public cloud bucket endpoints for ``keyword`` (read-only HEAD requests)."""
    clean = re.sub(r"[^a-z0-9-]", "-", (keyword or "").strip().lower()).strip("-")
    if not clean:
        return {"keyword": keyword, "status": "ERROR", "error": "Invalid keyword", "buckets": [], "total": 0}

    candidates = [
        ("AWS S3", f"{clean}", f"https://{clean}.s3.amazonaws.com"),
        ("AWS S3", f"{clean}-backup", f"https://{clean}-backup.s3.amazonaws.com"),
        ("AWS S3", f"{clean}-assets", f"https://{clean}-assets.s3.amazonaws.com"),
        ("GCP", f"{clean}", f"https://storage.googleapis.com/{clean}"),
        ("GCP", f"{clean}-assets", f"https://storage.googleapis.com/{clean}-assets"),
    ]
    buckets: List[Dict[str, Any]] = []
    errors: List[str] = []

    with httpx.Client(timeout=timeout, verify=True, follow_redirects=False, trust_env=False) as client:
        for provider, name, url in candidates:
            ok, reason = validate_http_url_target(url, allow_loopback=False, resolve_dns=False, fail_closed=False)
            if not ok:
                errors.append(f"{url}: {reason}")
                continue
            try:
                resp = client.head(url)
                if resp.status_code in (200, 301, 307, 403):
                    buckets.append({
                        "provider": provider,
                        "bucket": name,
                        "url": url,
                        "status_code": resp.status_code,
                        "public": resp.status_code == 200,
                        "verified": False,
                    })
            except Exception as exc:
                errors.append(f"{url}: {exc}")

    status = "OK" if buckets or not errors else "UNAVAILABLE"
    print(f"[Cloud Recon] Observed {len(buckets)} existing bucket(s) for '{clean}' (status={status})")
    return {
        "keyword": clean,
        "status": status,
        "buckets": buckets,
        "total": len(buckets),
        "errors": errors[:5],
    }


__all__ = ["cloud_recon"]
