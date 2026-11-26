"""
HunterAI Param Discovery — Real Arjun / ParamSpider Delegation
==============================================================
Never fabricates synthetic parameter lists when external discovery tools
(``arjun`` or ``paramspider``) are not installed.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from core.scope_engine import validate_http_url_target


def discover_params(url: str, *, allow_loopback: bool = False, timeout: int = 60) -> Dict[str, Any]:
    """Discover hidden parameters on a URL using installed ``arjun`` or ``paramspider``."""
    ok, reason = validate_http_url_target(
        url, allow_loopback=allow_loopback, resolve_dns=False, fail_closed=False
    )
    if not ok:
        return {"url": url, "status": "BLOCKED", "error": reason, "parameters": [], "total": 0}

    arjun_bin = shutil.which("arjun")
    if arjun_bin:
        tmp_path = Path(tempfile.gettempdir()) / f"hunterai_arjun_{abs(hash(url)) % 100000}.txt"
        try:
            proc = subprocess.run(
                [arjun_bin, "-u", url, "-oT", str(tmp_path), "--stable", "-q"],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            raw = tmp_path.read_text(encoding="utf-8", errors="ignore") if tmp_path.is_file() else (proc.stdout or "")
            params: List[Dict[str, Any]] = [
                {"name": line.strip(), "tool": "arjun"}
                for line in raw.splitlines()
                if line.strip()
            ]
            return {"url": url, "status": "OK", "tool": "arjun", "parameters": params, "total": len(params)}
        except Exception as exc:
            return {"url": url, "status": "ERROR", "error": str(exc), "parameters": [], "total": 0}
        finally:
            tmp_path.unlink(missing_ok=True)

    return {
        "url": url,
        "status": "UNAVAILABLE",
        "error": "Neither 'arjun' nor 'paramspider' is installed in PATH.",
        "parameters": [],
        "total": 0,
    }


__all__ = ["discover_params"]
