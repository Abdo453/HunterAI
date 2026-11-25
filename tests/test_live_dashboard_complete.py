"""Live HTTP Dashboard & Control Center Verification Suite.

Runs cleanly under pytest using an ephemeral localhost uvicorn server (with
isolated temporary platform DB & restored runtime artifacts), while preserving
standalone ``python tests/test_live_dashboard_complete.py [base_url]`` CLI usage.
"""
from __future__ import annotations

import os
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Optional

import httpx
import pytest
import uvicorn

_REPO_ROOT = Path(__file__).resolve().parents[1]

ROUTES_TO_CHECK = [
    ("/", 200),
    ("/?section=redteam", 200),
    ("/?section=editor", 200),
    ("/?section=chat", 200),
    ("/?section=radar", 200),
    ("/opencode", 200),
]

REDIRECTS_TO_CHECK = [
    ("/chat", "/?section=chat"),
    ("/command", "/?section=overview"),
]

SECTIONS_TO_CHECK = [
    ("sec-overview", "System Overview Dashboard"),
    ("sec-agents", "Specialized Agents Management"),
    ("sec-skills", "Skills Explorer & Dependency Inspector"),
    ("sec-tools", "Tools Center & Health Check"),
    ("sec-mcp", "MCP Servers Center"),
    ("sec-browser", "Interactive Browser Manager"),
    ("sec-burp", "Burp Suite Integration Monitor"),
    ("sec-models", "AI Models Manager"),
    ("sec-targets", "Target & Scope Guard"),
    ("sec-radar", "Live Target Radar"),
    ("sec-activity", "Live Activity Center"),
    ("sec-results", "Results & Vulnerabilities Explorer"),
    ("sec-diagnostics", "System Diagnostics"),
    ("sec-settings", "Settings & Security Policies"),
    ("sec-telemetry", "Attack Surface Graph & Wiretap"),
    ("sec-redteam", "Red Team Cockpit & Checklists"),
    ("sec-editor", "Monaco Code Editor & Burp Repeater"),
    ("sec-chat", "Multi-Model Autonomous Agent Chat"),
]

SCRIPTS_TO_CHECK = [
    ("Monaco Self-Hosted Loader", "/static/vendor/monaco/vs/loader.min.js"),
    ("DOMPurify Local Asset", "/static/vendor/dompurify/purify.min.js"),
    ("Unified Core JS", "/static/ui-core.js"),
    ("Platform Hub Client", "/static/platform-client.js"),
    ("Copilot Drawer JS", "/static/copilot-drawer.js"),
    ("RedTeam JS Cockpit", "function loadRedTeamCockpit"),
    ("Checklists Toggle JS", "function toggleChecklistItem"),
    ("7-Question Gate JS", "function evaluateSevenGate"),
    ("Lead Board Touch JS", "function touchLeadStatus"),
    ("Monaco Editor Init JS", "function initCodeEditor"),
    ("Burp Repeater Send JS", "function sendRepeaterRequest"),
    ("Unified Chat Stream JS", "function sendUnifiedChatMessage"),
    ("Auto-Switch Script", "window._defaultSection"),
]

API_ENDPOINTS_TO_CHECK = [
    ("GET", "/api/control/system-status", None),
    ("GET", "/api/control/agents", None),
    ("GET", "/api/control/skills", None),
    ("GET", "/api/control/tools", None),
    ("GET", "/api/control/browser", None),
    ("GET", "/api/control/burp", None),
    ("GET", "/api/control/models", None),
    ("GET", "/api/control/targets", None),
    ("GET", "/api/control/test-radar", None),
    ("GET", "/api/control/activity", None),
    ("GET", "/api/control/results", None),
    ("GET", "/api/control/settings", None),
    ("GET", "/api/control/checklists", None),
    ("GET", "/api/control/redteam-policy", None),
    ("GET", "/api/control/lead-board", None),
    ("GET", "/api/editor/tree", None),
    ("POST", "/api/control/checklists/toggle", {"item_id": "WEB-01", "checked": True}),
    (
        "POST",
        "/api/control/seven-gate/evaluate",
        {
            "title": "BOLA on Payment Gateway",
            "asset": "api.target.com",
            "poc": "GET /api/pay/99 HTTP/1.1",
            "impact": "Account takeover of customer transactions",
            "reproducibility": "100% reproducible",
            "vulnerability_class": "idor",
        },
    ),
    ("POST", "/api/control/test-radar/simulate", {}),
]


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _snapshot_files(paths: list[Path]) -> dict[Path, Optional[bytes]]:
    snap: dict[Path, Optional[bytes]] = {}
    for p in paths:
        snap[p] = p.read_bytes() if p.exists() else None
    return snap


def _restore_files(snap: dict[Path, Optional[bytes]]) -> None:
    for p, content in snap.items():
        if content is None:
            if p.exists():
                p.unlink()
        else:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(content)


def _start_ephemeral_server(db_path: Path):
    import core.platform_store as ps
    import ui.web.platform_hub as ph
    from ui.web.app import app

    prev_db_env = os.environ.get("HUNTER_PLATFORM_DB_PATH")
    prev_store = ps._GLOBAL_PLATFORM_STORE
    prev_attached = ph.EVENT_BUS._attached_store

    os.environ["HUNTER_PLATFORM_DB_PATH"] = str(db_path)
    ps._GLOBAL_PLATFORM_STORE = None
    ph.EVENT_BUS._attached_store = None

    port = _pick_free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    base_url = f"http://127.0.0.1:{port}"
    deadline = time.time() + 15.0
    while time.time() < deadline:
        try:
            r = httpx.get(f"{base_url}/api/platform/context", timeout=1.0)
            if r.status_code == 200:
                break
        except Exception:
            pass
        time.sleep(0.15)
    else:
        server.should_exit = True
        thread.join(timeout=3.0)
        raise RuntimeError(f"Ephemeral uvicorn server failed to start on {base_url}")

    def _cleanup() -> None:
        server.should_exit = True
        thread.join(timeout=5.0)
        if ps._GLOBAL_PLATFORM_STORE is not None:
            ps._GLOBAL_PLATFORM_STORE.close()
        ps._GLOBAL_PLATFORM_STORE = prev_store
        ph.EVENT_BUS._attached_store = prev_attached
        if prev_db_env is None:
            os.environ.pop("HUNTER_PLATFORM_DB_PATH", None)
        else:
            os.environ["HUNTER_PLATFORM_DB_PATH"] = prev_db_env

    return base_url, _cleanup


@pytest.fixture(scope="module")
def live_client():
    runtime_artifacts = [
        _REPO_ROOT / "data" / "checklist_state.json",
        _REPO_ROOT / "data" / "radar" / "latest_state.json",
    ]
    snap = _snapshot_files(runtime_artifacts)
    tmp_dir = tempfile.TemporaryDirectory(prefix="hunter_live_dash_")
    db_path = Path(tmp_dir.name) / "platform_test.sqlite3"
    base_url, cleanup = _start_ephemeral_server(db_path)
    try:
        with httpx.Client(base_url=base_url, timeout=15.0, follow_redirects=False) as client:
            yield client
    finally:
        cleanup()
        _restore_files(snap)
        tmp_dir.cleanup()


def test_live_dashboard_routes_and_redirects(live_client: httpx.Client):
    for route, expected in ROUTES_TO_CHECK:
        resp = live_client.get(route)
        assert resp.status_code == expected, f"{route} returned {resp.status_code}"

    for route, exp_loc in REDIRECTS_TO_CHECK:
        resp = live_client.get(route)
        assert resp.status_code == 302, f"{route} returned {resp.status_code}"
        assert resp.headers.get("location") == exp_loc


def test_live_dashboard_dom_sections_and_js_contracts(live_client: httpx.Client):
    resp = live_client.get("/")
    assert resp.status_code == 200
    html = resp.text

    for sec_id, label in SECTIONS_TO_CHECK:
        assert f'id="{sec_id}"' in html, f"Missing section #{sec_id} ({label})"

    for label, needle in SCRIPTS_TO_CHECK:
        assert needle in html, f"Missing {label} ({needle}) in /"

    assert "cdnjs.cloudflare.com" not in html
    assert "fonts.googleapis.com" not in html


def test_live_dashboard_control_api_endpoints(live_client: httpx.Client):
    for method, ep, payload in API_ENDPOINTS_TO_CHECK:
        resp = live_client.get(ep) if method == "GET" else live_client.post(ep, json=payload)
        assert resp.status_code == 200, f"{method} {ep} returned {resp.status_code}: {resp.text}"
        data = resp.json()
        assert isinstance(data, dict)
        if ep == "/api/control/test-radar/simulate":
            assert data.get("simulated") is True


def _run_standalone_cli(base_url: str) -> int:
    all_passed = True
    with httpx.Client(base_url=base_url, timeout=10.0, follow_redirects=False) as client:
        for route, expected in ROUTES_TO_CHECK:
            resp = client.get(route)
            ok = resp.status_code == expected
            if not ok:
                all_passed = False
            print(f"[{'PASS' if ok else 'FAIL'}] {route:25} -> {resp.status_code}")

        for route, exp_loc in REDIRECTS_TO_CHECK:
            resp = client.get(route)
            loc = resp.headers.get("location", "")
            ok = resp.status_code == 302 and loc == exp_loc
            if not ok:
                all_passed = False
            print(f"[{'PASS' if ok else 'FAIL'}] {route:25} -> {resp.status_code} ({loc})")

        html = client.get("/").text
        for sec_id, name in SECTIONS_TO_CHECK:
            ok = f'id="{sec_id}"' in html
            if not ok:
                all_passed = False
            print(f"[{'PASS' if ok else 'FAIL'}] #{sec_id:18} : {name}")

        for label, needle in SCRIPTS_TO_CHECK:
            ok = needle in html
            if not ok:
                all_passed = False
            print(f"[{'PASS' if ok else 'FAIL'}] {label:28} : present")

        for method, ep, payload in API_ENDPOINTS_TO_CHECK:
            resp = client.get(ep) if method == "GET" else client.post(ep, json=payload)
            ok = resp.status_code == 200
            if not ok:
                all_passed = False
            print(f"[{'PASS' if ok else 'FAIL'}] {method:4} {ep:35} -> {resp.status_code}")

    return 0 if all_passed else 1


if __name__ == "__main__":
    target_url = sys.argv[1] if len(sys.argv) > 1 else os.getenv("HUNTER_BASE_URL", "")
    if target_url:
        sys.exit(_run_standalone_cli(target_url))
    with tempfile.TemporaryDirectory(prefix="hunter_live_cli_") as tmp:
        url, cleanup = _start_ephemeral_server(Path(tmp) / "platform.sqlite3")
        try:
            sys.exit(_run_standalone_cli(url))
        finally:
            cleanup()
