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
    ("/?format=json", 200),
    ("/api/platform/overview", 200),
    ("/api/platform/context", 200),
    ("/api/models/catalog", 200),
    ("/opencode?format=json", 200),
]

REDIRECTS_TO_CHECK = [
    ("/", "http://127.0.0.1:3000/"),
    ("/chat", "http://127.0.0.1:3000/?copilot=open"),
    ("/command", "http://127.0.0.1:3000/"),
    ("/opencode", "http://127.0.0.1:3000/studio"),
]

FRONTEND_ROUTES_TO_CHECK = [
    "app/page.tsx",
    "app/surface/page.tsx",
    "app/findings/page.tsx",
    "app/operations/page.tsx",
    "app/studio/page.tsx",
    "app/intercept/page.tsx",
    "app/arsenal/page.tsx",
    "app/system/page.tsx",
]

FRONTEND_COMPONENTS_TO_CHECK = [
    "components/AppShell.tsx",
    "components/Navbar.tsx",
    "components/CopilotDrawer.tsx",
    "components/ApprovalsPanel.tsx",
    "components/LiveConsole.tsx",
    "components/StatsCards.tsx",
    "components/FindingsTable.tsx",
    "components/CommandPalette.tsx",
    "lib/platform-context.tsx",
    "public/vendor/monaco/vs/loader.min.js",
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
    import hunter_backend.runtime as rt
    from hunter_backend.asgi import application

    prev_db_env = os.environ.get("HUNTER_PLATFORM_DB_PATH")
    prev_store = ps._GLOBAL_PLATFORM_STORE

    os.environ["HUNTER_PLATFORM_DB_PATH"] = str(db_path)
    ps._GLOBAL_PLATFORM_STORE = None
    rt.EVENT_BUS._history.clear()

    port = _pick_free_port()
    config = uvicorn.Config(application, host="127.0.0.1", port=port, log_level="warning")
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
        rt.EVENT_BUS._history.clear()
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
    resp = live_client.get("/?format=json")
    assert resp.status_code == 200
    assert resp.json()["backend"] == "django-asgi"

    fe_root = _REPO_ROOT / "frontend"
    for rel in FRONTEND_ROUTES_TO_CHECK + FRONTEND_COMPONENTS_TO_CHECK:
        assert (fe_root / rel).is_file(), f"Missing unified frontend asset: {rel}"

    layout_src = (fe_root / "app" / "layout.tsx").read_text(encoding="utf-8")
    assert "cdnjs.cloudflare.com" not in layout_src
    assert "fonts.googleapis.com" not in layout_src


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

        root_info = client.get("/?format=json").json()
        ok_root = root_info.get("backend") == "django-asgi"
        if not ok_root:
            all_passed = False

        fe_root = _REPO_ROOT / "frontend"
        for rel in FRONTEND_ROUTES_TO_CHECK + FRONTEND_COMPONENTS_TO_CHECK:
            ok = (fe_root / rel).is_file()
            if not ok:
                all_passed = False
            print(f"[{'PASS' if ok else 'FAIL'}] frontend/{rel}")

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
