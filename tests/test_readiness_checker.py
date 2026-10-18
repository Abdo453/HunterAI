"""
Tests: Unified Readiness Checker (Phase 1)
==========================================
- Offline بالكامل (mocks) للتحكم الحتمي في الحالات
- اختبار REAL واحد فقط على ثنائيات محلية آمنة (python) بلا شبكة/هدف
- يُثبت: الإثبات قبل الـ READY، عزل الفشل، الـ strict gate، حفظ الـ artifact
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.readiness import (
    ComponentStatus,
    ComponentResult,
    ReadinessChecker,
    ReadinessGateError,
    ReadinessReport,
    enforce_strict,
    mission_gate_config,
    save_readiness_artifact,
    load_readiness_artifact,
    ARTIFACT_NAME,
)


def _ready(name: str, required: bool = True) -> ComponentResult:
    return ComponentResult(
        component="kali_tool", name=name, status=ComponentStatus.READY, required=required,
        detail="ok", probe="python --version", evidence={"binary": "python.exe"},
    )


def _missing(name: str, required: bool = True) -> ComponentResult:
    return ComponentResult(
        component="kali_tool", name=name, status=ComponentStatus.MISSING, required=required,
        detail="Not found on PATH", probe="snap=missing",
    )


# ══════════════════════════════════════════════════════════════════════════
# ReadinessReport — aggregate + serialization
# ══════════════════════════════════════════════════════════════════════════

def test_report_counts_and_blocked():
    report = ReadinessReport(target="t.example.com", session_id="s1", results=[
        _ready("nmap"), _ready("httpx"), _missing("sqlmap"), _missing("optional-tool", required=False),
    ])
    assert report.strict_ready is False
    assert [r.name for r in report.blocked] == ["sqlmap"]
    counts = report.counts()
    assert counts["READY"] == 2 and counts["MISSING"] == 2


def test_report_serialization_roundtrip():
    report = ReadinessReport(target="t.example.com", session_id="s1", results=[_ready("nmap")])
    data = json.loads(report.to_json())
    assert data["strict_ready"] is True
    assert data["target"] == "t.example.com"
    assert data["results"][0]["status"] == "READY"
    assert data["results"][0]["checked_at"] > 0


# ══════════════════════════════════════════════════════════════════════════
# strict gate
# ══════════════════════════════════════════════════════════════════════════

def test_gate_passes_when_all_required_ready():
    report = ReadinessReport(target="t", session_id="s", results=[_ready("nmap"), _ready("ollama")])
    assert enforce_strict(report) is report


def test_gate_blocks_on_missing_required():
    report = ReadinessReport(target="t", session_id="s", results=[_ready("nmap"), _missing("sqlmap")])
    with pytest.raises(ReadinessGateError) as exc:
        enforce_strict(report)
    # الخطأ يُحمل الـ report للرد الـ HTTP
    assert exc.value.report is report
    assert "sqlmap" in str(exc.value)
    # ESLINT: المهمة لم تُبدأ — الخطأ واضح


def test_gate_error_names_all_blocked_components():
    # عناصر محظورة تظهر بالاسم في رسالة الخطأ
    report = ReadinessReport(target="t", session_id="s", results=[_missing("subfinder"), _missing("ffuf")])
    with pytest.raises(ReadinessGateError) as exc:
        enforce_strict(report)
    msg = str(exc.value)
    assert "subfinder" in msg and "ffuf" in msg


# ══════════════════════════════════════════════════════════════════════════
# check_ollama (mocked /api/tags)
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_ollama_ready_with_models(monkeypatch):
    async def fake_tags(host):
        return ["xploiter:latest", "qwen2.5-coder:7b"]
    checker = ReadinessChecker()
    monkeypatch.setattr(checker, "_ollama_tags", fake_tags)
    results = await checker.check_ollama(expected_models=["xploiter:latest", "qwen2.5-coder:7b"])
    by_name = {r.name: r for r in results}
    assert by_name["ollama_server"].status is ComponentStatus.READY
    assert by_name["xploiter:latest"].status is ComponentStatus.READY
    # إثبات: البروب كان GET فعلي وليس ادعاء
    assert "/api/tags" in by_name["xploiter:latest"].probe


@pytest.mark.asyncio
async def test_ollama_offline_blocks(monkeypatch):
    async def fake_tags(host):
        return None
    checker = ReadinessChecker()
    monkeypatch.setattr(checker, "_ollama_tags", fake_tags)
    results = await checker.check_ollama(expected_models=["xploiter:latest"])
    by_name = {r.name: r for r in results}
    assert by_name["ollama_server"].status is ComponentStatus.UNHEALTHY
    assert by_name["xploiter:latest"].status is ComponentStatus.MISSING
    report = ReadinessReport(target="t", session_id="s", results=results)
    assert report.strict_ready is False


@pytest.mark.asyncio
async def test_ollama_missing_model_recorded(monkeypatch):
    async def fake_tags(host):
        return ["qwen2.5-coder:7b"]
    checker = ReadinessChecker()
    monkeypatch.setattr(checker, "_ollama_tags", fake_tags)
    results = await checker.check_ollama(expected_models=["whiterabbitneo:13b"])
    assert results[1].status is ComponentStatus.MISSING
    assert results[1].required is True


# ══════════════════════════════════════════════════════════════════════════
# check_kali_tools
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_kali_tools_configured_missing_and_ready(monkeypatch):
    """أداة مفقودة → MISSING مع إثبات probe؛ وأداة موجودة → READY."""
    checker = ReadinessChecker()

    def fake_probe(binary, timeout):
        if "missing" in binary:
            return {"status": "MISSING", "binary": binary, "path": None, "detail": "Not found on PATH"}
        return {"status": "READY", "binary": binary, "path": f"/usr/bin/{binary}", "detail": "v1.0"}

    import scripts.verify_kali_toolchain as vkt
    monkeypatch.setattr(vkt, "probe", fake_probe)

    configured = {
        "recon": {"nmap": {"cmd": "nmap"}, "ghost": {"cmd": "missing-tool-xyz"}},
    }
    results = await checker.check_kali_tools(configured=configured, required=["nmap", "ghost"])
    by_name = {r.name: r for r in results}
    assert by_name["nmap"].status is ComponentStatus.READY
    assert by_name["nmap"].required is True
    assert by_name["ghost"].status is ComponentStatus.MISSING
    assert "missing-tool-xyz" in by_name["ghost"].probe  # probe evidence
    assert isinstance(by_name["nmap"].evidence, dict)


@pytest.mark.asyncio
async def test_kali_probe_real_python_ready():
    """اختبار REAL محلي: python مُثبَت → probe حقيقي بلا شبكة/هدف."""
    checker = ReadinessChecker()
    results = await checker.check_kali_tools(
        configured={"misc": {"python": {"cmd": "python"}}}, required=["python"])
    assert len(results) == 1
    assert results[0].status is ComponentStatus.READY
    assert results[0].evidence.get("binary")  # مسار الثنائي الفعلي مُحمّل كإثبات


# ══════════════════════════════════════════════════════════════════════════
# _connectable_host — إصلاح عنوان الربط 0.0.0.0 (ظاهرة Windows حقيقية)
# ══════════════════════════════════════════════════════════════════════════

def test_connectable_host_fixes_bind_address():
    assert ReadinessChecker._connectable_host("http://0.0.0.0:11434") == "http://127.0.0.1:11434"
    assert ReadinessChecker._connectable_host("0.0.0.0:11434") == "http://127.0.0.1:11434"
    # عناوين سليمة تمر كما هي
    assert ReadinessChecker._connectable_host("http://127.0.0.1:11434") == "http://127.0.0.1:11434"
    assert ReadinessChecker._connectable_host("http://ollama.company:11434") == "http://ollama.company:11434"


@pytest.mark.asyncio
async def test_ollama_reports_configured_and_probed_host(monkeypatch):
    """التقرير يُظهر العنوانين: المُعدّ (0.0.0.0) والمُستخدم للاتصال (127.0.0.1)."""
    checker = ReadinessChecker(ollama_host="0.0.0.0:11434")

    async def fake_tags(host):
        return ["xploiter:latest"]
    monkeypatch.setattr(checker, "_ollama_tags", fake_tags)

    results = await checker.check_ollama(expected_models=["xploiter:latest"])
    server = results[0]
    assert server.status is ComponentStatus.READY
    assert server.evidence["configured_host"] == "0.0.0.0:11434"
    assert "127.0.0.1" in server.evidence["probed_host"]


# ══════════════════════════════════════════════════════════════════════════
# burp / playwright / wordlists
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_burp_proxy_tcp(monkeypatch):
    checker = ReadinessChecker()

    async def tcp(host, port):
        return port == 8080
    monkeypatch.setattr(checker, "_tcp_ready", tcp)

    res = await checker.check_burp_proxy()
    assert res.status is ComponentStatus.READY
    assert "8080" in res.detail

    res2 = await checker.check_burp_proxy(port=9999)
    assert res2.status is ComponentStatus.MISSING
    assert res2.required is False  # اختياري إلا عند --require-burp-browser


@pytest.mark.asyncio
async def test_gateway_skipped_when_not_listening(monkeypatch):
    checker = ReadinessChecker()

    async def tcp(host, port):
        return False
    monkeypatch.setattr(checker, "_tcp_ready", tcp)
    res = await checker.check_burp_gateway()
    assert res.status is ComponentStatus.SKIPPED


@pytest.mark.asyncio
async def test_run_all_isolates_crashed_check():
    """فشل معزول في فحص واحد لا يسقط التقرير وتُسجَل الحالة UNHEALTHY."""
    checker = ReadinessChecker()

    async def crash():
        raise RuntimeError("component crash")
    checker.check_burp_proxy = crash

    report = await checker.run_all(
        target="t", session_id="s", components=["burp_proxy", "playwright"])
    names = [r.name for r in report.results]
    assert "burp_proxy_check_crash" in names   # الفاشل مُسجَّل باسم مكوّنه
    assert report.results[0].status is ComponentStatus.UNHEALTHY
    # الفحوص الأخرى استمرت
    assert any(r.component == "playwright" for r in report.results)
    assert report.duration_sec > 0


@pytest.mark.asyncio
async def test_run_all_component_subset_only():
    checker = ReadinessChecker()
    report = await checker.run_all(target="t", session_id="s", components=["playwright"])
    assert all(r.component in ("playwright", "error") for r in report.results)
    assert any(r.component == "playwright" for r in report.results)


@pytest.mark.asyncio
async def test_wordlists_checked_really(tmp_path, monkeypatch):
    """wordlist resolve حقيقي → يقرأ المسار من الـ resolver الفعلي (محلي)."""
    checker = ReadinessChecker()
    results = await checker.check_wordlists()
    assert len(results) == 3
    for r in results:
        assert r.status in (ComponentStatus.READY, ComponentStatus.MISSING, ComponentStatus.UNHEALTHY)
        assert r.evidence.get("path") or r.detail  # إثبات المسار المُحلل


# ══════════════════════════════════════════════════════════════════════════
# artifact per session
# ══════════════════════════════════════════════════════════════════════════

def test_artifact_saved_per_session(tmp_path):
    report = ReadinessReport(target="dev.example.com", session_id="sess_42", results=[
        _ready("nmap"), _missing("sqlmap"),
    ])
    out = save_readiness_artifact(report, workspace_root=tmp_path)
    assert out is not None and out.is_file()
    assert ARTIFACT_NAME == "readiness_report.json"
    loaded = load_readiness_artifact(out)
    assert loaded["target"] == "dev.example.com"
    assert loaded["session_id"] == "sess_42"
    assert loaded["strict_ready"] is False
    assert loaded["counts"]["READY"] == 1
    # evidence dir
    assert "evidence" in str(out)


def test_artifact_default_dir_when_no_session(tmp_path, monkeypatch):
    report = ReadinessReport(target="", session_id="", results=[])
    monkeypatch.setattr("core.readiness.artifact.default_artifact_dir", lambda: tmp_path / "data" / "readiness")
    out = save_readiness_artifact(report)
    assert out is not None and out.parent.name == "readiness"


# ══════════════════════════════════════════════════════════════════════════
# mission gate config (Phase 1 wiring contract)
# ══════════════════════════════════════════════════════════════════════════

def test_gate_config_default_is_advisory():
    strict, components = mission_gate_config({})
    assert strict is False
    assert "kali_tools" in components and "ollama" in components


def test_gate_config_require_ready_is_strict():
    strict, components = mission_gate_config({"require_ready": True})
    assert strict is True
    assert set(components) >= {"kali_tools", "ollama"}


def test_gate_config_browser_forces_playwright_check():
    strict, components = mission_gate_config({
        "require_ready": True, "use_browser": True, "use_proxy": True,
    })
    assert strict is True
    assert "playwright" in components
    assert "burp_proxy" in components and "burp_gateway" in components


@pytest.mark.asyncio
async def test_run_mission_gate_strict_blocks(monkeypatch):
    from core.readiness.gate import run_mission_gate
    checker = ReadinessChecker()

    async def fake_kali():
        return [_missing("nmap")]
    checker.check_kali_tools = fake_kali

    with pytest.raises(ReadinessGateError):
        await run_mission_gate({"require_ready": True}, "t.example.com", "s1", checker=checker)
