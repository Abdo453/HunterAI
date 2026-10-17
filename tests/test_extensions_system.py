"""
Unit Tests for Extension System — Phase 6
Tests: manifest validation (fail-closed), trust assessment,
       permission enforcement (HostAPI), registry install/enable flow.
"""
import json

import pytest

from extensions_ext.loader import (
    ExtensionError, HostAPI, PermissionDenied, activate_extension,
)
from extensions_ext.manifest import (
    ExtensionManifest, ManifestError, Permission, validate_manifest,
)
from extensions_ext.registry import ExtensionRegistry
from extensions_ext.trust import TrustLevel, assess_trust


def _write_ext(tmp_path, name="test-ext", perms=None, entry="main.py",
               body="def run():\n    return 'ok'\n"):
    d = tmp_path / name
    d.mkdir(parents=True, exist_ok=True)
    (d / entry).write_text(body, encoding="utf-8")
    manifest = {
        "name": name,
        "version": "1.0.0",
        "entry": entry,
        "permissions": perms or [],
    }
    (d / "plugin.json").write_text(
        json.dumps(manifest), encoding="utf-8")
    return d


# ── Manifest validation ───────────────────────────────────────────────────

class TestManifest:
    def test_valid_manifest(self):
        m = validate_manifest({
            "name": "my-ext", "version": "1.2.3", "entry": "main.py",
            "permissions": [Permission.READ_WORKSPACE],
        })
        assert m.name == "my-ext"
        assert Permission.READ_WORKSPACE in m.permissions

    def test_missing_required_field(self):
        with pytest.raises(ManifestError, match="ناقص"):
            validate_manifest({"name": "x", "version": "1.0.0"})

    def test_bad_name_rejected(self):
        with pytest.raises(ManifestError, match="اسم"):
            validate_manifest({
                "name": "Bad Name!", "version": "1.0.0", "entry": "main.py"})

    def test_bad_version_rejected(self):
        with pytest.raises(ManifestError, match="إصدار"):
            validate_manifest({
                "name": "ok", "version": "1.0", "entry": "main.py"})

    def test_path_traversal_entry_rejected(self):
        with pytest.raises(ManifestError, match="آمن"):
            validate_manifest({
                "name": "ok", "version": "1.0.0", "entry": "../evil.py"})

    def test_unknown_permission_rejected(self):
        with pytest.raises(ManifestError, match="صلاحية غير معروفة"):
            validate_manifest({
                "name": "ok", "version": "1.0.0", "entry": "main.py",
                "permissions": ["root_access"]})

    def test_non_py_entry_rejected(self):
        with pytest.raises(ManifestError, match="entry"):
            validate_manifest({
                "name": "ok", "version": "1.0.0", "entry": "main.js"})


# ── Trust ─────────────────────────────────────────────────────────────────

class TestTrust:
    def test_local_no_high_risk_is_high(self, tmp_path):
        d = _write_ext(tmp_path)
        from extensions_ext.manifest import load_manifest
        m = load_manifest(d)
        report = assess_trust(m, d, is_local=True)
        assert report.level == TrustLevel.HIGH
        assert report.allowed

    def test_high_risk_downgrades_to_medium(self, tmp_path):
        d = _write_ext(tmp_path, perms=[Permission.RUN_TOOL])
        from extensions_ext.manifest import load_manifest
        m = load_manifest(d)
        report = assess_trust(m, d, is_local=True)
        assert report.level == TrustLevel.MEDIUM

    def test_read_env_downgrades_to_low(self, tmp_path):
        d = _write_ext(tmp_path, perms=[Permission.READ_ENV])
        from extensions_ext.manifest import load_manifest
        m = load_manifest(d)
        report = assess_trust(m, d, is_local=True)
        assert report.level == TrustLevel.LOW

    def test_missing_entry_file_is_none(self, tmp_path):
        d = tmp_path / "broken"
        d.mkdir()
        (d / "plugin.json").write_text(json.dumps({
            "name": "broken", "version": "1.0.0", "entry": "missing.py"}))
        from extensions_ext.manifest import load_manifest
        m = load_manifest(d)
        report = assess_trust(m, d)
        assert report.level == TrustLevel.NONE
        assert not report.allowed

    def test_min_level_enforced(self, tmp_path):
        d = _write_ext(tmp_path, perms=[Permission.READ_ENV])
        from extensions_ext.manifest import load_manifest
        m = load_manifest(d)
        report = assess_trust(m, d, min_level=TrustLevel.MEDIUM)
        assert not report.allowed


# ── HostAPI permission enforcement ────────────────────────────────────────

class TestHostAPI:
    def _manifest(self, perms):
        return ExtensionManifest(
            name="x", version="1.0.0", entry="main.py", permissions=perms)

    def test_read_denied_without_permission(self, tmp_path):
        api = HostAPI(self._manifest([]), tmp_path)
        with pytest.raises(PermissionDenied):
            api.read_workspace("f.txt")

    def test_write_denied_without_permission(self, tmp_path):
        api = HostAPI(self._manifest([]), tmp_path)
        with pytest.raises(PermissionDenied):
            api.write_workspace("out.txt", b"x")

    def test_write_allowed_with_permission(self, tmp_path):
        api = HostAPI(self._manifest([Permission.WRITE_WORKSPACE]), tmp_path)
        p = api.write_workspace("out.txt", b"hello")
        assert p.read_bytes() == b"hello"

    def test_path_traversal_blocked(self, tmp_path):
        api = HostAPI(self._manifest([Permission.WRITE_WORKSPACE]), tmp_path)
        with pytest.raises(PermissionDenied, match="traversal"):
            api.write_workspace("../escape.txt", b"x")

    def test_run_tool_denied_without_permission(self, tmp_path):
        api = HostAPI(self._manifest([]), tmp_path,
                      tool_runner=lambda name, **kw: "ran")
        with pytest.raises(PermissionDenied):
            api.run_tool("nmap")

    def test_call_llm_denied_without_permission(self, tmp_path):
        api = HostAPI(self._manifest([]), tmp_path,
                      llm_caller=lambda p, **kw: "reply")
        with pytest.raises(PermissionDenied):
            api.call_llm("hi")


# ── Registry install/enable ───────────────────────────────────────────────

class TestRegistry:
    def test_install_and_enable(self, tmp_path):
        d = _write_ext(tmp_path, name="safe-ext")
        reg = ExtensionRegistry(
            extensions_root=str(tmp_path / "root"),
            min_trust=TrustLevel.LOW)
        rec = reg.install(d)
        assert rec.manifest.name == "safe-ext"
        module = reg.enable("safe-ext")
        assert module.run() == "ok"
        assert reg.get("safe-ext").enabled
        assert reg.disable("safe-ext")
        assert not reg.get("safe-ext").enabled

    def test_install_rejects_untrusted(self, tmp_path):
        d = _write_ext(tmp_path, name="env-ext", perms=[Permission.READ_ENV])
        reg = ExtensionRegistry(
            extensions_root=str(tmp_path / "root"),
            min_trust=TrustLevel.MEDIUM)   # أدنى ثقة أعلى مما تقدّم الإضافة
        with pytest.raises(ExtensionError, match="الثقة"):
            reg.install(d)

    def test_enable_uninstalled_raises(self, tmp_path):
        reg = ExtensionRegistry(extensions_root=str(tmp_path / "root"))
        with pytest.raises(ExtensionError, match="غير مثبّتة"):
            reg.enable("ghost")

    def test_list_extensions_shape(self, tmp_path):
        d = _write_ext(tmp_path, name="listed")
        reg = ExtensionRegistry(extensions_root=str(tmp_path / "root"))
        reg.install(d)
        items = reg.list_extensions()
        assert len(items) == 1
        assert items[0]["name"] == "listed"
        assert "trust_level" in items[0]
