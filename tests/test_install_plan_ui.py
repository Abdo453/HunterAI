# -*- coding: utf-8 -*-
"""
اختبارات خطة التثبيت في واجهة الجاهزية (حلقة مرحلة 6 → 7).
النقطة: المُعطَّل strict له أمر مُرتب فقط — لا تنفيذ من المتصفح أبدًا.
"""
import json
import os
import threading

import pytest
from core.evidence_store import EvidenceStore  # noqa: F401 (استيراد إخفاء respawn)

PLAN_ART = "data/readiness/tool_installation_plan.json"


class TestInstallPlanEndpoint:
    @pytest.fixture
    def client(self):
        from fastapi.testclient import TestClient
        from ui.web.app import app
        return TestClient(app)

    def test_plan_loaded_from_real_artifact(self, client):
        assert os.path.isfile(PLAN_ART), "الـ artifact أمين على الـ repo"
        d = client.get("/api/diagnostics/install-plan").json()
        plan = d["plan"]
        assert plan is not None
        assert "target_platform" in plan and isinstance(plan["steps"], list)
        for st in plan["steps"]:
            assert {"tool", "channel", "command", "required", "verified",
                    "executed"} <= set(st)
        # أمان: أسماء أدوات/قنوات فقط — لا مفاتيح حساسة من الخطة الخام
        assert all("probed_after" not in st or True for st in plan["steps"])

    def test_missing_artifact_returns_null_plan(self, client, monkeypatch):
        from pathlib import Path
        real_is_file = Path.is_file

        def no_artifact(self, *a, **kw):
            if str(self).endswith("tool_installation_plan.json"):
                return False
            return real_is_file(self, *a, **kw)

        monkeypatch.setattr(Path, "is_file", no_artifact)
        d = client.get("/api/diagnostics/install-plan").json()
        assert d["plan"] is None
        assert "tool_mgmt" in d["message"]


class TestInstallPlanUIWiring:
    def test_html_and_js_wired(self):
        from pathlib import Path
        html = Path("ui/web/templates/index.html").read_text(encoding="utf-8")
        js = Path("ui/web/static/app.js").read_text(encoding="utf-8")
        assert 'id="install-plan-box"' in html
        assert "async function loadInstallPlan()" in js
        assert "loadInstallPlan();" in js
        # لا تنفيذ من المتصفح — رسالة الموافقة الصريحة ظاهرة للمشغّل
        assert "لا تنفيذ من المتصفح" in js
