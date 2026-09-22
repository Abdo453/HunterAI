import pytest
import tempfile
from pathlib import Path
from fastapi.testclient import TestClient
from core.burp_gateway.capture_store import CaptureStore
from core.burp_gateway.gateway import BurpGateway

@pytest.fixture
def tmp_store(tmp_path):
    return CaptureStore("test.target.local", base_dir=tmp_path)

@pytest.fixture
def gateway_client(tmp_path):
    store = CaptureStore("test.target.local", base_dir=tmp_path)
    gw = BurpGateway(capture_store=store)
    return TestClient(gw.app), gw

@pytest.fixture
def scoped_gateway_client(tmp_path):
    store = CaptureStore("app.target.local", base_dir=tmp_path)
    from core.scope_guard import ScopeGuard
    scope = ScopeGuard(in_scope=["app.target.local", "*.app.target.local"], out_of_scope=["evil.com"])
    gw = BurpGateway(capture_store=store, scope_engine=scope)
    gw.set_scope(include=["app.target.local", "*.app.target.local"], exclude=["evil.com"])
    return TestClient(gw.app), gw
