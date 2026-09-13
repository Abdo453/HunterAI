"""
HunterAI AST Workflow & Concurrency Remediation Engine
======================================================
Synthesizes production-ready AST patches and regression tests for:
1. Workflow Step Enforcement (Preventing step-skipping via session/token guards)
2. Distributed Idempotency Keys (Preventing double-spend / replay)
3. Atomic Pessimistic Row Locking (Preventing TOCTOU balance decrement races)
"""
from __future__ import annotations

import difflib
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class WorkflowRemediationRequest:
    flaw_type: str  # "STEP_SKIPPING", "RE_ENTRANCY", "MISSING_IDEMPOTENCY_KEY", "CHECK_THEN_ACT"
    route: str
    file_path: str = "views.py"
    function_name: str = "handle_request"
    framework: str = "fastapi"  # "fastapi", "flask", or "django"


@dataclass
class WorkflowRemediationResult:
    flaw_type: str
    target_file: str
    git_diff: str
    defense_middleware_code: str
    patched_endpoint_snippet: str
    regression_test_code: str
    developer_guidance: str


class WorkflowRemediationEngine:
    """
    Generates defensive Python middleware, decorators, and atomic database
    transactions to neutralize business logic and concurrency vulnerabilities.
    """

    @classmethod
    def generate_remediation(cls, request: WorkflowRemediationRequest) -> WorkflowRemediationResult:
        ft = request.flaw_type.upper()
        if "SKIP" in ft or "STEP" in ft:
            return cls._remediate_step_skipping(request)
        elif "IDEMPOTENCY" in ft or "REPLAY" in ft or "RE_ENTRANCY" in ft:
            return cls._remediate_idempotency(request)
        elif "CHECK_THEN_ACT" in ft or "LOCK" in ft or "TOCTOU" in ft or "RACE" in ft:
            return cls._remediate_concurrency_race(request)
        else:
            return cls._remediate_step_skipping(request)

    @classmethod
    def _create_git_diff(cls, file_path: str, orig: str, patched: str) -> str:
        orig_lines = orig.splitlines(keepends=True)
        patched_lines = patched.splitlines(keepends=True)
        diff = difflib.unified_diff(
            orig_lines,
            patched_lines,
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
            lineterm=""
        )
        return "".join(diff)

    @classmethod
    def _remediate_step_skipping(cls, req: WorkflowRemediationRequest) -> WorkflowRemediationResult:
        orig = f"""# Vulnerable Endpoint: Missing prerequisite step check
@app.post("{req.route}")
async def {req.function_name}(request: Request):
    data = await request.json()
    # Flaw: Directly executes final mutation without verifying prior funnel steps
    order = db.create_order(data)
    return {{"status": "confirmed", "order_id": order.id}}
"""
        patched = f"""# Patched Endpoint: Protected by Workflow Step Guard
from core.security.guards import require_workflow_step

@app.post("{req.route}")
@require_workflow_step(required_steps=["STEP_CART", "STEP_PAYMENT"])
async def {req.function_name}(request: Request):
    data = await request.json()
    order = db.create_order(data)
    return {{"status": "confirmed", "order_id": order.id}}
"""
        middleware = """# Reusable Workflow Guard Decorator
from functools import wraps
from fastapi import HTTPException, Request

def require_workflow_step(required_steps: list):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            request = kwargs.get("request") or (args[0] if args else None)
            session = getattr(request, "session", {})
            completed = session.get("completed_steps", [])
            for step in required_steps:
                if step not in completed:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Precondition Failed: Workflow step '{step}' must be completed."
                    )
            return await func(*args, **kwargs)
        return wrapper
    return decorator
"""
        test = f"""# Automated Regression Suite: Verifies Step Skipping Prevention
import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_step_skipping_blocked_without_prerequisites(client: AsyncClient):
    # Direct jump to confirmation without payment
    response = await client.post("{req.route}", json={{"item": "laptop"}})
    assert response.status_code == 400
    assert "Precondition Failed" in response.json()["detail"]

@pytest.mark.asyncio
async def test_valid_step_sequence_succeeds(client: AsyncClient):
    # Complete cart, then payment, then confirmation
    await client.post("/api/cart/add", json={{"item": "laptop"}})
    await client.post("/api/checkout/pay", json={{"amount": 100}})
    response = await client.post("{req.route}", json={{"item": "laptop"}})
    assert response.status_code == 200
    assert response.json()["status"] == "confirmed"
"""
        return WorkflowRemediationResult(
            flaw_type="STEP_SKIPPING",
            target_file=req.file_path,
            git_diff=cls._create_git_diff(req.file_path, orig, patched),
            defense_middleware_code=middleware,
            patched_endpoint_snippet=patched,
            regression_test_code=test,
            developer_guidance="Enforces that all required prerequisites must be satisfied in the user session before executing terminal action."
        )

    @classmethod
    def _remediate_idempotency(cls, req: WorkflowRemediationRequest) -> WorkflowRemediationResult:
        orig = f"""# Vulnerable Endpoint: Non-idempotent mutation without replay protection
@app.post("{req.route}")
async def {req.function_name}(request: Request):
    payload = await request.json()
    result = payment_service.charge(payload)
    return {{"status": "success", "charge_id": result.id}}
"""
        patched = f"""# Patched Endpoint: Enforces Idempotency-Key Header
from core.security.idempotency import idempotent

@app.post("{req.route}")
@idempotent(key_header="Idempotency-Key", expire_seconds=300)
async def {req.function_name}(request: Request):
    payload = await request.json()
    result = payment_service.charge(payload)
    return {{"status": "success", "charge_id": result.id}}
"""
        middleware = """# Reusable Idempotency Filter with Distributed Cache
import redis
from functools import wraps
from fastapi import HTTPException, Request, Response

redis_client = redis.Redis(host="localhost", port=6379, db=0)

def idempotent(key_header="Idempotency-Key", expire_seconds=300):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            request = kwargs.get("request") or (args[0] if args else None)
            idem_key = request.headers.get(key_header)
            if not idem_key:
                raise HTTPException(status_code=400, detail="Missing required Idempotency-Key header.")
            
            cache_key = f"idem:{idem_key}"
            # Atomic set NX (only if not exists)
            acquired = redis_client.set(cache_key, "PROCESSING", nx=True, ex=expire_seconds)
            if not acquired:
                raise HTTPException(status_code=409, detail="Duplicate request: Already processed or currently in-flight.")
            
            try:
                res = await func(*args, **kwargs)
                return res
            except Exception:
                redis_client.delete(cache_key)
                raise
        return wrapper
    return decorator
"""
        test = f"""# Automated Regression Suite: Idempotency Verification
import pytest
import uuid
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_duplicate_idempotency_key_rejected(client: AsyncClient):
    unique_key = str(uuid.uuid4())
    headers = {{"Idempotency-Key": unique_key}}
    
    # First request must succeed
    res1 = await client.post("{req.route}", headers=headers, json={{"amount": 50}})
    assert res1.status_code == 200
    
    # Second duplicate request with identical key must be rejected
    res2 = await client.post("{req.route}", headers=headers, json={{"amount": 50}})
    assert res2.status_code == 409
    assert "Duplicate request" in res2.json()["detail"]
"""
        return WorkflowRemediationResult(
            flaw_type="MISSING_IDEMPOTENCY_KEY",
            target_file=req.file_path,
            git_diff=cls._create_git_diff(req.file_path, orig, patched),
            defense_middleware_code=middleware,
            patched_endpoint_snippet=patched,
            regression_test_code=test,
            developer_guidance="Guarantees at-most-once execution for mutating financial and quota endpoints using atomic cache reservation."
        )

    @classmethod
    def _remediate_concurrency_race(cls, req: WorkflowRemediationRequest) -> WorkflowRemediationResult:
        orig = f"""# Vulnerable: Check-Then-Act without DB row-level locking
def {req.function_name}(account_id: int, amount: int):
    account = Account.objects.get(id=account_id)
    # TOCTOU Window: Concurrent threads both see balance >= amount
    if account.balance >= amount:
        account.balance -= amount
        account.save()
        return True
    return False
"""
        patched = f"""# Patched: Pessimistic Row Locking with atomic transaction
from django.db import transaction

def {req.function_name}(account_id: int, amount: int):
    with transaction.atomic():
        # SELECT ... FOR UPDATE locks the row until transaction commit
        account = Account.objects.select_for_update().get(id=account_id)
        if account.balance >= amount:
            account.balance -= amount
            account.save()
            return True
        return False
"""
        test = f"""# Automated Regression Suite: Concurrency Race Condition Safety
import threading
from django.test import TestCase

class ConcurrencySafetyTest(TestCase):
    def test_concurrent_debit_prevents_negative_balance(self):
        account = Account.objects.create(balance=100)
        results = []

        def worker():
            res = {req.function_name}(account.id, 100)
            results.append(res)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        account.refresh_from_db()
        assert results.count(True) == 1
        assert results.count(False) == 4
        assert account.balance == 0
"""
        return WorkflowRemediationResult(
            flaw_type="CHECK_THEN_ACT_WINDOW",
            target_file=req.file_path,
            git_diff=cls._create_git_diff(req.file_path, orig, patched),
            defense_middleware_code="# Use database row-level locking: SELECT ... FOR UPDATE",
            patched_endpoint_snippet=patched,
            regression_test_code=test,
            developer_guidance="Enforces serialized row mutation within an ACID transaction using select_for_update() to close the TOCTOU gap."
        )
