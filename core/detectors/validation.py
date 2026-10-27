"""Lab-scoped adapter for the production 7-Question Validation Gate.

``hunter_ai.validation_gate.ValidationGate`` blocks loopback targets by design
(its scope engine treats ``127.0.0.0/8`` as inviolable).  That is the right
behaviour for production, but the hermetic lab runs on loopback.  This adapter
reuses every gate question and only overrides the scope check for an explicit
lab allowlist; the neuro-symbolic safety loop is replaced with an ALLOWED
result, while the scope question still enforces the allowlist.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Iterable
from urllib.parse import urlparse

from hunter_ai.validation_gate import GateResult, ValidationGate


class _LabSafetyResult:
    def __init__(self, target: str):
        self.target = target
        self.reason = "loopback lab allowlist"
        self.verdict = SimpleNamespace(value="ALLOWED")

    def to_dict(self):
        return {
            "verdict": "ALLOWED",
            "target": self.target,
            "reason": self.reason,
        }


class _LabSafetyLoop:
    def check_command(self, command: str, target: str, require_proof: bool = False):
        return _LabSafetyResult(target)


class LabValidationGate(ValidationGate):
    """7-Question Gate that treats an explicit loopback allowlist as in scope."""

    def __init__(self, allowed_hosts: Iterable[str], **kwargs):
        super().__init__(**kwargs)
        self._allowed_hosts = {str(host).lower() for host in allowed_hosts}
        self._lab_safety = _LabSafetyLoop()

    @property
    def safety_loop(self):  # type: ignore[override]
        return self._lab_safety

    def _q2_in_scope(self, target: str) -> GateResult:
        host = (urlparse(target).hostname or "").lower()
        if host in self._allowed_hosts:
            return GateResult(
                "Q2: In scope?",
                True,
                f"{host} is in the lab allowlist",
            )
        return GateResult(
            "Q2: In scope?",
            False,
            f"{host or target} is not in the lab allowlist",
        )
