"""Owner Execution Mode — single source of truth for agent execution latitude.
================================================================================

The operator owns this platform and runs it on their own machine, so the
DEFAULT is **UNRESTRICTED execution**: the agent acts with FULL permissions —
any target, any action, no scope gating, no policy blocks, no active-testing
authorization flag and no human-approval queues.

What this switch does NOT touch (result integrity, deliberately preserved):

  * Proof-of-Execution is still required BEFORE a finding is CONFIRMED.
  * The Evidence Court still rejects reflection / free-text / assumption proofs.
  * Scanner signals still enter as hypotheses, not confirmed findings.
  * Secret sanitization still scrubs every artifact written to disk.

In other words: full freedom to *execute* — zero freedom to *fake results*.

Set ``HUNTER_UNRESTRICTED=0`` to restore fail-closed governance. The security
test-suite sets this to exercise the guarded code paths.
"""
from __future__ import annotations

import os

_ENV_VAR = "HUNTER_UNRESTRICTED"

# Values that explicitly disable unrestricted mode (i.e. restore governance).
_FALSY = {"0", "false", "no", "off", "disabled", "governed", "restricted"}


def unrestricted_mode() -> bool:
    """Return True when the owner grants the agent full execution permissions.

    Defaults to True (owner machine, full permissions). Any of
    ``0/false/no/off/disabled/governed/restricted`` in ``HUNTER_UNRESTRICTED``
    restores fail-closed governance.
    """
    value = os.getenv(_ENV_VAR)
    if value is None:
        return True
    return value.strip().lower() not in _FALSY


def set_unrestricted(enabled: bool) -> None:
    """Programmatically toggle the execution mode (used by CLI/flags and tests)."""
    os.environ[_ENV_VAR] = "1" if enabled else "0"
