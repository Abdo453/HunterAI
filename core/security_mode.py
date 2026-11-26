"""Owner Execution Mode — single source of truth for agent execution latitude.
================================================================================

Governance defaults are **fail-closed**:

  * ``unrestricted_mode()`` returns ``False`` unless ``HUNTER_UNRESTRICTED`` is
    explicitly set to a truthy value (``1/true/yes/on/enabled/unrestricted``) or
    enabled programmatically via ``set_unrestricted(True)``.
  * ``web_governance_enforced()`` returns ``True`` unless
    ``HUNTER_WEB_UNRESTRICTED`` is explicitly set to a truthy value.

What these switches NEVER weaken (result integrity, deliberately preserved):

  * Proof-of-Execution is still required BEFORE a finding is CONFIRMED.
  * The Evidence Court still rejects reflection / free-text / assumption proofs.
  * Scanner signals still enter as hypotheses, not confirmed findings.
  * Secret sanitization still scrubs every artifact written to disk.
"""
from __future__ import annotations

import os

_ENV_VAR = "HUNTER_UNRESTRICTED"
_WEB_UNRESTRICTED_ENV_VAR = "HUNTER_WEB_UNRESTRICTED"

# Values that explicitly opt into unrestricted execution / disable governance.
_FALSY = {"0", "false", "no", "off", "disabled", "governed", "restricted"}
_TRUTHY = {"1", "true", "yes", "on", "enabled", "unrestricted"}


def unrestricted_mode() -> bool:
    """Return True ONLY when the owner explicitly opts into unrestricted execution.

    Defaults to ``False`` (fail-closed governance). Set ``HUNTER_UNRESTRICTED``
    to an explicit truthy value (``1/true/yes/on/enabled/unrestricted``) or call
    ``set_unrestricted(True)`` to opt into unrestricted mode.
    """
    value = os.getenv(_ENV_VAR)
    if value is None:
        return False
    clean = value.strip().lower()
    if not clean:
        return False
    return clean in _TRUTHY


def set_unrestricted(enabled: bool) -> None:
    """Programmatically toggle the execution mode (used by CLI/flags and tests)."""
    os.environ[_ENV_VAR] = "1" if enabled else "0"


def web_governance_enforced() -> bool:
    """Return True unless strict web/API scope governance is explicitly disabled.

    Defaults to ``True`` (fail-closed web scope governance). Set
    ``HUNTER_WEB_UNRESTRICTED`` to an explicit truthy value
    (``1/true/yes/on/enabled/unrestricted``) to opt into unrestricted web target
    mode (non-overridable Cloud Metadata/link-local SSRF, dangerous schemes,
    shell metacharacters, traversal, and CSRF/Origin checks still remain enforced).
    """
    value = os.getenv(_WEB_UNRESTRICTED_ENV_VAR)
    if value is None:
        return True
    clean = value.strip().lower()
    if not clean:
        return True
    return clean not in _TRUTHY
