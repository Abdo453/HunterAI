"""Global test configuration.

The platform's DEFAULT runtime mode is *unrestricted* (owner full permissions).
The security test-suite, however, must keep exercising the fail-closed
governance paths (scope invariants, policy gate, approval gates). We therefore
force GOVERNED mode for the test session.

Tests that specifically validate unrestricted mode flip the switch back with
``monkeypatch.setenv("HUNTER_UNRESTRICTED", "1")``.
"""
import os

os.environ["HUNTER_UNRESTRICTED"] = "0"
