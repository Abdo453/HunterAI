from .policy_as_code import (
    PolicyAsCodeEngine,
    EnvironmentTier,
    PolicyDecision,
    PolicyReceipt,
)

__all__ = [
    "PolicyAsCodeEngine",
    "EnvironmentTier",
    "PolicyDecision",
    "PolicyReceipt",
    # Lazily imported from ``core.policy.red_team`` (PEP 562) so that running
    # ``python -m core.policy.red_team`` does not import the module twice.
    "ActionClass",
    "ActionRequest",
    "AuditLog",
    "AuthorizationGrant",
    "Decision",
    "ForbiddenAction",
    "Profile",
    "RedTeamPolicyEngine",
    "ScopeTarget",
    "load_grant",
    "save_grant",
]

_RED_TEAM_EXPORTS = {
    "ActionClass",
    "ActionRequest",
    "AuditLog",
    "AuthorizationGrant",
    "Decision",
    "ForbiddenAction",
    "Profile",
    "RedTeamPolicyEngine",
    "ScopeTarget",
    "load_grant",
    "save_grant",
}


def __getattr__(name: str):
    if name in _RED_TEAM_EXPORTS:
        from . import red_team

        return getattr(red_team, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
