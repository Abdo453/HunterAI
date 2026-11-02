"""Capability model and policy binding for the root controller tree.

Two layers, both fail-closed:

1. **Capability layer** -- every agent carries a set of named capabilities
   (``recon``, ``active_testing``, ``exploit_verify``, ...).  A capability is
   required before an action class is even offered to the signed-grant engine.
2. **Policy layer** -- ``core.policy.red_team.RedTeamPolicyEngine`` evaluates
   the action against the HMAC-signed authorization grant: scope match, profile
   risk ceiling, approval rules, and the hard invariants (no persistence, no
   C2, no destructive writes, no evasion, no bulk credential dumping, no
   exfiltration, no lateral movement outside the grant).

With no grant loaded, every action is denied.

Python 3.11.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence
from urllib.parse import urlparse

from core.policy.red_team import (
    ActionClass,
    ActionRequest,
    AuditLog,
    Decision,
    ForbiddenAction,
    Profile,
    RedTeamPolicyEngine,
    load_grant,
)

__all__ = [
    "ACTION_CAPABILITIES",
    "DEFAULT_CAPABILITIES",
    "PermissionPolicy",
    "PermissionSet",
    "PROFILE_CAPABILITIES",
]


DEFAULT_CAPABILITIES: tuple[str, ...] = (
    "recon",
    "scan",
    "active_testing",
    "vuln_verification",
    "exploit_verify",
    "evidence_adjudication",
    "reporting",
    "osint",
    "cloud_audit",
    "mobile_audit",
    "web3_audit",
    "wireless_audit",
    "ot_audit",
    "lead_management",
)

# Which capabilities satisfy which action class.  The action class is the
# coarse gate; the capability set is the per-agent gate.
ACTION_CAPABILITIES: Dict[str, tuple[str, ...]] = {
    "read_only": (
        "recon",
        "scan",
        "active_testing",
        "vuln_verification",
        "exploit_verify",
        "osint",
        "cloud_audit",
        "mobile_audit",
        "web3_audit",
        "wireless_audit",
        "ot_audit",
    ),
    "active_test": ("active_testing", "vuln_verification", "exploit_verify"),
    "proof_write": ("vuln_verification", "exploit_verify"),
    "exploit_proof": ("exploit_verify",),
}

PROFILE_CAPABILITIES: Dict[Profile, tuple[str, ...]] = {
    Profile.SAFE: ("recon", "osint", "reporting", "lead_management"),
    Profile.STANDARD: tuple(
        c
        for c in DEFAULT_CAPABILITIES
        if c
        not in ("exploit_verify", "cloud_audit", "mobile_audit", "web3_audit", "wireless_audit", "ot_audit")
    ),
    Profile.RED_TEAM: DEFAULT_CAPABILITIES,
}


@dataclass(frozen=True)
class PermissionSet:
    """Immutable capability set with set algebra."""

    names: frozenset[str]

    @classmethod
    def from_iterable(cls, values: Optional[Iterable[str]]) -> "PermissionSet":
        if values is None:
            return cls(frozenset())
        return cls(frozenset(str(v) for v in values))

    def allows(self, name: str) -> bool:
        return name in self.names

    def allows_any(self, names: Sequence[str]) -> bool:
        return any(name in self.names for name in names)

    def union(self, other: "PermissionSet") -> "PermissionSet":
        return PermissionSet(self.names | other.names)

    def intersect(self, other: "PermissionSet") -> "PermissionSet":
        return PermissionSet(self.names & other.names)

    def is_subset_of(self, other: "PermissionSet") -> bool:
        return self.names <= other.names

    def to_list(self) -> List[str]:
        return sorted(self.names)

    def __contains__(self, item: object) -> bool:
        return item in self.names

    def __iter__(self):
        return iter(sorted(self.names))

    def __len__(self) -> int:
        return len(self.names)

    def __bool__(self) -> bool:
        return bool(self.names)


class PermissionPolicy:
    """Binds the agent tree to a signed authorization grant."""

    def __init__(
        self,
        *,
        engine: Optional[RedTeamPolicyEngine] = None,
        profile: Profile = Profile.SAFE,
        capabilities: Optional[Iterable[str]] = None,
        fail_closed: bool = True,
    ) -> None:
        self._engine = engine
        self._profile = profile
        self._capabilities = PermissionSet.from_iterable(
            capabilities if capabilities is not None else PROFILE_CAPABILITIES[profile]
        )
        self._fail_closed = bool(fail_closed)

    # -- construction ------------------------------------------------------
    @classmethod
    def from_grant(
        cls,
        grant_path: str,
        profile: Profile = Profile.RED_TEAM,
        *,
        secret: Optional[bytes] = None,
        capabilities: Optional[Iterable[str]] = None,
        audit_log: Optional[AuditLog] = None,
    ) -> "PermissionPolicy":
        """Build a policy bound to a signed grant file.

        The signing secret comes from ``HUNTERAI_POLICY_SECRET`` unless given
        explicitly.  A tampered grant (bad signature, expired window) raises
        here rather than degrading into an open policy.
        """
        if secret is None:
            env_secret = os.environ.get("HUNTERAI_POLICY_SECRET", "")
            if not env_secret:
                raise PermissionError(
                    "HUNTERAI_POLICY_SECRET is not set; refusing to load an "
                    "unsigned or unverifiable grant"
                )
            secret = env_secret.encode("utf-8")
        grant = load_grant(grant_path)
        engine = RedTeamPolicyEngine(
            grant, profile, secret, audit_log=audit_log
        )
        return cls(
            engine=engine,
            profile=profile,
            capabilities=(
                capabilities
                if capabilities is not None
                else PROFILE_CAPABILITIES[profile]
            ),
        )

    # -- accessors ---------------------------------------------------------
    @property
    def engine(self) -> Optional[RedTeamPolicyEngine]:
        return self._engine

    @property
    def profile(self) -> Profile:
        return self._profile

    @property
    def capabilities(self) -> PermissionSet:
        return self._capabilities

    @property
    def bound(self) -> bool:
        return self._engine is not None

    def scope_targets(self) -> List[str]:
        """Scope entries as plain values the tool registry can match.

        The registry's secondary scope check compares host strings, so a
        ``domain``/``host`` entry is passed verbatim, a ``url`` entry is
        reduced to its host, and a ``cidr`` entry keeps its network string.
        The authoritative match is always the grant's own
        ``ScopeTarget.matches`` -- see ``RootController.auth_context``.
        """
        if self._engine is None:
            return []
        values: List[str] = []
        for entry in self._engine.grant.scope:
            if entry.kind == "url":
                parsed = urlparse(entry.value if "://" in entry.value else f"https://{entry.value}")
                values.append(parsed.hostname or entry.value)
            else:
                values.append(entry.value)
        return values

    def scope_entries(self) -> List[Dict[str, str]]:
        """Scope entries with their kind, for display and audit records."""
        if self._engine is None:
            return []
        return [entry.to_dict() for entry in self._engine.grant.scope]

    def grant_id(self) -> str:
        return self._engine.grant.grant_id if self._engine else ""

    # -- evaluation --------------------------------------------------------
    def check(
        self,
        agent: Any,
        target: str,
        action_class: str = "read_only",
        *,
        tool_id: str = "",
        risk_level: str = "low",
        operation: str = "",
        mutates_state: bool = False,
        forbidden_action: Optional[ForbiddenAction] = None,
    ) -> Decision:
        """Evaluate one proposed action for one agent.

        Returns a :class:`Decision`; ``allowed`` is the single source of truth
        for the caller.  Denials carry the reason that produced them.
        """
        try:
            action = ActionClass(action_class)
        except ValueError:
            action = ActionClass.READ_ONLY

        if action is ActionClass.FORBIDDEN or forbidden_action is not None:
            reason = (
                f"forbidden action: {forbidden_action.value}"
                if forbidden_action
                else "forbidden action class"
            )
            return Decision(
                allowed=False, requires_approval=False, reason=reason, audit_id=""
            )

        required = ACTION_CAPABILITIES.get(action.value, ())
        agent_caps = PermissionSet.from_iterable(
            getattr(agent, "capabilities", None) or []
        )
        if required and not agent_caps.allows_any(required):
            return Decision(
                allowed=False,
                requires_approval=False,
                reason=(
                    f"agent '{getattr(agent, 'agent_id', 'unknown')}' holds no capability "
                    f"for {action.value}; needs one of: {', '.join(required)}"
                ),
                audit_id="",
            )

        if self._engine is None:
            if self._fail_closed:
                return Decision(
                    allowed=False,
                    requires_approval=False,
                    reason=(
                        "fail-closed: no signed authorization grant is bound to this "
                        "controller"
                    ),
                    audit_id="",
                )
            return Decision(
                allowed=True,
                requires_approval=False,
                reason="no policy engine bound (fail_closed disabled)",
                audit_id="",
            )

        request = ActionRequest(
            target=target,
            action_class=action,
            tool_id=tool_id,
            risk_level=risk_level,
            forbidden_action=forbidden_action,
            operation=operation,
            mutates_state=mutates_state,
        )
        return self._engine.evaluate(request)

    def describe(self) -> Dict[str, Any]:
        """Machine-readable description of the active policy."""
        return {
            "profile": self._profile.value,
            "bound": self.bound,
            "grant_id": self.grant_id(),
            "scope": self.scope_targets(),
            "capabilities": self._capabilities.to_list(),
            "fail_closed": self._fail_closed,
            "action_class_requirements": {
                key: list(value) for key, value in ACTION_CAPABILITIES.items()
            },
            "hard_invariants": [
                action.value for action in ForbiddenAction
            ],
        }
