"""Authorized red-team mode: zero-friction execution inside a signed scope.

What this module is
-------------------
A policy engine for engagements where the operator has **explicit, signed
authorization** and does not want per-action confirmation prompts.  The
``RED_TEAM`` profile removes friction: no approval queue, ``critical`` risk
ceiling, active testing and exploit-proof actions allowed, all catalog tools
allowed.

What this module refuses to do
------------------------------
Some actions are **hard invariants**: they are denied in every profile, for
every grant, even a valid ``RED_TEAM`` grant.  Authorization is a legal
permission to test a target; it is not a permission to turn a target into
malware infrastructure.

Denied always:

* ``BACKDOOR`` / ``PERSISTENCE`` (webshells, cron/systemd/registry persistence,
  SSH key injection, implants),
* ``C2`` (reverse shells, beaconing, command-and-control),
* ``LATERAL_MOVEMENT`` (pivoting to hosts outside the grant),
* ``DESTRUCTIVE_WRITE`` (SQL DELETE/UPDATE/DROP/TRUNCATE, file deletion,
  service shutdown),
* ``EVASION`` (log tampering, anti-forensics, disabling monitoring),
* ``DATA_EXFILTRATION`` (bulk copying of real user data),
* ``CREDENTIAL_DUMP`` (dumping password stores or secrets at scale).

Proof is still allowed: a SQL injection can be proven with a read-only
boolean/time-based payload, RCE with ``id``/``whoami``, SSRF with an
operator-owned out-of-band listener, IDOR with two-account differential
testing and canary data.

Usage
-----
>>> secret = b"engagement-secret"
>>> grant = AuthorizationGrant.sign(
...     secret,
...     grant_id="ENG-001",
...     authorized_by="Acme Security",
...     scope=[ScopeTarget("domain", "example.com")],
...     not_before=time.time() - 60,
...     not_after=time.time() + 3600,
...     profiles=[Profile.RED_TEAM],
... )
>>> engine = RedTeamPolicyEngine(grant, Profile.RED_TEAM, secret)
>>> engine.evaluate(
...     ActionRequest("https://example.com/login", ActionClass.EXPLOIT_PROOF)
... ).allowed
True

CLI
---
Create a signed grant (secret comes from ``HUNTERAI_POLICY_SECRET``)::

    python -m core.policy.red_team grant --scope example.com --days 7 \
        --authorized-by "Acme" --out grant.json

Check an action::

    python -m core.policy.red_team check --grant grant.json \
        --target https://example.com/login --class exploit_proof
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import re
import sys
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

__all__ = [
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


class ActionClass(str, Enum):
    """What kind of action is being attempted."""

    READ_ONLY = "read_only"
    ACTIVE_TEST = "active_test"
    PROOF_WRITE = "proof_write"
    EXPLOIT_PROOF = "exploit_proof"
    FORBIDDEN = "forbidden"


class ForbiddenAction(str, Enum):
    """Actions that no profile or grant can authorize."""

    BACKDOOR = "backdoor"
    PERSISTENCE = "persistence"
    C2 = "c2"
    LATERAL_MOVEMENT = "lateral_movement"
    DESTRUCTIVE_WRITE = "destructive_write"
    EVASION = "evasion"
    DATA_EXFILTRATION = "data_exfiltration"
    CREDENTIAL_DUMP = "credential_dump"


class Profile(str, Enum):
    """Execution profiles, from read-only to authorized red team."""

    SAFE = "safe"
    STANDARD = "standard"
    RED_TEAM = "red_team"


_RISK_ORDER: Dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}

_PROFILE_RULES: Dict[Profile, Dict[str, Any]] = {
    Profile.SAFE: {
        "classes": {ActionClass.READ_ONLY},
        "max_risk": "low",
        "approval": set(),
    },
    Profile.STANDARD: {
        "classes": {
            ActionClass.READ_ONLY,
            ActionClass.ACTIVE_TEST,
            ActionClass.PROOF_WRITE,
            ActionClass.EXPLOIT_PROOF,
        },
        "max_risk": "high",
        "approval": {ActionClass.EXPLOIT_PROOF},
    },
    Profile.RED_TEAM: {
        "classes": {
            ActionClass.READ_ONLY,
            ActionClass.ACTIVE_TEST,
            ActionClass.PROOF_WRITE,
            ActionClass.EXPLOIT_PROOF,
        },
        "max_risk": "critical",
        "approval": set(),
    },
}

# Defence in depth: the enum is the primary control; these patterns catch an
# operation string that contradicts the declared action class.  They are not
# an exhaustive malware detector, and they are not a substitute for the enum.
_DESTRUCTIVE_PATTERNS = re.compile(
    r"(?i)("
    r"\b(drop|truncate)\s+(table|database|schema)\b"
    r"|\bdelete\s+from\b"
    r"|\bupdate\s+[a-z0-9_.\"]+\s+set\b"
    r"|\binsert\s+into\b"
    r"|\balter\s+table\b"
    r"|\brm\s+-[a-z]*r[a-z]*f?\b"
    r"|\bmkfs(\.\w+)?\b"
    r"|\bformat\s+[a-z]:"
    r"|\b(shutdown|reboot|halt|poweroff)\b"
    r")"
)

_PERSISTENCE_PATTERNS = re.compile(
    r"(?i)("
    r"webshell|web-shell|web shell"
    r"|/etc/cron|crontab\s+-"
    r"|authorized_keys|\.ssh/authorized"
    r"|systemctl\s+enable|/etc/systemd"
    r"|schtasks\s+/create|reg\s+add\s+.*\\run"
    r"|launchctl\s+load|/library/launchagents"
    r"|bash\s+-i\s*>&|nc\s+-e|ncat\s+-e|socat\s+.*exec"
    r"|reverse\s*shell|bind\s*shell|meterpreter|beacon"
    r"|base64\s+-d\s*\|.*sh"
    r")"
)

_EXFIL_PATTERNS = re.compile(
    r"(?i)("
    r"\bdump\s+(all\s+)?(user|password|hash|credential)s?\b"
    r"|/etc/shadow|sam\s+file|ntds\.dit"
    r"|\bexfiltrat(e|ion)\b"
    r"|tar\s+.*\|\s*(curl|wget|nc)\b"
    r")"
)

_EVASION_PATTERNS = re.compile(
    r"(?i)("
    r"clear\s+(the\s+)?(logs|history)|wevtutil\s+cl"
    r"|unset\s+histfile|shred\s+.*log"
    r"|disable\s+(audit|logging|edr|av|defender)"
    r"|timestomp|anti[- ]forensic"
    r")"
)


def _normalize_host(value: str) -> str:
    text = str(value or "").strip().lower()
    if "://" in text:
        text = urlparse(text).hostname or ""
    elif text.startswith("["):
        # IPv6 literal such as [::1]:8080
        text = text[1:].split("]", 1)[0]
    else:
        text = text.split("/", 1)[0]
        if text.count(":") == 1:
            text = text.split(":", 1)[0]
    return text.strip(".")


@dataclass(frozen=True)
class ScopeTarget:
    """One authorized target: domain suffix, exact host, CIDR, or URL prefix."""

    kind: str
    value: str

    def __post_init__(self) -> None:
        kind = str(self.kind or "").strip().lower()
        if kind not in {"domain", "host", "cidr", "url"}:
            raise ValueError(f"unsupported scope kind: {self.kind!r}")
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "value", str(self.value or "").strip())
        if not self.value:
            raise ValueError("scope value is required")

    def matches(self, target: str) -> bool:
        text = str(target or "").strip()
        if not text:
            return False
        if self.kind == "cidr":
            host = _normalize_host(text)
            try:
                return ipaddress.ip_address(host) in ipaddress.ip_network(
                    self.value, strict=False
                )
            except ValueError:
                return False
        if self.kind == "url":
            parsed = urlparse(text if "://" in text else "https://" + text)
            base = urlparse(self.value if "://" in self.value else "https://" + self.value)
            if (parsed.scheme, parsed.hostname, parsed.port) != (
                base.scheme,
                base.hostname,
                base.port,
            ):
                return False
            base_path = (base.path or "/").rstrip("/")
            target_path = (parsed.path or "/").rstrip("/")
            return target_path == base_path or target_path.startswith(base_path + "/")
        host = _normalize_host(text)
        expected = _normalize_host(self.value)
        if not host or not expected:
            return False
        if self.kind == "host":
            return host == expected
        # domain: exact or any subdomain
        return host == expected or host.endswith("." + expected)

    def to_dict(self) -> Dict[str, str]:
        return {"kind": self.kind, "value": self.value}


def _canonical_grant_payload(
    grant_id: str,
    authorized_by: str,
    scope: Sequence[ScopeTarget],
    not_before: float,
    not_after: float,
    profiles: Sequence[Profile],
) -> bytes:
    payload = {
        "grant_id": grant_id,
        "authorized_by": authorized_by,
        "scope": [item.to_dict() for item in scope],
        "not_before": float(not_before),
        "not_after": float(not_after),
        "profiles": sorted(item.value for item in profiles),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class AuthorizationGrant:
    """A signed authorization envelope for one engagement."""

    grant_id: str
    authorized_by: str
    scope: Tuple[ScopeTarget, ...]
    not_before: float
    not_after: float
    profiles: Tuple[Profile, ...]
    signature: str

    @classmethod
    def sign(
        cls,
        secret: bytes,
        *,
        grant_id: str,
        authorized_by: str,
        scope: Sequence[ScopeTarget],
        not_before: float,
        not_after: float,
        profiles: Sequence[Profile],
    ) -> "AuthorizationGrant":
        targets = tuple(scope)
        profile_items = tuple(profiles)
        if not targets:
            raise ValueError("a grant needs at least one scope target")
        if not profile_items:
            raise ValueError("a grant needs at least one profile")
        if not_after <= not_before:
            raise ValueError("not_after must be later than not_before")
        payload = _canonical_grant_payload(
            grant_id, authorized_by, targets, not_before, not_after, profile_items
        )
        signature = hmac.new(secret, payload, hashlib.sha256).hexdigest()
        return cls(
            grant_id=grant_id,
            authorized_by=authorized_by,
            scope=targets,
            not_before=float(not_before),
            not_after=float(not_after),
            profiles=profile_items,
            signature=signature,
        )

    def verify(self, secret: bytes) -> bool:
        payload = _canonical_grant_payload(
            self.grant_id,
            self.authorized_by,
            self.scope,
            self.not_before,
            self.not_after,
            self.profiles,
        )
        expected = hmac.new(secret, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, self.signature)

    def active_at(self, now: float) -> bool:
        return self.not_before <= float(now) <= self.not_after

    def allows_profile(self, profile: Profile) -> bool:
        return profile in self.profiles

    def matches_target(self, target: str) -> bool:
        return any(item.matches(target) for item in self.scope)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "grant_id": self.grant_id,
            "authorized_by": self.authorized_by,
            "scope": [item.to_dict() for item in self.scope],
            "not_before": self.not_before,
            "not_after": self.not_after,
            "profiles": [item.value for item in self.profiles],
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuthorizationGrant":
        if not isinstance(data, dict):
            raise ValueError("grant must be a JSON object")
        return cls(
            grant_id=str(data.get("grant_id") or ""),
            authorized_by=str(data.get("authorized_by") or ""),
            scope=tuple(
                ScopeTarget(str(item.get("kind")), str(item.get("value")))
                for item in (data.get("scope") or [])
                if isinstance(item, dict)
            ),
            not_before=float(data.get("not_before") or 0),
            not_after=float(data.get("not_after") or 0),
            profiles=tuple(Profile(str(item)) for item in (data.get("profiles") or [])),
            signature=str(data.get("signature") or ""),
        )


@dataclass(frozen=True)
class ActionRequest:
    """One proposed action that must pass the policy engine."""

    target: str
    action_class: ActionClass
    tool_id: str = ""
    risk_level: str = "low"
    forbidden_action: Optional[ForbiddenAction] = None
    operation: str = ""
    mutates_state: bool = False


@dataclass(frozen=True)
class Decision:
    allowed: bool
    requires_approval: bool
    reason: str
    audit_id: str
    evaluated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "requires_approval": self.requires_approval,
            "reason": self.reason,
            "audit_id": self.audit_id,
            "evaluated_at": self.evaluated_at,
        }


class AuditLog:
    """Append-only JSONL audit log with a hash chain.

    Every decision is linked to the previous record's hash, so deleting or
    editing an entry in the middle breaks verification.
    """

    def __init__(self, path: Optional[str] = None):
        self._path = Path(path) if path else None
        self._records: List[Dict[str, Any]] = []
        self._last_hash = "0" * 64
        if self._path and self._path.exists():
            for line in self._path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    record = json.loads(line)
                    self._records.append(record)
                    self._last_hash = str(record.get("hash") or self._last_hash)

    def append(self, decision: Decision, request: ActionRequest) -> Dict[str, Any]:
        record = {
            "audit_id": decision.audit_id,
            "target": request.target,
            "action_class": request.action_class.value,
            "tool_id": request.tool_id,
            "risk_level": request.risk_level,
            "allowed": decision.allowed,
            "requires_approval": decision.requires_approval,
            "reason": decision.reason,
            "evaluated_at": decision.evaluated_at,
            "prev_hash": self._last_hash,
        }
        blob = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        record["hash"] = hashlib.sha256(blob).hexdigest()
        self._records.append(record)
        self._last_hash = record["hash"]
        if self._path:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
        return record

    def records(self) -> List[Dict[str, Any]]:
        return list(self._records)

    def verify(self) -> bool:
        previous = "0" * 64
        for record in self._records:
            if record.get("prev_hash") != previous:
                return False
            body = {key: value for key, value in record.items() if key != "hash"}
            blob = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
            if hashlib.sha256(blob).hexdigest() != record.get("hash"):
                return False
            previous = str(record["hash"])
        return True


class RedTeamPolicyEngine:
    """Evaluates actions against a signed grant and hard safety invariants."""

    def __init__(
        self,
        grant: AuthorizationGrant,
        profile: Profile,
        secret: bytes,
        *,
        now: Optional[float] = None,
        audit_log: Optional[AuditLog] = None,
        max_actions_per_minute: int = 600,
    ):
        self._grant = grant
        self._profile = profile
        self._secret = secret
        self._clock = now or time.time
        self._audit = audit_log or AuditLog()
        self._limit = int(max_actions_per_minute)
        self._recent: List[float] = []

    @property
    def grant(self) -> AuthorizationGrant:
        return self._grant

    @property
    def profile(self) -> Profile:
        return self._profile

    def evaluate(self, request: ActionRequest) -> Decision:
        decision = self._decide(request)
        self._audit.append(decision, request)
        return decision

    def _decide(self, request: ActionRequest) -> Decision:
        def deny(reason: str) -> Decision:
            return Decision(
                allowed=False,
                requires_approval=False,
                reason=reason,
                audit_id=self._new_audit_id(),
            )

        # 1. Hard invariants: no grant can authorize these.
        if request.forbidden_action is not None:
            return deny(
                "hard invariant: "
                f"{request.forbidden_action.value} is never authorized, even with a valid grant"
            )
        if request.action_class == ActionClass.FORBIDDEN:
            return deny("hard invariant: forbidden action class is never authorized")

        operation = str(request.operation or "")
        if operation:
            if _DESTRUCTIVE_PATTERNS.search(operation):
                return deny(
                    "hard invariant: destructive write/operation detected in the request"
                )
            if _PERSISTENCE_PATTERNS.search(operation):
                return deny(
                    "hard invariant: persistence/backdoor/reverse-shell pattern detected"
                )
            if _EXFIL_PATTERNS.search(operation):
                return deny("hard invariant: data exfiltration/credential dump detected")
            if _EVASION_PATTERNS.search(operation):
                return deny("hard invariant: evasion/anti-forensics detected")
        if request.mutates_state and request.action_class == ActionClass.READ_ONLY:
            return deny("inconsistent request: a state-mutating action cannot be read-only")

        # 2. Grant validity.
        if not self._grant.verify(self._secret):
            return deny("authorization grant signature is invalid")
        now = float(self._clock())
        if not self._grant.active_at(now):
            return deny("authorization grant is not valid at this time")
        if not self._grant.allows_profile(self._profile):
            return deny(f"grant does not authorize profile '{self._profile.value}'")

        # 3. Scope.
        if not self._grant.matches_target(request.target):
            return deny(f"target '{request.target}' is outside the authorized scope")

        # 4. Profile rules.
        rules = _PROFILE_RULES[self._profile]
        if request.action_class not in rules["classes"]:
            return deny(
                f"profile '{self._profile.value}' does not allow "
                f"action class '{request.action_class.value}'"
            )
        tool_risk = _RISK_ORDER.get(str(request.risk_level or "low").lower(), _RISK_ORDER["medium"])
        max_risk = _RISK_ORDER[rules["max_risk"]]
        if tool_risk > max_risk:
            return deny(
                f"risk level '{request.risk_level}' exceeds the profile ceiling "
                f"'{rules['max_risk']}'"
            )

        # 5. Rate limit (per engine instance).
        cutoff = now - 60.0
        self._recent = [stamp for stamp in self._recent if stamp >= cutoff]
        if len(self._recent) >= self._limit:
            return deny(
                f"rate limit reached: {self._limit} actions per minute for this engine"
            )
        self._recent.append(now)

        requires_approval = request.action_class in rules["approval"]
        if requires_approval:
            return Decision(
                allowed=False,
                requires_approval=True,
                reason=(
                    f"profile '{self._profile.value}' requires operator approval for "
                    f"'{request.action_class.value}'"
                ),
                audit_id=self._new_audit_id(),
            )
        return Decision(
            allowed=True,
            requires_approval=False,
            reason=(
                f"authorized by grant '{self._grant.grant_id}' "
                f"({self._grant.authorized_by}) under profile '{self._profile.value}'"
            ),
            audit_id=self._new_audit_id(),
        )

    @staticmethod
    def _new_audit_id() -> str:
        return "AUD-" + uuid.uuid4().hex[:12]


def save_grant(grant: AuthorizationGrant, path: str) -> None:
    Path(path).write_text(
        json.dumps(grant.to_dict(), indent=2, sort_keys=True), encoding="utf-8"
    )


def load_grant(path: str) -> AuthorizationGrant:
    return AuthorizationGrant.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def _secret_from_env() -> bytes:
    value = os.environ.get("HUNTERAI_POLICY_SECRET", "")
    if not value:
        raise SystemExit(
            "HUNTERAI_POLICY_SECRET is required; set it to the engagement signing secret"
        )
    return value.encode("utf-8")


def _cmd_grant(args: argparse.Namespace) -> int:
    secret = _secret_from_env()
    now = time.time()
    grant = AuthorizationGrant.sign(
        secret,
        grant_id=args.grant_id,
        authorized_by=args.authorized_by,
        scope=[ScopeTarget("domain", item) for item in args.scope],
        not_before=now,
        not_after=now + float(args.days) * 86400.0,
        profiles=[Profile(item) for item in args.profiles],
    )
    save_grant(grant, args.out)
    print(f"wrote {args.out} (grant {grant.grant_id}, expires in {args.days} day(s))")
    return 0


def _cmd_check(args: argparse.Namespace) -> int:
    secret = _secret_from_env()
    grant = load_grant(args.grant)
    engine = RedTeamPolicyEngine(grant, Profile(args.profile), secret)
    request = ActionRequest(
        target=args.target,
        action_class=ActionClass(args.action_class),
        tool_id=args.tool or "",
        risk_level=args.risk,
        operation=args.operation or "",
    )
    decision = engine.evaluate(request)
    print(json.dumps(decision.to_dict(), indent=2))
    return 0 if decision.allowed else 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    grant = sub.add_parser("grant", help="create a signed authorization grant")
    grant.add_argument("--grant-id", default="ENG-" + uuid.uuid4().hex[:8])
    grant.add_argument("--authorized-by", required=True)
    grant.add_argument("--scope", action="append", required=True, help="domain, repeatable")
    grant.add_argument("--days", type=float, default=7.0)
    grant.add_argument(
        "--profiles",
        action="append",
        default=["red_team"],
        choices=[item.value for item in Profile],
    )
    grant.add_argument("--out", default="authorization_grant.json")
    grant.set_defaults(func=_cmd_grant)

    check = sub.add_parser("check", help="check one action against a grant")
    check.add_argument("--grant", required=True)
    check.add_argument("--target", required=True)
    check.add_argument(
        "--class",
        dest="action_class",
        default=ActionClass.EXPLOIT_PROOF.value,
        choices=[item.value for item in ActionClass],
    )
    check.add_argument(
        "--profile",
        default=Profile.RED_TEAM.value,
        choices=[item.value for item in Profile],
    )
    check.add_argument("--tool", default="")
    check.add_argument("--risk", default="low")
    check.add_argument("--operation", default="")
    check.set_defaults(func=_cmd_check)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
