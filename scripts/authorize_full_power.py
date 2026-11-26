#!/usr/bin/env python3
"""
authorize_full_power.py — one command: scope + authorization -> signed red_team grant
=====================================================================================
The operator provides scope and authorization ONCE. This script:

  1. Reads/creates the signing secret (HUNTERAI_POLICY_SECRET) from .env
  2. Parses each scope item: CIDR, IP, URL, or domain -> ScopeTarget(kind, value)
  3. Signs an AuthorizationGrant with the red_team profile (full capability set,
     no per-action approval required)
  4. Saves it to data/root_controller/authorization_grant.json (verified readback)
  5. Prints the autonomous-run commands

Usage:
    python scripts/authorize_full_power.py issue --scope example.com,10.10.0.0/24 --authorized-by "Client Owner SOW-77" --days 7
    python scripts/authorize_full_power.py check --target example.com   # test a target against the grant
    python scripts/authorize_full_power.py revoke                       # invalidate current grant
"""
from __future__ import annotations

import argparse
import ipaddress
import os
import secrets
import stat
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.policy.red_team import (  # noqa: E402
    ActionClass,
    ActionRequest,
    AuthorizationGrant,
    Profile,
    RedTeamPolicyEngine,
    ScopeTarget,
    load_grant,
    save_grant,
)

GRANT_PATH = ROOT / "data" / "root_controller" / "authorization_grant.json"
KEY_PATH = ROOT / "data" / "root_controller" / ".policy_secret"
_MIN_SECRET_LEN = 32
_BANNED_SECRETS = {
    "hunter-ai-default-authorized-secret",
    "changeme",
    "secret",
    "default",
}


def _validate_secret_material(raw: str, source: str) -> bytes:
    """Validate signing secret integrity; fail closed if missing, weak, or corrupt."""
    cleaned = raw.strip()
    if not cleaned:
        raise RuntimeError(f"Signing secret from {source} is empty (fail-closed).")
    if any(ch.isspace() or ord(ch) < 33 or ord(ch) > 126 for ch in cleaned):
        raise RuntimeError(f"Signing secret from {source} contains invalid/corrupt characters.")
    if len(cleaned) < _MIN_SECRET_LEN:
        raise RuntimeError(
            f"Signing secret from {source} is too short (< {_MIN_SECRET_LEN} chars)."
        )
    if cleaned.lower() in _BANNED_SECRETS:
        raise RuntimeError(f"Signing secret from {source} uses a banned static secret.")
    return cleaned.encode("utf-8")


def _write_owner_only_key(key_path: Path, secret: str) -> None:
    """Persist CSPRNG key material with owner-only permissions (0o600 on POSIX)."""
    key_path.parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(str(key_path), flags, 0o600)
        try:
            os.write(fd, (secret + "\n").encode("utf-8"))
        finally:
            os.close(fd)
        os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)
    else:
        key_path.write_text(secret + "\n", encoding="utf-8")


def _ensure_secret(*, create_if_missing: bool = False, key_path: Path | None = None) -> bytes:
    """Load policy signing secret from HUNTERAI_POLICY_SECRET or owner-only key file.

    Never falls back to static or deterministic path-derived secrets.
    When ``create_if_missing=True`` (used only during ``issue``), generates a
    256-bit CSPRNG secret via ``secrets.token_hex(32)`` and persists it under
    ``key_path`` (mode 0o600 on POSIX). Fails closed if the key is missing
    (when ``create_if_missing=False``) or corrupt.
    """
    env_secret = os.environ.get("HUNTERAI_POLICY_SECRET")
    if env_secret is not None:
        return _validate_secret_material(env_secret, "HUNTERAI_POLICY_SECRET")

    target_key = key_path or KEY_PATH
    if target_key.exists():
        try:
            raw = target_key.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise RuntimeError(f"Policy key file {target_key} is unreadable/corrupt: {exc}") from exc
        if os.name != "nt":
            mode = stat.S_IMODE(target_key.stat().st_mode)
            if mode & (stat.S_IRWXG | stat.S_IRWXO):
                os.chmod(target_key, stat.S_IRUSR | stat.S_IWUSR)
        secret_bytes = _validate_secret_material(raw, str(target_key))
        print(f"[+] using existing policy key from {target_key}")
        return secret_bytes

    if not create_if_missing:
        raise RuntimeError(
            f"Missing policy signing secret: set HUNTERAI_POLICY_SECRET or initialize {target_key} via 'issue'."
        )

    generated = secrets.token_hex(32)
    _write_owner_only_key(target_key, generated)
    print(f"[+] generated CSPRNG policy key -> {target_key}")
    return generated.encode("utf-8")


def _parse_target(value: str) -> ScopeTarget:
    v = value.strip().split("/")[0].strip()
    raw = value.strip()
    try:
        ipaddress.ip_network(raw, strict=False)
        return ScopeTarget("cidr", raw)
    except ValueError:
        pass
    try:
        ipaddress.ip_address(raw)
        return ScopeTarget("host", raw)
    except ValueError:
        pass
    if raw.startswith(("http://", "https://")):
        return ScopeTarget("url", raw)
    return ScopeTarget("domain", raw)


def cmd_issue(args: argparse.Namespace) -> int:
    try:
        secret = _ensure_secret(create_if_missing=True)
    except RuntimeError as exc:
        print(f"[!] {exc}")
        return 1
    now = time.time()
    scope = [_parse_target(x) for x in ",".join(args.scope).split(",") if x.strip()]
    grant = AuthorizationGrant.sign(
        secret,
        grant_id=args.grant_id or "ENG-" + uuid.uuid4().hex[:8],
        authorized_by=args.authorized_by,
        scope=scope,
        not_before=now - 300,
        not_after=now + args.days * 86400.0,
        profiles=[Profile.RED_TEAM],
    )
    GRANT_PATH.parent.mkdir(parents=True, exist_ok=True)
    save_grant(grant, str(GRANT_PATH))
    verified = load_grant(str(GRANT_PATH))
    if not verified.verify(secret):
        print("!! grant failed signature verification on readback — do NOT run autonomous")
        return 1
    print(f"[+] grant {verified.grant_id} signed -> {GRANT_PATH}")
    print(f"    scope      : {[f'{t.kind}:{t.value}' for t in verified.scope]}")
    print(f"    authorized : {verified.authorized_by}")
    print(f"    validity   : {args.days} day(s) (red_team profile, full power)")
    print(f"    signature  : verified (HMAC-SHA256)")
    print()
    print("Ready. Autonomous entry points:")
    print(f"    python pentest.py autopilot {verified.scope[0].value}")
    print("    hunterai-redteam        (central project skill routes the requested chain)")
    print(f"    python scripts/authorize_full_power.py check --target <target>   # verify in-scope")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    try:
        secret = _ensure_secret(create_if_missing=False)
    except RuntimeError as exc:
        print(f"[!] {exc} — DENIED (fail-closed).")
        return 1
    if not GRANT_PATH.exists():
        print("[!] no active authorization grant — DENIED by default.")
        print("    issue one first: python scripts/authorize_full_power.py issue --scope ...")
        return 1
    try:
        grant = load_grant(str(GRANT_PATH))
    except Exception as exc:
        print(f"[!] failed to load authorization grant ({exc}) — DENIED (fail-closed).")
        return 1
    engine = RedTeamPolicyEngine(grant, Profile.RED_TEAM, secret)
    all_allowed = True
    for klass in ("read_only", "active_test", "exploit_proof"):
        request = ActionRequest(
            target=args.target,
            action_class=ActionClass(klass),
            tool_id="check",
            risk_level="critical",
            operation="probe",
        )
        decision = engine.evaluate(request)
        if not decision.allowed:
            all_allowed = False
        print(f"{klass:<14} -> {'ALLOWED' if decision.allowed else 'DENIED'} ({decision.reason})")
    return 0 if all_allowed else 1


def cmd_revoke(_: argparse.Namespace) -> int:
    if GRANT_PATH.exists():
        GRANT_PATH.unlink()
        print(f"[-] revoked: {GRANT_PATH}")
    else:
        print("no active grant to revoke")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("issue", help="sign a full-power red_team grant")
    g.add_argument("--scope", action="append", required=True, help="domain|ip|cidr|url (repeatable or comma list)")
    g.add_argument("--authorized-by", required=True)
    g.add_argument("--days", type=float, default=7.0)
    g.add_argument("--grant-id", default="")
    g.set_defaults(func=cmd_issue)

    c = sub.add_parser("check", help="test a target against the current grant")
    c.add_argument("--target", required=True)
    c.set_defaults(func=cmd_check)

    r = sub.add_parser("revoke", help="remove the current grant")
    r.set_defaults(func=cmd_revoke)

    args = p.parse_args()
    if len(sys.argv) == 1:
        p.print_help()
        return 0
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
