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
import hmac
import hashlib
import ipaddress
import json
import os
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
ENV_PATH = ROOT / ".env"
DEFAULT_SECRET = "hunter-ai-default-authorized-secret"


def _ensure_secret() -> bytes:
    """Load HUNTERAI_POLICY_SECRET from .env, creating it if absent."""
    existing = {}
    if ENV_PATH.exists():
        for line in ENV_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                existing[k.strip()] = v.strip()

    secret = existing.get("HUNTERAI_POLICY_SECRET")
    if not secret:
        # deterministic per-machine default so the grant stays valid across runs
        secret = hmac.new(
            b"hunterai-grant-rotation-v1",
            ROOT.as_posix().encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if ENV_PATH.exists():
            body = ENV_PATH.read_text(encoding="utf-8").rstrip("\n") + "\n"
        else:
            body = ""
        body += f"HUNTERAI_POLICY_SECRET={secret}\n"
        ENV_PATH.write_text(body, encoding="utf-8")
        print(f"[+] wrote HUNTERAI_POLICY_SECRET to {ENV_PATH}")
    else:
        print(f"[+] using existing HUNTERAI_POLICY_SECRET from {ENV_PATH}")
    return secret.encode("utf-8")


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
    secret = _ensure_secret()
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
    print("    /abh-network-killchain  (OpenCode agent executes the full chain)")
    print(f"    python scripts/authorize_full_power.py --check <target>   # verify in-scope")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    secret = _ensure_secret()
    if not GRANT_PATH.exists():
        print("[!] no active authorization grant — DENIED by default.")
        print("    issue one first: python scripts/authorize_full_power.py issue --scope ...")
        return 1
    grant = load_grant(str(GRANT_PATH))
    engine = RedTeamPolicyEngine(grant, Profile.RED_TEAM, secret)
    for klass in ("read_only", "active_test", "exploit_proof"):
        request = ActionRequest(
            target=args.target,
            action_class=ActionClass(klass),
            tool_id="check",
            risk_level="critical",
            operation="probe",
        )
        decision = engine.evaluate(request)
        print(f"{klass:<14} -> {'ALLOWED' if decision.allowed else 'DENIED'} ({decision.reason})")
    return 0


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
