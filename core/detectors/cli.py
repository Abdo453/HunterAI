"""CLI for the safe detector lab.

Examples
--------
Run all three detectors against an authorized target::

    python -m core.detectors.cli scan --target https://staging.example.com \
        --path /search --param q --class sqli

Run the hermetic demo (loopback fake target, no external traffic)::

    python -m core.detectors.cli demo

With a signed grant, every probe is checked before it leaves the process::

    $env:HUNTERAI_POLICY_SECRET = "..."
    python -m core.detectors.cli scan --target https://staging.example.com \
        --path /search --param q --grant grant.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Dict, List, Optional, Sequence
from urllib.parse import urlparse

from core.detectors.contract import Detection, DetectionContext
from core.detectors.evidence_chain import EvidenceChain
from core.detectors.idor import IDORDetector
from core.detectors.local_target import ALICE_CANARY, LocalFakeTarget
from core.detectors.sqli_boolean import SQLiBooleanDetector
from core.detectors.transport import HttpTransport, PolicyViolation, TransportConfig
from core.detectors.xss_reflected import XSSReflectedDetector

_DETECTORS = {
    "sqli": SQLiBooleanDetector,
    "xss": XSSReflectedDetector,
    "idor": IDORDetector,
}


def _parse_header(values: Sequence[str]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for item in values:
        if ":" not in item:
            raise SystemExit(f"header must be Name:Value, got {item!r}")
        name, value = item.split(":", 1)
        headers[name.strip()] = value.strip()
    return headers


def _build_transport(target: str, grant_path: str, profile: str) -> HttpTransport:
    host = urlparse(target).hostname
    if not host:
        raise SystemExit(f"invalid target: {target!r}")
    policy_engine = None
    if grant_path:
        secret = os.environ.get("HUNTERAI_POLICY_SECRET", "")
        if not secret:
            raise SystemExit(
                "HUNTERAI_POLICY_SECRET is required when --grant is used"
            )
        from core.policy.red_team import Profile, RedTeamPolicyEngine, load_grant

        policy_engine = RedTeamPolicyEngine(
            load_grant(grant_path), Profile(profile), secret.encode("utf-8")
        )
    return HttpTransport(
        TransportConfig(allowed_hosts={host}), policy_engine=policy_engine
    )


def _run_scan(args: argparse.Namespace) -> int:
    transport = _build_transport(args.target, args.grant, args.profile)
    context = DetectionContext(
        base_url=args.target,
        path=args.path,
        parameter=args.param,
        id_parameter=args.id_param,
        resource_id=args.resource_id,
        owner_headers=_parse_header(args.owner_header),
        other_headers=_parse_header(args.other_header),
        owner_marker=args.owner_marker,
    )

    selected = (
        list(_DETECTORS) if args.vuln_class == "all" else [args.vuln_class]
    )
    detections: List[Detection] = []
    chain = EvidenceChain()
    for name in selected:
        detector = _DETECTORS[name]()
        try:
            detection = detector.detect(context, transport)
        except PolicyViolation as exc:
            print(json.dumps({"error": "policy_denied", "reason": str(exc)}))
            return 2
        detections.append(detection)
        chain.append_all(detection)

    summary = {
        "target": args.target,
        "path": args.path,
        "chain_verified": chain.verify(),
        "records": len(chain.records),
        "detections": [detection.to_dict() for detection in detections],
    }
    print(json.dumps(summary, indent=2))
    if args.out:
        chain.save(args.out)
        print(f"evidence chain written to {args.out}", file=sys.stderr)
    return 0


def _run_demo() -> int:
    checks = []
    with LocalFakeTarget() as target:
        transport = HttpTransport(
            TransportConfig(allowed_hosts={"127.0.0.1"})
        )
        scenarios = [
            (
                "sqli.vulnerable",
                SQLiBooleanDetector(),
                DetectionContext(target.base_url, "/search", "q"),
                True,
            ),
            (
                "sqli.safe",
                SQLiBooleanDetector(),
                DetectionContext(target.base_url, "/search/safe", "q"),
                False,
            ),
            (
                "xss.vulnerable",
                XSSReflectedDetector(),
                DetectionContext(target.base_url, "/echo", "name"),
                True,
            ),
            (
                "xss.safe",
                XSSReflectedDetector(),
                DetectionContext(target.base_url, "/echo/safe", "name"),
                False,
            ),
            (
                "idor.vulnerable",
                IDORDetector(),
                DetectionContext(
                    target.base_url,
                    "/profile",
                    id_parameter="id",
                    resource_id="1",
                    owner_headers={"X-User": "alice"},
                    other_headers={"X-User": "bob"},
                    owner_marker=ALICE_CANARY,
                ),
                True,
            ),
            (
                "idor.safe",
                IDORDetector(),
                DetectionContext(
                    target.base_url,
                    "/profile/safe",
                    id_parameter="id",
                    resource_id="1",
                    owner_headers={"X-User": "alice"},
                    other_headers={"X-User": "bob"},
                    owner_marker=ALICE_CANARY,
                ),
                False,
            ),
        ]

        chain = EvidenceChain()
        for label, detector, context, expected in scenarios:
            detection = detector.detect(context, transport)
            chain.append_all(detection)
            checks.append(
                {
                    "check": label,
                    "expected_confirmed": expected,
                    "confirmed": detection.confirmed,
                    "reason": detection.reason,
                }
            )

        only_get = all(item["method"] == "GET" for item in target.requests)
        chain_ok = chain.verify()
        ok = (
            all(item["confirmed"] == item["expected_confirmed"] for item in checks)
            and only_get
            and chain_ok
        )
        print(
            json.dumps(
                {
                    "ok": ok,
                    "only_get_requests": only_get,
                    "requests": len(target.requests),
                    "chain_verified": chain_ok,
                    "checks": checks,
                },
                indent=2,
            )
        )
        return 0 if ok else 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="run detectors against one endpoint")
    scan.add_argument("--target", required=True)
    scan.add_argument("--path", default="/")
    scan.add_argument("--param", default="")
    scan.add_argument("--class", dest="vuln_class", default="all", choices=["sqli", "xss", "idor", "all"])
    scan.add_argument("--id-param", default="id")
    scan.add_argument("--resource-id", default="1")
    scan.add_argument("--owner-header", action="append", default=[])
    scan.add_argument("--other-header", action="append", default=[])
    scan.add_argument("--owner-marker", default="")
    scan.add_argument("--grant", default="")
    scan.add_argument("--profile", default="red_team")
    scan.add_argument("--out", default="")
    scan.set_defaults(func=_run_scan)

    demo = sub.add_parser("demo", help="run the hermetic loopback demo")
    demo.set_defaults(func=lambda args: _run_demo())

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
