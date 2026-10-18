"""
HunterAI Lead Board — Hunt Memory
=================================
Persistent per-target lead ledger that routes every recon observation to the
right hunt-* skill and tracks its status so no lead is forgotten.

Inspired by Agentic-Bug-Hunter's `lead_board.py`.
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


from enum import Enum


class LeadStatus(str, Enum):
    UNTOUCHED = "untouched"
    INVESTIGATING = "investigating"
    KILLED = "killed"
    REPORTED = "reported"


@dataclass
class Lead:
    lead_id: str
    target: str
    signal_type: str  # idor, ssrf, graphql, oauth, samll, llm, source-leak, tech-stack, nuclei, ...
    description: str
    status: LeadStatus = LeadStatus.UNTOUCHED
    created_at: float = 0.0
    updated_at: float = 0.0
    route_to: str = ""  # hunt-* skill name
    evidence: dict = field(default_factory=dict)


class LeadBoard:
    """Persistent lead board — never lose a lead."""

    def __init__(self, memory_dir: str = "memory/leads"):
        self.memory_dir = Path(memory_dir)
        self.memory_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, target: str) -> Path:
        safe = "".join(c if c.isalnum() or c in "-._" else "_" for c in target)
        return self.memory_dir / f"{safe}.jsonl"

    def ingest(self, target: str, observations: List[Dict[str, Any]]) -> int:
        """Parse recon output and route signal types to skills."""
        count = 0
        for obs in observations:
            signal_type = obs.get("signal_type", "other")
            route_to = self._route_signal(signal_type)
            lead = Lead(
                lead_id=str(uuid.uuid4())[:8],
                target=target,
                signal_type=signal_type,
                description=obs.get("description", ""),
                status=LeadStatus.UNTOUCHED,
                created_at=time.time(),
                updated_at=time.time(),
                route_to=route_to,
                evidence=obs.get("evidence", {}),
            )
            self._append(target, lead)
            count += 1
        return count

    def _route_signal(self, signal_type: str) -> str:
        mapping = {
            "idor": "hunt-idor",
            "ssrf": "hunt-ssrf",
            "graphql": "hunt-graphql",
            "oauth": "hunt-oauth",
            "saml": "hunt-saml",
            "llm": "hunt-llm",
            "source-leak": "hunt-secrets",
            "tech-stack": "hunt-tech",
            "nuclei": "hunt-nuclei",
            "xss": "hunt-xss",
            "sqli": "hunt-sqli",
            "takeover": "hunt-takeover",
            "cloud": "hunt-cloud",
        }
        return mapping.get(signal_type, "hunt-generic")

    def _append(self, target: str, lead: Lead) -> None:
        path = self._path(target)
        record = {
            "lead_id": lead.lead_id,
            "target": lead.target,
            "signal_type": lead.signal_type,
            "description": lead.description,
            "status": lead.status.value,
            "created_at": lead.created_at,
            "updated_at": lead.updated_at,
            "route_to": lead.route_to,
            "evidence": lead.evidence,
        }
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    def show(self, target: str) -> List[Dict[str, Any]]:
        """List untouched-first and flag stale high-priority leads."""
        path = self._path(target)
        if not path.exists():
            print(f"[Lead Board] No leads for {target}")
            return []
        leads = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    leads.append(json.loads(line))
        # Sort: untouched first, then by created_at desc
        leads.sort(key=lambda l: (l["status"] != "untouched", -l.get("created_at", 0)))
        print(f"\n[Lead Board] {target} ({len(leads)} leads)\n")
        for l in leads:
            status_icon = {
                "untouched": "[O]",
                "investigating": "[!]",
                "killed": "[X]",
                "reported": "[*]",
            }.get(l["status"], "[O]")
            print(
                f"  {status_icon} {l['lead_id']} | {l['signal_type']:15} | {l['route_to']:15} | {l['description'][:60]}"
            )
        return leads

    def next(self, target: str) -> Optional[Dict[str, Any]]:
        """Return the single top lead (untouched first)."""
        leads = self.show(target)
        for l in leads:
            if l["status"] == "untouched":
                print(f"\n[TARGET] Next lead: {l['lead_id']} -> {l['route_to']}")
                return l
        print("No untouched leads remaining.")
        return None

    def touch(
        self, target: str, lead_id: str, status: LeadStatus
    ) -> bool:
        """Mark a lead as investigating/killed/reported."""
        path = self._path(target)
        if not path.exists():
            return False
        updated = False
        lines = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                record = json.loads(line.strip())
                if record["lead_id"] == lead_id:
                    record["status"] = status.value
                    record["updated_at"] = time.time()
                    updated = True
                lines.append(json.dumps(record, ensure_ascii=False))
        if updated:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
            print(f"[Lead Board] Lead {lead_id} → {status.value}")
        return updated

    def remember(self, target: str, note: str) -> None:
        """Log a finding or technique to hunt memory."""
        lead = Lead(
            lead_id=str(uuid.uuid4())[:8],
            target=target,
            signal_type="remember",
            description=note,
            status=LeadStatus.UNTOUCHED,
            created_at=time.time(),
            updated_at=time.time(),
            route_to="hunt-memory",
            evidence={"note": note},
        )
        self._append(target, lead)
        print(f"[Lead Board] Remembered: {note[:80]}")


def main():
    import argparse

    p = argparse.ArgumentParser(prog="lead-board")
    sub = p.add_subparsers(dest="command")

    sp = sub.add_parser("ingest")
    sp.add_argument("target")
    sp.add_argument("--file", help="JSON file with observations")

    sp = sub.add_parser("show")
    sp.add_argument("target")

    sp = sub.add_parser("next")
    sp.add_argument("target")

    sp = sub.add_parser("touch")
    sp.add_argument("target")
    sp.add_argument("lead_id")
    sp.add_argument("status", choices=[s.value for s in LeadStatus])

    sp = sub.add_parser("remember")
    sp.add_argument("target")
    sp.add_argument("note")

    args = p.parse_args()
    board = LeadBoard()

    if args.command == "ingest":
        obs = json.loads(Path(args.file).read_text(encoding="utf-8")) if args.file else []
        board.ingest(args.target, obs)
    elif args.command == "show":
        board.show(args.target)
    elif args.command == "next":
        board.next(args.target)
    elif args.command == "touch":
        board.touch(args.target, args.lead_id, LeadStatus(args.status))
    elif args.command == "remember":
        board.remember(args.target, args.note)


if __name__ == "__main__":
    main()
