"""
HunterAI Peer Review Workflow
=============================
Enables human security engineers or secondary validator agents to audit, verify,
or reject confirmed findings before final compliance sign-off.

Actions:
- APPROVE: Signs off on finding and evidence.
- REJECT: Refutes finding and returns to researcher.
- REQUEST_EVIDENCE: Mandates additional proof-of-execution or replays.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ReviewStatus(str, Enum):
    AWAITING_REVIEW = "AWAITING_REVIEW"
    APPROVED = "PEER_APPROVED"
    REJECTED = "PEER_REJECTED"
    EVIDENCE_REQUESTED = "ADDITIONAL_EVIDENCE_REQUESTED"


@dataclass
class ReviewDecision:
    decision_id: str
    finding_id: str
    reviewer: str
    status: ReviewStatus
    comments: str
    timestamp: float = field(default_factory=time.time)


@dataclass
class ReviewPacket:
    packet_id: str
    finding_id: str
    target: str
    vulnerability_title: str
    cwe_id: str
    contract_status: str
    replay_script_path: str
    submitted_at: float = field(default_factory=time.time)
    current_status: ReviewStatus = ReviewStatus.AWAITING_REVIEW
    history: List[ReviewDecision] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "packet_id": self.packet_id,
            "finding_id": self.finding_id,
            "target": self.target,
            "title": self.vulnerability_title,
            "cwe_id": self.cwe_id,
            "contract": self.contract_status,
            "status": self.current_status.value,
            "review_count": len(self.history),
        }


class PeerReviewWorkflow:
    """Manages peer review queue for verified findings"""

    def __init__(self):
        self._packets: Dict[str, ReviewPacket] = {}
        self._counter = 0

    def submit_finding(
        self,
        finding_id: str,
        target: str,
        title: str,
        cwe_id: str,
        contract_status: str = "CONFIRMED",
        replay_script: str = "replay.py"
    ) -> ReviewPacket:
        self._counter += 1
        packet_id = f"REV-{finding_id}-{self._counter:02d}"
        packet = ReviewPacket(
            packet_id=packet_id,
            finding_id=finding_id,
            target=target,
            vulnerability_title=title,
            cwe_id=cwe_id,
            contract_status=contract_status,
            replay_script_path=replay_script,
            current_status=ReviewStatus.AWAITING_REVIEW
        )
        self._packets[finding_id] = packet
        return packet

    def approve_finding(self, finding_id: str, reviewer: str, comments: str = "Evidence verified") -> bool:
        packet = self._packets.get(finding_id)
        if not packet:
            return False
        dec = ReviewDecision(
            decision_id=f"DEC-{finding_id}-{len(packet.history)+1:02d}",
            finding_id=finding_id,
            reviewer=reviewer,
            status=ReviewStatus.APPROVED,
            comments=comments
        )
        packet.current_status = ReviewStatus.APPROVED
        packet.history.append(dec)
        return True

    def reject_finding(self, finding_id: str, reviewer: str, comments: str) -> bool:
        packet = self._packets.get(finding_id)
        if not packet:
            return False
        dec = ReviewDecision(
            decision_id=f"DEC-{finding_id}-{len(packet.history)+1:02d}",
            finding_id=finding_id,
            reviewer=reviewer,
            status=ReviewStatus.REJECTED,
            comments=comments
        )
        packet.current_status = ReviewStatus.REJECTED
        packet.history.append(dec)
        return True

    def request_additional_evidence(self, finding_id: str, reviewer: str, evidence_details: str) -> bool:
        packet = self._packets.get(finding_id)
        if not packet:
            return False
        dec = ReviewDecision(
            decision_id=f"DEC-{finding_id}-{len(packet.history)+1:02d}",
            finding_id=finding_id,
            reviewer=reviewer,
            status=ReviewStatus.EVIDENCE_REQUESTED,
            comments=evidence_details
        )
        packet.current_status = ReviewStatus.EVIDENCE_REQUESTED
        packet.history.append(dec)
        return True

    def get_pending(self) -> List[ReviewPacket]:
        return [p for p in self._packets.values() if p.current_status == ReviewStatus.AWAITING_REVIEW]
