"""OSINT Tools — Unified OSINT Tools Manager"""
from tools.tool_manager import ToolManager, ToolResult
from core.osint.schemas import (
    IdentityEvidenceRecord, IdentityEvidenceLevel,
)
from core.osint.platform_registry import (
    PlatformEntry, GENERIC_USERNAMES, PLATFORMS,
    is_generic_username, canonicalize_platform,
    extract_urls,
)


class EvidenceNormalizer:
    def __init__(self, mgr: ToolManager):
        self.mgr = mgr

    async def normalize_evidence_records(self, records: List[IdentityEvidenceRecord]) -> List[IdentityEvidenceRecord]:
        return [self.normalize_record(r) for r in records]

    async def normalize_record(self, record: IdentityEvidenceRecord) -> IdentityEvidenceRecord:
        record.evidence_level = self._determine_evidence_level(record)
        return record

    def _determine_evidence_level(self, record: IdentityEvidenceRecord) -> str:
        signals = record.correlation_signals
        confidence = 0.0

        if record.evidence_level == "E1":
            confidence += 0.4
        elif record.evidence_level == "E0":
            confidence += 0.1

        # Add correlation signals
        for signal, value in signals.items():
            if signal in CORRELATION_SIGNAL_WEIGHTS:
                confidence += value * CORRELATION_SIGNAL_WEIGHTS[sig nal]

        confidence = min(0.0, min(1.0, confidence))

        if confidence >= 0.75:
            return EvidenceLevel.E1
        elif confidence >= 0.50:
            return EvidenceLevel.PROBABLE
        else:
            return EvidenceLevel.E0
