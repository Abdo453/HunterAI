"""
HunterAI Coverage & Blindspot Ledger (P0)
=========================================
Implements exhaustive, honest tracking of investigation boundaries:
  - Discovered Assets (Hosts, Endpoints, Parameters, APIs, Services)
  - Analyzed Assets (Parsed JS bundles, mapped schemas, observed traffic)
  - Tested Assets (Differential fuzzing, injection probes, auth tests)
  - Confirmed Findings (Adjudicated by Evidence Court)
  - Failed Probes (Timeouts, network failures, unexpected crashes)
  - Untestable Surfaces (Requires operator auth, WAF block, binary protocol)
  - Explicit Blindspots (Identified gaps with documented technical rationale)
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("hunter_ai.coverage_ledger")


class AssetType(str, Enum):
    DOMAIN    = "DOMAIN"
    HOST      = "HOST"
    PORT      = "PORT"
    SERVICE   = "SERVICE"
    ENDPOINT  = "ENDPOINT"
    PARAMETER = "PARAMETER"
    API       = "API"
    JS_BUNDLE = "JS_BUNDLE"
    AUTH_FLOW = "AUTH_FLOW"


class UntestableReason(str, Enum):
    WAF_BLOCKED          = "WAF_BLOCKED"
    REQUIRES_OPERATOR_2FA = "REQUIRES_OPERATOR_2FA"
    BINARY_PROTOCOL      = "BINARY_PROTOCOL"
    OUT_OF_SCOPE         = "OUT_OF_SCOPE"
    HOST_UNRESPONSIVE    = "HOST_UNRESPONSIVE"
    DESTRUCTIVE_RISK     = "DESTRUCTIVE_RISK"
    ENVIRONMENT_LIMIT    = "ENVIRONMENT_LIMIT"


@dataclass
class AssetItem:
    asset_type: AssetType
    identifier: str
    discovered_by: str = ""
    discovered_at: float = field(default_factory=time.time)
    analyzed: bool = False
    analyzed_by: str = ""
    tested: bool = False
    tested_vuln_classes: List[str] = field(default_factory=list)
    confirmed: bool = False
    finding_refs: List[str] = field(default_factory=list)
    failed: bool = False
    failure_reasons: List[str] = field(default_factory=list)
    untestable: bool = False
    untestable_reason: Optional[UntestableReason] = None
    untestable_detail: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["asset_type"] = self.asset_type.value
        data["untestable_reason"] = self.untestable_reason.value if self.untestable_reason else None
        return data


@dataclass
class BlindspotEntry:
    category: str
    description: str
    impact: str
    recommended_mitigation: str
    detected_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CoverageLedger:
    """
    Central accounting ledger for investigation completeness.
    Ensures the assessment report explicitly discloses unprobed surfaces.
    """
    def __init__(self, persistence_file: Optional[str | Path] = None):
        self.persistence_file = Path(persistence_file) if persistence_file else None
        self._assets: Dict[str, AssetItem] = {}
        self._blindspots: List[BlindspotEntry] = []
        self._load()

    def record_discovery(
        self,
        asset_type: AssetType,
        identifier: str,
        discovered_by: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AssetItem:
        key = f"{asset_type.value}:{identifier.strip()}"
        if key not in self._assets:
            item = AssetItem(
                asset_type=asset_type,
                identifier=identifier.strip(),
                discovered_by=discovered_by,
                metadata=metadata or {},
            )
            self._assets[key] = item
            self._persist()
            return item
        return self._assets[key]

    def record_analysis(self, asset_type: AssetType, identifier: str, analyzed_by: str = "") -> bool:
        key = f"{asset_type.value}:{identifier.strip()}"
        item = self._assets.get(key)
        if item:
            item.analyzed = True
            item.analyzed_by = analyzed_by
            self._persist()
            return True
        return False

    def record_test(self, asset_type: AssetType, identifier: str, vuln_class: str) -> bool:
        key = f"{asset_type.value}:{identifier.strip()}"
        item = self._assets.get(key)
        if item:
            item.tested = True
            if vuln_class not in item.tested_vuln_classes:
                item.tested_vuln_classes.append(vuln_class)
            self._persist()
            return True
        return False

    def record_confirmation(self, asset_type: AssetType, identifier: str, finding_id: str) -> bool:
        key = f"{asset_type.value}:{identifier.strip()}"
        item = self._assets.get(key)
        if item:
            item.confirmed = True
            if finding_id not in item.finding_refs:
                item.finding_refs.append(finding_id)
            self._persist()
            return True
        return False

    def record_failure(self, asset_type: AssetType, identifier: str, reason: str) -> bool:
        key = f"{asset_type.value}:{identifier.strip()}"
        item = self._assets.get(key)
        if item:
            item.failed = True
            item.failure_reasons.append(reason)
            self._persist()
            return True
        return False

    def record_untestable(
        self,
        asset_type: AssetType,
        identifier: str,
        reason: UntestableReason,
        detail: str = "",
    ) -> bool:
        key = f"{asset_type.value}:{identifier.strip()}"
        item = self._assets.get(key)
        if not item:
            item = self.record_discovery(asset_type, identifier)
        item.untestable = True
        item.untestable_reason = reason
        item.untestable_detail = detail
        self._persist()
        return True

    def record_blindspot(
        self,
        category: str,
        description: str,
        impact: str = "MEDIUM",
        recommended_mitigation: str = "",
    ) -> None:
        entry = BlindspotEntry(
            category=category,
            description=description,
            impact=impact,
            recommended_mitigation=recommended_mitigation,
        )
        self._blindspots.append(entry)
        self._persist()

    def get_summary(self) -> Dict[str, Any]:
        total = len(self._assets)
        analyzed = sum(1 for a in self._assets.values() if a.analyzed)
        tested = sum(1 for a in self._assets.values() if a.tested)
        confirmed = sum(1 for a in self._assets.values() if a.confirmed)
        failed = sum(1 for a in self._assets.values() if a.failed)
        untestable = sum(1 for a in self._assets.values() if a.untestable)

        # By type breakdown
        by_type: Dict[str, Dict[str, int]] = {}
        for a in self._assets.values():
            t = a.asset_type.value
            if t not in by_type:
                by_type[t] = {"total": 0, "analyzed": 0, "tested": 0, "confirmed": 0}
            by_type[t]["total"] += 1
            if a.analyzed: by_type[t]["analyzed"] += 1
            if a.tested: by_type[t]["tested"] += 1
            if a.confirmed: by_type[t]["confirmed"] += 1

        analysis_rate = (analyzed / max(1, total)) * 100.0
        test_rate = (tested / max(1, total)) * 100.0

        return {
            "total_assets_discovered": total,
            "assets_analyzed": analyzed,
            "assets_tested": tested,
            "findings_confirmed": confirmed,
            "probes_failed": failed,
            "assets_untestable": untestable,
            "blindspots_count": len(self._blindspots),
            "analysis_coverage_pct": round(analysis_rate, 1),
            "testing_coverage_pct": round(test_rate, 1),
            "by_type": by_type,
            "blindspots": [b.to_dict() for b in self._blindspots],
        }

    def _persist(self) -> None:
        if not self.persistence_file:
            return
        try:
            self.persistence_file.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "assets": [a.to_dict() for a in self._assets.values()],
                "blindspots": [b.to_dict() for b in self._blindspots],
            }
            self.persistence_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception as e:
            logger.warning("Failed saving coverage ledger: %s", e)

    def _load(self) -> None:
        if not self.persistence_file or not self.persistence_file.exists():
            return
        try:
            data = json.loads(self.persistence_file.read_text(encoding="utf-8"))
            for item in data.get("assets", []):
                at = AssetType(item["asset_type"])
                ur = UntestableReason(item["untestable_reason"]) if item.get("untestable_reason") else None
                ai = AssetItem(
                    asset_type=at,
                    identifier=item["identifier"],
                    discovered_by=item.get("discovered_by", ""),
                    discovered_at=item.get("discovered_at", time.time()),
                    analyzed=item.get("analyzed", False),
                    analyzed_by=item.get("analyzed_by", ""),
                    tested=item.get("tested", False),
                    tested_vuln_classes=item.get("tested_vuln_classes", []),
                    confirmed=item.get("confirmed", False),
                    finding_refs=item.get("finding_refs", []),
                    failed=item.get("failed", False),
                    failure_reasons=item.get("failure_reasons", []),
                    untestable=item.get("untestable", False),
                    untestable_reason=ur,
                    untestable_detail=item.get("untestable_detail", ""),
                    metadata=item.get("metadata", {}),
                )
                self._assets[f"{at.value}:{ai.identifier}"] = ai
            for b in data.get("blindspots", []):
                self._blindspots.append(BlindspotEntry(**b))
        except Exception as e:
            logger.warning("Failed loading coverage ledger: %s", e)
