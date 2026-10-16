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
    # Legacy negative-space reasons (kept so the endpoint-level ledger can
    # record the *specific* causal reason instead of collapsing it).
    AUTH_MISSING              = "AUTH_MISSING"
    RATE_LIMITED              = "RATE_LIMITED"
    POLICY_RESTRICTION        = "POLICY_RESTRICTION"
    MANUAL_APPROVAL_REQUIRED  = "MANUAL_APPROVAL_REQUIRED"
    UNSUPPORTED_PROTOCOL      = "UNSUPPORTED_PROTOCOL"
    USER_RESTRICTION          = "USER_RESTRICTION"


class CoverageStatus(str, Enum):
    """Endpoint-level probe outcome.

    Backward-compatibility surface: existed before the asset-based ledger
    rewrite and is still consumed by ``cli/hunter_cli.py``,
    ``core/brain/autonomous_brain.py`` and several test suites.
    """
    PROBED_AND_VERIFIED = "PROBED_AND_VERIFIED"
    PROBED_AND_SAFE = "PROBED_AND_SAFE"
    SKIPPED_OUT_OF_SCOPE = "SKIPPED_OUT_OF_SCOPE"
    SKIPPED_AUTH_MISSING = "SKIPPED_AUTH_MISSING"
    SKIPPED_RATE_LIMITED = "SKIPPED_RATE_LIMITED"
    SKIPPED_WAF_BLOCKED = "SKIPPED_WAF_BLOCKED"
    SKIPPED_POLICY_RESTRICTION = "SKIPPED_POLICY_RESTRICTION"
    SKIPPED_MANUAL_APPROVAL_REQUIRED = "SKIPPED_MANUAL_APPROVAL_REQUIRED"
    SKIPPED_UNSUPPORTED_PROTOCOL = "SKIPPED_UNSUPPORTED_PROTOCOL"
    SKIPPED_USER_RESTRICTION = "SKIPPED_USER_RESTRICTION"


# Maps a legacy skip status to the asset-level untestable reason it implies,
# so one record satisfies both consumers without losing the causal detail.
LEGACY_STATUS_TO_REASON: Dict[CoverageStatus, UntestableReason] = {
    CoverageStatus.SKIPPED_OUT_OF_SCOPE: UntestableReason.OUT_OF_SCOPE,
    CoverageStatus.SKIPPED_AUTH_MISSING: UntestableReason.AUTH_MISSING,
    CoverageStatus.SKIPPED_RATE_LIMITED: UntestableReason.RATE_LIMITED,
    CoverageStatus.SKIPPED_WAF_BLOCKED: UntestableReason.WAF_BLOCKED,
    CoverageStatus.SKIPPED_POLICY_RESTRICTION: UntestableReason.POLICY_RESTRICTION,
    CoverageStatus.SKIPPED_MANUAL_APPROVAL_REQUIRED: UntestableReason.MANUAL_APPROVAL_REQUIRED,
    CoverageStatus.SKIPPED_UNSUPPORTED_PROTOCOL: UntestableReason.UNSUPPORTED_PROTOCOL,
    CoverageStatus.SKIPPED_USER_RESTRICTION: UntestableReason.USER_RESTRICTION,
}


@dataclass
class SurfaceItem:
    """Endpoint-level ledger row (legacy shape, still emitted)."""
    target: str
    endpoint: str
    method: str
    parameter: Optional[str] = None
    status: CoverageStatus = CoverageStatus.PROBED_AND_SAFE
    reason: str = ""
    probe_count: int = 0
    timestamp: float = field(default_factory=time.time)


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
    def __init__(
        self,
        target_scope: Optional[str | Path] = None,
        persistence_file: Optional[str | Path] = None,
    ):
        # Backward compatibility: the pre-rewrite constructor took the target
        # scope as the sole positional argument. Callers that pass a *.json
        # path positionally are treated as supplying persistence_file.
        if target_scope is not None and persistence_file is None:
            if str(target_scope).lower().endswith(".json"):
                persistence_file = target_scope
                target_scope = None
        self.target_scope: str = str(target_scope) if target_scope else ""
        self.persistence_file = Path(persistence_file) if persistence_file else None
        self._assets: Dict[str, AssetItem] = {}
        self._blindspots: List[BlindspotEntry] = []
        self.items: Dict[str, SurfaceItem] = {}
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

    # ── Endpoint-level ledger (legacy API, preserved) ─────────────────────────

    def _make_key(self, endpoint: str, method: str, parameter: Optional[str] = None) -> str:
        param_part = f"?{parameter}" if parameter else ""
        return f"{method.upper()}:{endpoint}{param_part}"

    def record_probed(
        self,
        endpoint: str,
        method: str,
        parameter: Optional[str] = None,
        verified_finding: bool = False,
    ) -> SurfaceItem:
        """Record an endpoint/parameter that was actually probed.

        Writes both the endpoint-level row and the asset-level record so the
        asset summary stays consistent with the negative-space ledger.
        """
        key = self._make_key(endpoint, method, parameter)
        previous = self.items.get(key)
        item = SurfaceItem(
            target=self.target_scope,
            endpoint=endpoint,
            method=method.upper(),
            parameter=parameter,
            status=(
                CoverageStatus.PROBED_AND_VERIFIED
                if verified_finding
                else CoverageStatus.PROBED_AND_SAFE
            ),
            reason="Tested with differential verification probes.",
            probe_count=(previous.probe_count if previous else 0) + 1,
        )
        self.items[key] = item

        self.record_discovery(AssetType.ENDPOINT, endpoint, discovered_by="coverage_ledger")
        if parameter:
            self.record_discovery(
                AssetType.PARAMETER,
                f"{endpoint}?{parameter}",
                discovered_by="coverage_ledger",
            )
        self.record_analysis(AssetType.ENDPOINT, endpoint, analyzed_by="coverage_ledger")
        self.record_test(AssetType.ENDPOINT, endpoint, vuln_class="coverage_probe")
        if verified_finding:
            self.record_confirmation(
                AssetType.ENDPOINT, endpoint, finding_id=f"probe:{key}"
            )
        return item

    def record_skipped(
        self,
        endpoint: str,
        method: str,
        status: CoverageStatus,
        reason: str,
        parameter: Optional[str] = None,
    ) -> SurfaceItem:
        """Record negative space: surface that was identified but NOT tested."""
        key = self._make_key(endpoint, method, parameter)
        item = SurfaceItem(
            target=self.target_scope,
            endpoint=endpoint,
            method=method.upper(),
            parameter=parameter,
            status=status,
            reason=reason,
            probe_count=0,
        )
        self.items[key] = item

        self.record_discovery(AssetType.ENDPOINT, endpoint, discovered_by="coverage_ledger")
        mapped = LEGACY_STATUS_TO_REASON.get(status)
        if mapped is not None:
            self.record_untestable(AssetType.ENDPOINT, endpoint, mapped, detail=reason)
        return item

    def format_terminal_coverage_map(self) -> str:
        summary = self.get_summary()
        pct = summary["coverage_percentage"]
        filled_slots = int(pct / 5)
        bar = "█" * filled_slots + "░" * (20 - filled_slots)
        sep = "═" * 70
        sub = "─" * 70
        lines = [
            sep,
            f" 🗺️ HunterAI Attack Surface Coverage Map — {self.target_scope}",
            sep,
            f" Coverage Progress: [{bar}] {pct}%",
            f" Total Identified Surface:  {summary['total_surface_items']:>6} endpoints & parameters",
            f" Fully Probed & Verified:   {summary['probed_items']:>6} ({pct}%)",
            f" Endpoint-Level Coverage:   {summary['endpoint_coverage_pct']:>6}%",
            f" Parameter-Level Coverage:  {summary['parameter_coverage_pct']:>6}%",
            f" Untested / Negative Space: {summary['skipped_items']:>6}",
            sub,
            " Negative Space Ledger (What was NOT tested and why):",
        ]
        if summary["skipped_breakdown"]:
            for k, count in sorted(summary["skipped_breakdown"].items()):
                lines.append(f"   [!] {k:<32} : {count:>4} items")
        else:
            lines.append("   • All discovered in-scope endpoints were fully probed.")
        lines.append(sep)
        return "\n".join(lines)

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

        # ── Endpoint-level (legacy) projection of the same ledger ────────────
        ep_total = len(self.items)
        probed_verified = sum(
            1 for i in self.items.values() if i.status == CoverageStatus.PROBED_AND_VERIFIED
        )
        probed_safe = sum(
            1 for i in self.items.values() if i.status == CoverageStatus.PROBED_AND_SAFE
        )
        probed_items = probed_verified + probed_safe
        skipped_items = ep_total - probed_items
        coverage_pct = round((probed_items / max(1, ep_total)) * 100.0, 1)

        skipped_breakdown: Dict[str, int] = {}
        for i in self.items.values():
            if "SKIPPED" in i.status.value:
                skipped_breakdown[i.status.value] = skipped_breakdown.get(i.status.value, 0) + 1

        unique_endpoints = len({i.endpoint for i in self.items.values()})
        probed_endpoints = len(
            {i.endpoint for i in self.items.values() if "PROBED" in i.status.value}
        )
        endpoint_pct = round((probed_endpoints / max(1, unique_endpoints)) * 100.0, 1)

        params = [i for i in self.items.values() if i.parameter]
        probed_params = [i for i in params if "PROBED" in i.status.value]
        param_pct = (
            round((len(probed_params) / max(1, len(params))) * 100.0, 1) if params else 100.0
        )

        return {
            # Asset-level view (current API)
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
            # Endpoint-level view (legacy API, preserved for existing callers)
            "target_scope": self.target_scope,
            "total_surface_items": ep_total,
            "probed_items": probed_items,
            "probed_and_verified": probed_verified,
            "probed_and_safe": probed_safe,
            "skipped_items": skipped_items,
            "coverage_percentage": coverage_pct,
            "endpoint_coverage_pct": endpoint_pct,
            "parameter_coverage_pct": param_pct,
            "skipped_breakdown": skipped_breakdown,
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
