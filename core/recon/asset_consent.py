"""
HunterAI Asset Discovery with Mandatory Operator Consent
========================================================
Categorizes discovered assets into 5 distinct, independently scoped lists:
- DOMAIN
- SUBDOMAIN
- API_ENDPOINT
- JAVASCRIPT_BUNDLE
- CLOUD_BUCKET

Guarantee:
- Discovered assets remain in PENDING_CONSENT.
- Zero requests are sent to newly discovered assets without explicit operator authorization.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class AssetCategory(str, Enum):
    DOMAIN = "DOMAIN"
    SUBDOMAIN = "SUBDOMAIN"
    API_ENDPOINT = "API_ENDPOINT"
    JAVASCRIPT_BUNDLE = "JAVASCRIPT_BUNDLE"
    CLOUD_BUCKET = "CLOUD_BUCKET"


class ConsentStatus(str, Enum):
    PENDING = "PENDING_CONSENT"
    APPROVED = "APPROVED_FOR_SCOPE"
    REJECTED = "REJECTED_OUT_OF_SCOPE"


@dataclass
class DiscoveredAsset:
    asset_id: str
    category: AssetCategory
    value: str
    discovery_source: str
    discovered_at: float = field(default_factory=time.time)
    consent_status: ConsentStatus = ConsentStatus.PENDING
    operator_decision_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "category": self.category.value,
            "value": self.value,
            "discovery_source": self.discovery_source,
            "discovered_at": self.discovered_at,
            "consent_status": self.consent_status.value,
            "operator_decision_reason": self.operator_decision_reason,
        }


class AssetConsentManager:
    """Manages discovery queue, categorized scoping, and human-in-the-loop consent"""

    def __init__(self):
        self._assets: Dict[str, DiscoveredAsset] = {}
        self._counter: int = 0

    def discover_asset(
        self,
        category: AssetCategory,
        value: str,
        source: str
    ) -> DiscoveredAsset:
        # Check if already tracked
        for existing in self._assets.values():
            if existing.category == category and existing.value == value:
                return existing

        self._counter += 1
        asset_id = f"AST-{category.value[:3]}-{self._counter:04d}"
        asset = DiscoveredAsset(
            asset_id=asset_id,
            category=category,
            value=value,
            discovery_source=source,
            consent_status=ConsentStatus.PENDING
        )
        self._assets[asset_id] = asset
        return asset

    def approve_asset(self, asset_id: str, reason: str = "Authorized by operator") -> bool:
        if asset_id in self._assets:
            self._assets[asset_id].consent_status = ConsentStatus.APPROVED
            self._assets[asset_id].operator_decision_reason = reason
            return True
        return False

    def reject_asset(self, asset_id: str, reason: str = "Rejected out of scope") -> bool:
        if asset_id in self._assets:
            self._assets[asset_id].consent_status = ConsentStatus.REJECTED
            self._assets[asset_id].operator_decision_reason = reason
            return True
        return False

    def get_pending(self, category: Optional[AssetCategory] = None) -> List[DiscoveredAsset]:
        results = [
            a for a in self._assets.values()
            if a.consent_status == ConsentStatus.PENDING
        ]
        if category:
            results = [a for a in results if a.category == category]
        return results

    def get_approved_scope(self, category: Optional[AssetCategory] = None) -> List[str]:
        results = [
            a.value for a in self._assets.values()
            if a.consent_status == ConsentStatus.APPROVED
        ]
        if category:
            results = [
                a.value for a in self._assets.values()
                if a.consent_status == ConsentStatus.APPROVED and a.category == category
            ]
        return results

    def export_scope_manifest(self) -> Dict[str, List[str]]:
        manifest: Dict[str, List[str]] = {cat.value: [] for cat in AssetCategory}
        for a in self._assets.values():
            if a.consent_status == ConsentStatus.APPROVED:
                manifest[a.category.value].append(a.value)
        return manifest
