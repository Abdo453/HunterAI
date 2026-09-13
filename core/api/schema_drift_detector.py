"""
HunterAI Schema Drift Detector
==============================
Takes snapshots of API responses and detects dynamic schema modifications.
Flags stale evidence to prevent making security decisions on outdated structures.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass
class SchemaSnapshot:
    endpoint: str
    status_code: int
    top_level_keys: Set[str] = field(default_factory=set)
    field_types: Dict[str, str] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


class SchemaDriftDetector:
    """Compares API response schemas across assessment timeline"""

    @classmethod
    def extract_snapshot(cls, endpoint: str, status_code: int, response_json: Dict[str, Any]) -> SchemaSnapshot:
        keys = set(response_json.keys()) if isinstance(response_json, dict) else set()
        types = {k: type(v).__name__ for k, v in response_json.items()} if isinstance(response_json, dict) else {}
        return SchemaSnapshot(endpoint=endpoint, status_code=status_code, top_level_keys=keys, field_types=types)

    @classmethod
    def detect_drift(cls, baseline_snap: SchemaSnapshot, current_snap: SchemaSnapshot) -> Dict[str, Any]:
        added_keys = current_snap.top_level_keys - baseline_snap.top_level_keys
        removed_keys = baseline_snap.top_level_keys - current_snap.top_level_keys

        type_changes = {}
        for k in baseline_snap.top_level_keys.intersection(current_snap.top_level_keys):
            if baseline_snap.field_types.get(k) != current_snap.field_types.get(k):
                type_changes[k] = {
                    "old": baseline_snap.field_types.get(k),
                    "new": current_snap.field_types.get(k)
                }

        has_drift = bool(added_keys or removed_keys or type_changes)
        return {
            "has_drift": has_drift,
            "added_fields": list(added_keys),
            "removed_fields": list(removed_keys),
            "type_changes": type_changes,
            "warning": "Evidence may be stale; baseline schema modified mid-scan." if has_drift else "Schema consistent."
        }