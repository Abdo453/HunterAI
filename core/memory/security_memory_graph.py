"""
HunterAI Security Memory Graph & Attack Surface Differ
======================================================
Stores persistent target memory across scans:
- Known assets, endpoints, parameters, and technologies
- Historical findings and verified fixes
- Baselines and failed test memory
Computes Attack Surface Diff (Delta) to prioritize testing changed surface.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


@dataclass
class SurfaceSnapshot:
    domain: str
    endpoints: Set[str] = field(default_factory=set)
    parameters: Dict[str, List[str]] = field(default_factory=dict)
    technologies: Set[str] = field(default_factory=set)
    timestamp: float = field(default_factory=time.time)


@dataclass
class AttackSurfaceDelta:
    domain: str
    new_endpoints: List[str] = field(default_factory=list)
    removed_endpoints: List[str] = field(default_factory=list)
    new_parameters: Dict[str, List[str]] = field(default_factory=dict)
    new_technologies: List[str] = field(default_factory=list)
    has_changes: bool = False

    def format_summary(self) -> str:
        lines = [
            f"Δ Attack Surface Diff for {self.domain}:",
            f"   • New Endpoints:    +{len(self.new_endpoints)}",
            f"   • Removed Endpoints: -{len(self.removed_endpoints)}",
            f"   • New Parameters:   +{sum(len(v) for v in self.new_parameters.values())}",
            f"   • New Technologies: +{len(self.new_technologies)}"
        ]
        return "\n".join(lines)


class SecurityMemoryGraph:
    """Persistent long-term memory for target architecture and historical findings"""

    def __init__(self, storage_dir: Optional[Path] = None):
        self.storage_dir = storage_dir or (Path(__file__).resolve().parent.parent.parent / "data" / "memory")
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.targets: Dict[str, Dict[str, Any]] = {}

    def _file_for_domain(self, domain: str) -> Path:
        safe_domain = domain.replace(":", "_").replace("/", "_")
        return self.storage_dir / f"target_memory_{safe_domain}.json"

    def load_target_memory(self, domain: str) -> Optional[Dict[str, Any]]:
        target_file = self._file_for_domain(domain)
        if target_file.exists():
            try:
                with open(target_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.targets[domain] = data
                    return data
            except Exception:
                pass
        return None

    def save_target_memory(
        self,
        domain: str,
        endpoints: List[str],
        parameters: Dict[str, List[str]],
        technologies: List[str],
        findings_count: int = 0
    ):
        data = {
            "domain": domain,
            "endpoints": sorted(list(set(endpoints))),
            "parameters": parameters,
            "technologies": sorted(list(set(technologies))),
            "findings_count": findings_count,
            "last_scanned": time.time()
        }
        self.targets[domain] = data
        target_file = self._file_for_domain(domain)
        try:
            with open(target_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass


class AttackSurfaceDiffer:
    """Calculates diff between historical baseline and current discovery"""

    @classmethod
    def compute_delta(
        cls,
        domain: str,
        historical_data: Optional[Dict[str, Any]],
        current_endpoints: List[str],
        current_parameters: Dict[str, List[str]],
        current_technologies: List[str]
    ) -> AttackSurfaceDelta:
        if not historical_data:
            # First scan -> all endpoints are new
            return AttackSurfaceDelta(
                domain=domain,
                new_endpoints=current_endpoints,
                new_parameters=current_parameters,
                new_technologies=current_technologies,
                has_changes=True
            )

        old_endpoints = set(historical_data.get("endpoints", []))
        curr_endpoints = set(current_endpoints)

        new_eps = list(curr_endpoints - old_endpoints)
        removed_eps = list(old_endpoints - curr_endpoints)

        old_techs = set(historical_data.get("technologies", []))
        curr_techs = set(current_technologies)
        new_techs = list(curr_techs - old_techs)

        old_params = historical_data.get("parameters", {})
        new_params = {}
        for ep, params in current_parameters.items():
            old_p_set = set(old_params.get(ep, []))
            new_p = list(set(params) - old_p_set)
            if new_p:
                new_params[ep] = new_p

        has_changes = bool(new_eps or removed_eps or new_techs or new_params)

        return AttackSurfaceDelta(
            domain=domain,
            new_endpoints=new_eps,
            removed_endpoints=removed_eps,
            new_parameters=new_params,
            new_technologies=new_techs,
            has_changes=has_changes
        )
