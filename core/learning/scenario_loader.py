"""
Dynamic Scenario Loader & Knowledge Sync Engine
Automatically monitors, discovers, validates, and synchronizes new training scenarios
and CVE case studies from data/scenarios/ and data/knowledge_base/cves/.
Ensures the Agent dynamically detects new knowledge without code changes.
"""
import os
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional

from core.learning.knowledge_store import KnowledgeStore, KnowledgeItem

log = logging.getLogger("core.learning.scenario_loader")

SCENARIOS_DIR = Path("data/scenarios")
CVES_DIR = Path("data/knowledge_base/cves")
INTELLIGENCE_DIR = Path("data/knowledge_base/intelligence")

for d in [SCENARIOS_DIR, CVES_DIR, INTELLIGENCE_DIR]:
    d.mkdir(parents=True, exist_ok=True)


class DynamicScenarioLoader:
    """
    محرك استيعاب ومزامنة السيناريوهات وقواعد الـ CVEs ومصادر المعرفة الخارجية تلقائياً:
    يفحص المجلدات، يكتشف أي ملفات جديدة، ينسقها ويدمجها في قاعدة المعرفة
    """

    def __init__(self, knowledge_store: Optional[KnowledgeStore] = None):
        self.kb = knowledge_store or KnowledgeStore()
        self.loaded_scenarios: Dict[str, Dict[str, Any]] = {}
        self.loaded_cves: Dict[str, Dict[str, Any]] = {}
        self.loaded_intel: Dict[str, Dict[str, Any]] = {}
        self.sync_all()

    def sync_all(self) -> Dict[str, Any]:
        """فحص كامل ومزامنة السيناريوهات والـ CVEs والمعارف الخارجية الجديدة"""
        new_scenarios = self._sync_scenarios()
        new_cves = self._sync_cves()
        new_intel = self._sync_intelligence()

        report = {
            "new_scenarios_added": len(new_scenarios),
            "new_cves_indexed": len(new_cves),
            "new_intelligence_indexed": len(new_intel),
            "total_active_scenarios": len(self.loaded_scenarios),
            "total_indexed_cves": len(self.loaded_cves),
            "total_indexed_intelligence": len(self.loaded_intel),
            "scenarios_list": list(self.loaded_scenarios.keys()),
            "cves_list": list(self.loaded_cves.keys()),
            "intelligence_list": list(self.loaded_intel.keys())
        }
        log.info(f"[SYNC] Scenario, CVE & Intelligence Sync completed: {report}")
        return report


    def _sync_scenarios(self) -> List[str]:
        new_loaded = []
        for json_file in SCENARIOS_DIR.glob("**/*.json"):
            try:
                data = json.loads(json_file.read_text(encoding="utf-8"))
                items = data if isinstance(data, list) else [data]
                for item in items:
                    s_id = item.get("scenario_id")
                    if s_id and s_id not in self.loaded_scenarios:
                        # Validate structure
                        if "hidden_truth" in item and "success_criteria" in item:
                            self.loaded_scenarios[s_id] = item
                            new_loaded.append(s_id)
            except Exception as e:
                log.warning(f"Could not parse scenario file {json_file}: {e}")
        return new_loaded

    def _sync_cves(self) -> List[str]:
        new_cves = []
        for json_file in CVES_DIR.glob("**/*.json"):
            try:
                data = json.loads(json_file.read_text(encoding="utf-8"))
                items = data if isinstance(data, list) else [data]
                for item in items:
                    cve_id = item.get("cve_id")
                    if cve_id and cve_id not in self.loaded_cves:
                        self.loaded_cves[cve_id] = item
                        new_cves.append(cve_id)

                        # Ingest into KnowledgeStore as structured KnowledgeItem
                        k_item = KnowledgeItem(
                            id=cve_id,
                            item_type="cve_case_study",
                            topic=item.get("vulnerability_type", "general").lower(),
                            name=f"{cve_id}: {item.get('software', 'Software')}",
                            prerequisites=[item.get("cwe", "CWE-89")],
                            signals=item.get("detection_signals", []),
                            verification_strategy=item.get("verification_strategy", ""),
                            evidence_requirements=item.get("evidence_requirements", []),
                            remediation_pattern=item.get("remediation", ""),
                            description=item.get("architecture_root_cause", "")
                        )
                        self.kb.save_item(k_item)
            except Exception as e:
                log.warning(f"Could not parse CVE file {json_file}: {e}")
        return new_cves

    def _sync_intelligence(self) -> List[str]:
        new_intel = []
        for json_file in INTELLIGENCE_DIR.glob("**/*.json"):
            try:
                data = json.loads(json_file.read_text(encoding="utf-8"))
                items = data if isinstance(data, list) else [data]
                for item in items:
                    intel_id = item.get("id") or item.get("intel_id")
                    if intel_id and intel_id not in self.loaded_intel:
                        self.loaded_intel[intel_id] = item
                        new_intel.append(intel_id)

                        k_item = KnowledgeItem(
                            id=intel_id,
                            item_type=item.get("item_type", "curated_intelligence"),
                            topic=item.get("topic", "sqli").lower(),
                            name=item.get("title") or item.get("name", "Intelligence Item"),
                            prerequisites=item.get("prerequisites", []),
                            signals=item.get("signals", []),
                            verification_strategy=item.get("verification_strategy", ""),
                            evidence_requirements=item.get("evidence_requirements", []),
                            remediation_pattern=item.get("remediation", ""),
                            description=item.get("description", "")
                        )
                        self.kb.save_item(k_item)
            except Exception as e:
                log.warning(f"Could not parse intelligence file {json_file}: {e}")
        return new_intel

    def get_scenario(self, scenario_id: str) -> Optional[Dict[str, Any]]:
        return self.loaded_scenarios.get(scenario_id)

    def get_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        return self.loaded_cves.get(cve_id)

    def get_intelligence(self, intel_id: str) -> Optional[Dict[str, Any]]:
        return self.loaded_intel.get(intel_id)

    def list_scenarios_by_skill(self, skill: str) -> List[Dict[str, Any]]:
        return [s for s in self.loaded_scenarios.values() if s.get("skill") == skill]

    def list_cves_by_vuln_type(self, vuln_type: str) -> List[Dict[str, Any]]:
        return [c for c in self.loaded_cves.values() if c.get("vulnerability_type") == vuln_type]

