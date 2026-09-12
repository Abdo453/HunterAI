"""
Tool & Capability Manifest System
Allows tools and skills to declare their capabilities, inputs, outputs, and requirements.
Enables the AI Planner to dynamically discover capable tools for a given security goal.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class ToolManifest:
    name: str
    category: str
    capabilities: List[str] = field(default_factory=list)
    inputs: List[str] = field(default_factory=list)
    outputs: List[str] = field(default_factory=list)
    requires: List[str] = field(default_factory=list)
    description: str = ""

    def satisfies_goal(self, goal_capability: str) -> bool:
        return goal_capability.lower() in [c.lower() for c in self.capabilities]


class ToolManifestRegistry:
    """
    سجل بيانات الأدوات والقدرات (Tool Manifest Registry):
    - يتيح للـ Planner البحث عن الأدوات القادرة على تحقيق هدف أمني محدد (e.g. 'content_discovery').
    """

    def __init__(self):
        self._manifests: Dict[str, ToolManifest] = {}
        self._load_builtin_manifests()

    def _load_builtin_manifests(self):
        # Register standard tool manifests
        self.register(ToolManifest(
            name="subfinder",
            category="recon",
            capabilities=["subdomain_enumeration", "passive_recon"],
            inputs=["target_domain"],
            outputs=["subdomains.txt"],
            requires=["network.dns", "filesystem.write"],
            description="Fast passive subdomain enumeration tool"
        ))

        self.register(ToolManifest(
            name="nmap",
            category="recon",
            capabilities=["port_scanning", "service_detection", "version_detection"],
            inputs=["target_domain", "ip_address"],
            outputs=["nmap.txt", "open_ports.txt"],
            requires=["network.scan", "filesystem.write"],
            description="Network port and service scanner"
        ))

        self.register(ToolManifest(
            name="ffuf",
            category="web",
            capabilities=["content_discovery", "fuzzing", "directory_enumeration"],
            inputs=["target_url", "wordlist"],
            outputs=["endpoints.txt"],
            requires=["network.http", "filesystem.write"],
            description="Fast web fuzzer and directory discovery tool"
        ))

        self.register(ToolManifest(
            name="playwright_browser",
            category="browser",
            capabilities=["browser_interaction", "dom_extraction", "network_interception", "ui_simulation"],
            inputs=["target_url"],
            outputs=["pages.txt", "links.txt", "forms.txt", "requests.txt", "screenshots"],
            requires=["browser.navigate", "browser.interact", "filesystem.write"],
            description="Headless browser intelligence and DOM interaction"
        ))

    def register(self, manifest: ToolManifest):
        self._manifests[manifest.name] = manifest

    def find_tools_by_capability(self, capability: str) -> List[ToolManifest]:
        """البحث عن كافة الأدوات التي تمتلك قدرة معينة"""
        return [m for m in self._manifests.values() if m.satisfies_goal(capability)]

    def get_manifest(self, tool_name: str) -> Optional[ToolManifest]:
        return self._manifests.get(tool_name)
