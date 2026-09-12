"""
Code Intelligence Agent (Orchestrator)
=====================================
Orchestrates the entire Code Intelligence Pipeline:
PageCollector -> JSInventory -> SmartCodeChunker -> EndpointHunter
-> SecretHunter -> SourceSinkAnalyzer -> FrameworkAnalyzer -> Manifest.
"""
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.code_intel.chunker import SmartCodeChunker
from core.code_intel.codemap import CodeMapGenerator
from core.code_intel.collector import PageCollector
from core.code_intel.endpoint_hunter import EndpointHunter
from core.code_intel.framework_analyzer import FrameworkAnalyzer
from core.code_intel.inventory import JSInventory
from core.code_intel.models import (
    AnalysisManifest, ApplicationCodeMap, CodeFinding,
    DiscoveredEndpoint, PageAssetBundle, SecretCandidate, SourceSinkFlow
)
from core.code_intel.secret_hunter import SecretHunter
from core.code_intel.source_sink import SourceSinkAnalyzer

logger = logging.getLogger("hunter_ai.code_intel.agent")


class CodeIntelligenceAgent:
    """Master orchestrator for client-side static code and page asset intelligence"""

    def __init__(self, output_dir: Optional[str] = None):
        self.inventory = JSInventory()
        self.output_dir = Path(output_dir) if output_dir else None

    async def analyze_page(
        self,
        target_url: str,
        raw_html: str,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        fetched_scripts: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Executes end-to-end code intelligence on a web page and its associated JavaScript files.
        """
        logger.info(f"[CodeIntelligence] Analyzing page code for: {target_url}")

        # 1. Collect Page Assets
        bundle: PageAssetBundle = PageCollector.collect_from_html(
            target_url=target_url,
            raw_html=raw_html,
            headers=headers,
            cookies=cookies
        )

        all_endpoints: List[DiscoveredEndpoint] = []
        all_secrets: List[SecretCandidate] = []
        all_flows: List[SourceSinkFlow] = []
        all_chunks = []

        # 2. Analyze Inline Scripts
        for idx, script in enumerate(bundle.inline_scripts, start=1):
            s_name = f"inline_script_{idx}"
            _, is_dup = self.inventory.register(s_name, script)
            if not is_dup:
                chunks = SmartCodeChunker.chunk_javascript(script, file_path=s_name)
                all_chunks.extend(chunks)
                all_endpoints.extend(EndpointHunter.hunt_endpoints(script, source_file=s_name))
                all_secrets.extend(SecretHunter.hunt_secrets(script, source_file=s_name))
                all_flows.extend(SourceSinkAnalyzer.analyze_flows(script, source_file=s_name))

        # 3. Analyze Fetched External JS Scripts
        if fetched_scripts:
            for s_url, s_content in fetched_scripts.items():
                _, is_dup = self.inventory.register(s_url, s_content)
                if not is_dup:
                    chunks = SmartCodeChunker.chunk_javascript(s_content, file_path=s_url)
                    all_chunks.extend(chunks)
                    all_endpoints.extend(EndpointHunter.hunt_endpoints(s_content, source_file=s_url))
                    all_secrets.extend(SecretHunter.hunt_secrets(s_content, source_file=s_url))
                    all_flows.extend(SourceSinkAnalyzer.analyze_flows(s_content, source_file=s_url))

        # 4. Framework Specific Analysis
        framework_data = FrameworkAnalyzer.analyze_nextjs(bundle.next_data, raw_html, target_url)

        # 5. Build Code Map
        tech_stack = [framework_data.get("framework")] if framework_data.get("detected") else ["vanilla"]
        code_map: ApplicationCodeMap = CodeMapGenerator.generate_map(
            target=target_url,
            pages=[target_url],
            chunks=all_chunks,
            endpoints=all_endpoints,
            tech_stack=tech_stack
        )

        # 6. Generate Manifest
        manifest = AnalysisManifest(
            target=target_url,
            scope=[target_url],
            files_analyzed=1 + len(fetched_scripts or {}),
            js_analyzed=len(bundle.inline_scripts) + len(fetched_scripts or {}),
            endpoints_discovered=len(all_endpoints),
            secrets_discovered=len([s for s in all_secrets if s.status.value == "VALIDATED"]),
            technologies=tech_stack,
            observations=framework_data.get("observations", []),
            do_not_repeat=[]
        )

        # Save artifacts to output directory if configured
        if self.output_dir:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            with open(self.output_dir / "analysis_manifest.json", "w", encoding="utf-8") as f:
                json.dump(manifest.to_dict(), f, indent=2)
            with open(self.output_dir / "code_map.json", "w", encoding="utf-8") as f:
                json.dump(code_map.to_dict(), f, indent=2)
            with open(self.output_dir / "endpoints.json", "w", encoding="utf-8") as f:
                json.dump([ep.to_dict() for ep in all_endpoints], f, indent=2)

        return {
            "bundle": bundle.to_dict(),
            "manifest": manifest.to_dict(),
            "code_map": code_map.to_dict(),
            "endpoints": [ep.to_dict() for ep in all_endpoints],
            "secrets": [sec.to_dict() for sec in all_secrets],
            "source_sink_flows": [f.to_dict() for f in all_flows],
            "framework": framework_data
        }