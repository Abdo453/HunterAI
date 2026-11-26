"""
Code Intelligence Agent (Orchestrator)
=====================================
Orchestrates the entire Code Intelligence Pipeline:
PageCollector -> JSInventory -> SourceMap Resolution -> SmartCodeChunker
-> EndpointHunter -> SecretHunter -> SourceSinkAnalyzer -> FrameworkAnalyzer -> Manifest.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urljoin

from core.code_intel.chunker import SmartCodeChunker
from core.code_intel.codemap import CodeMapGenerator
from core.code_intel.collector import PageCollector
from core.code_intel.endpoint_hunter import EndpointHunter
from core.code_intel.framework_analyzer import FrameworkAnalyzer
from core.code_intel.inventory import JSInventory
from core.code_intel.models import (
    AnalysisManifest,
    ApplicationCodeMap,
    CodeFinding,
    DiscoveredEndpoint,
    JSInventoryItem,
    PageAssetBundle,
    SecretCandidate,
    SourceSinkFlow,
)
from core.code_intel.secret_hunter import SecretHunter
from core.code_intel.source_sink import SourceSinkAnalyzer

logger = logging.getLogger("hunter_ai.code_intel.agent")


class CodeIntelligenceAgent:
    """Master orchestrator for client-side static code and page asset intelligence"""

    def __init__(self, output_dir: Optional[str] = None):
        self.inventory = JSInventory()
        self.output_dir = Path(output_dir) if output_dir else None

    @staticmethod
    def _parse_source_map_payload(raw_map: str, map_label: str) -> List[Tuple[str, str]]:
        """Parse a Source Map v3 JSON payload into `(source_label, source_code)` pairs."""
        try:
            data = json.loads(raw_map)
        except Exception:
            return []
        if not isinstance(data, dict):
            return []
        sources = data.get("sources") or []
        contents = data.get("sourcesContent") or []
        if not isinstance(sources, list) or not isinstance(contents, list):
            return []

        extracted: List[Tuple[str, str]] = []
        for idx, src_code in enumerate(contents):
            if not isinstance(src_code, str) or not src_code.strip():
                continue
            src_name = str(sources[idx]) if idx < len(sources) and sources[idx] else f"source_{idx}.js"
            extracted.append((f"{map_label}::{src_name}", src_code))
        return extracted

    async def _resolve_source_map(
        self,
        script_url: str,
        item: JSInventoryItem,
        *,
        target_url: str,
        source_maps: Optional[Dict[str, str]] = None,
        source_map_fetcher: Optional[Callable[[str], Any]] = None,
    ) -> Tuple[Optional[str], List[Tuple[str, str]]]:
        """Resolve an inline or external JS source map into original source code entries."""
        if not item.has_source_map or not item.source_map_url:
            return None, []

        raw_ref = item.source_map_url.strip()
        # 1. Inline data: URI source map (hermetic, offline)
        if raw_ref.startswith("data:") and "base64," in raw_ref:
            try:
                b64_part = raw_ref.split("base64,", 1)[1].strip()
                decoded = base64.b64decode(b64_part).decode("utf-8", errors="replace")
                label = f"{script_url}#inline_sourcemap"
                return label, self._parse_source_map_payload(decoded, label)
            except Exception as exc:
                logger.debug("Inline source map decode failed for %s: %s", script_url, exc)
                return None, []

        # 2. External sourceMappingURL resolved relative to script_url (or target_url)
        base_for_join = script_url if "://" in script_url else target_url
        resolved_url = urljoin(base_for_join, raw_ref)

        raw_map: Optional[str] = None
        if source_maps:
            raw_map = (
                source_maps.get(resolved_url)
                or source_maps.get(raw_ref)
                or source_maps.get(script_url)
            )
        if raw_map is None and source_map_fetcher is not None:
            try:
                fetched = source_map_fetcher(resolved_url)
                if asyncio.iscoroutine(fetched):
                    fetched = await fetched
                if isinstance(fetched, str) and fetched.strip():
                    raw_map = fetched
            except Exception as exc:
                logger.debug("External source map fetch failed for %s: %s", resolved_url, exc)

        if not raw_map:
            return None, []
        return resolved_url, self._parse_source_map_payload(raw_map, resolved_url)

    def _analyze_script_content(
        self,
        source_label: str,
        content: str,
        *,
        all_chunks: List[Any],
        all_endpoints: List[DiscoveredEndpoint],
        all_secrets: List[SecretCandidate],
        all_flows: List[SourceSinkFlow],
    ) -> Tuple[JSInventoryItem, bool]:
        item, is_dup = self.inventory.register(source_label, content)
        if not is_dup:
            all_chunks.extend(SmartCodeChunker.chunk_javascript(content, file_path=source_label))
            all_endpoints.extend(EndpointHunter.hunt_endpoints(content, source_file=source_label))
            all_secrets.extend(SecretHunter.hunt_secrets(content, source_file=source_label))
            all_flows.extend(SourceSinkAnalyzer.analyze_flows(content, source_file=source_label))
        return item, is_dup

    async def analyze_page(
        self,
        target_url: str,
        raw_html: str,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        fetched_scripts: Optional[Dict[str, str]] = None,
        source_maps: Optional[Dict[str, str]] = None,
        source_map_fetcher: Optional[Callable[[str], Any]] = None,
        resolve_source_maps: bool = True,
    ) -> Dict[str, Any]:
        """
        Executes end-to-end code intelligence on a web page, its fetched JavaScript files,
        and any resolved Source Map v3 original sources.
        """
        logger.info(f"[CodeIntelligence] Analyzing page code for: {target_url}")

        # 1. Collect Page Assets
        bundle: PageAssetBundle = PageCollector.collect_from_html(
            target_url=target_url,
            raw_html=raw_html,
            headers=headers,
            cookies=cookies,
        )

        all_endpoints: List[DiscoveredEndpoint] = []
        all_secrets: List[SecretCandidate] = []
        all_flows: List[SourceSinkFlow] = []
        all_chunks: List[Any] = []
        resolved_source_maps: List[Dict[str, Any]] = []

        # 2. Analyze Inline Scripts
        for idx, script in enumerate(bundle.inline_scripts, start=1):
            s_name = f"inline_script_{idx}"
            item, is_dup = self._analyze_script_content(
                s_name,
                script,
                all_chunks=all_chunks,
                all_endpoints=all_endpoints,
                all_secrets=all_secrets,
                all_flows=all_flows,
            )
            if not is_dup and resolve_source_maps and item.has_source_map:
                map_url, recovered = await self._resolve_source_map(
                    s_name,
                    item,
                    target_url=target_url,
                    source_maps=source_maps,
                    source_map_fetcher=source_map_fetcher,
                )
                if map_url and recovered:
                    resolved_source_maps.append({
                        "script": s_name,
                        "source_map": map_url,
                        "sources_count": len(recovered),
                    })
                    for src_label, src_code in recovered:
                        self._analyze_script_content(
                            src_label,
                            src_code,
                            all_chunks=all_chunks,
                            all_endpoints=all_endpoints,
                            all_secrets=all_secrets,
                            all_flows=all_flows,
                        )

        # 3. Analyze Fetched External JS Scripts (+ Source Map resolution)
        if fetched_scripts:
            for s_url, s_content in fetched_scripts.items():
                if not isinstance(s_content, str) or not s_content:
                    continue
                item, is_dup = self._analyze_script_content(
                    s_url,
                    s_content,
                    all_chunks=all_chunks,
                    all_endpoints=all_endpoints,
                    all_secrets=all_secrets,
                    all_flows=all_flows,
                )
                if not is_dup and resolve_source_maps and item.has_source_map:
                    map_url, recovered = await self._resolve_source_map(
                        s_url,
                        item,
                        target_url=target_url,
                        source_maps=source_maps,
                        source_map_fetcher=source_map_fetcher,
                    )
                    if map_url and recovered:
                        resolved_source_maps.append({
                            "script": s_url,
                            "source_map": map_url,
                            "sources_count": len(recovered),
                        })
                        for src_label, src_code in recovered:
                            self._analyze_script_content(
                                src_label,
                                src_code,
                                all_chunks=all_chunks,
                                all_endpoints=all_endpoints,
                                all_secrets=all_secrets,
                                all_flows=all_flows,
                            )

        # 4. Framework Specific Analysis
        framework_data = FrameworkAnalyzer.analyze_nextjs(bundle.next_data, raw_html, target_url)

        # 5. Build Code Map
        tech_stack = [framework_data.get("framework")] if framework_data.get("detected") else ["vanilla"]
        code_map: ApplicationCodeMap = CodeMapGenerator.generate_map(
            target=target_url,
            pages=[target_url],
            chunks=all_chunks,
            endpoints=all_endpoints,
            tech_stack=tech_stack,
        )

        # 6. Generate Manifest
        recovered_sources_total = sum(int(m.get("sources_count", 0)) for m in resolved_source_maps)
        manifest = AnalysisManifest(
            target=target_url,
            scope=[target_url],
            files_analyzed=1 + len(fetched_scripts or {}) + recovered_sources_total,
            js_analyzed=len(bundle.inline_scripts) + len(fetched_scripts or {}) + recovered_sources_total,
            endpoints_discovered=len(all_endpoints),
            secrets_discovered=len([s for s in all_secrets if s.status.value == "VALIDATED"]),
            technologies=tech_stack,
            observations=framework_data.get("observations", []),
            do_not_repeat=[],
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
            "source_maps_resolved": resolved_source_maps,
            "framework": framework_data,
        }
