"""
Application Code Map Generator
==============================
Builds high-level interactive architectural tree of the target web application:
Pages -> Functions -> API Endpoints.
"""
from typing import Any, Dict, List
from core.code_intel.models import ApplicationCodeMap, CodeChunk, DiscoveredEndpoint


class CodeMapGenerator:
    """Constructs application architecture map"""

    @classmethod
    def generate_map(
        cls,
        target: str,
        pages: List[str],
        chunks: List[CodeChunk],
        endpoints: List[DiscoveredEndpoint],
        tech_stack: List[str]
    ) -> ApplicationCodeMap:
        func_map: Dict[str, List[str]] = {}
        for chk in chunks:
            if chk.name and chk.name not in ("block", ""):
                file_k = chk.file_path or "inline"
                func_map.setdefault(file_k, []).append(f"{chk.name}:{chk.start_line}")

        api_routes = [
            {
                "path": ep.url_or_path,
                "method": ep.method,
                "file": ep.source_file,
                "line": ep.line_number,
                "params": ep.parameters,
                "auth": ep.auth_hint
            }
            for ep in endpoints
        ]

        return ApplicationCodeMap(
            target=target,
            pages=pages,
            functions=func_map,
            api_routes=api_routes,
            technology_stack=tech_stack
        )