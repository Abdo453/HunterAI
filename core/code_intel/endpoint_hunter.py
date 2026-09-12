"""
Endpoint Hunter
===============
Extracts REST endpoints, fetch(), axios, XMLHttpRequest, WebSocket, and GraphQL calls
from JavaScript source code with line tracking and parameter extraction.
"""
import re
from typing import List, Set
from urllib.parse import parse_qs, urlparse

from core.code_intel.models import DiscoveredEndpoint


class EndpointHunter:
    """Searches JavaScript code for reachable API routes and network endpoints"""

    # Patterns for API calls
    FETCH_PATTERN = re.compile(r"""fetch\s*\(\s*['"`]?(/[^'"`\s\)]+|https?://[^'"`\s\)]+)['"`]?""", re.I)
    AXIOS_PATTERN = re.compile(r"""axios\.(?:get|post|put|delete|patch)\s*\(\s*['"`]?(/[^'"`\s\)]+|https?://[^'"`\s\)]+)['"`]?""", re.I)
    XHR_PATTERN = re.compile(r"""\.open\s*\(\s*['"](GET|POST|PUT|DELETE)['"]\s*,\s*['"`]?(/[^'"`\s\)]+|https?://[^'"`\s\)]+)['"`]?""", re.I)
    WS_PATTERN = re.compile(r"""new\s+WebSocket\s*\(\s*['"`](wss?://[^'"`\s\)]+)['"`]""", re.I)
    API_PATH_PATTERN = re.compile(r"""['"`](/(?:api|v1|v2|v3|graphql|auth|user|admin|service)/[^'"`\s\)]+)['"`]""", re.I)

    @classmethod
    def hunt_endpoints(cls, js_content: str, source_file: str = "") -> List[DiscoveredEndpoint]:
        endpoints: List[DiscoveredEndpoint] = []
        seen: Set[str] = set()
        lines = js_content.splitlines()

        for idx, line in enumerate(lines, start=1):
            # 1. fetch()
            for m in cls.FETCH_PATTERN.finditer(line):
                path = m.group(1).strip()
                if path and path not in seen:
                    seen.add(path)
                    endpoints.append(cls._build_endpoint(path, "GET", source_file, idx, "fetch"))

            # 2. axios
            for m in cls.AXIOS_PATTERN.finditer(line):
                path = m.group(1).strip()
                if path and path not in seen:
                    seen.add(path)
                    endpoints.append(cls._build_endpoint(path, "POST" if "post" in line.lower() else "GET", source_file, idx, "axios"))

            # 3. XHR .open()
            for m in cls.XHR_PATTERN.finditer(line):
                method = m.group(1).upper()
                path = m.group(2).strip()
                if path and path not in seen:
                    seen.add(path)
                    endpoints.append(cls._build_endpoint(path, method, source_file, idx, "xhr"))

            # 4. WebSocket
            for m in cls.WS_PATTERN.finditer(line):
                ws_url = m.group(1).strip()
                if ws_url and ws_url not in seen:
                    seen.add(ws_url)
                    endpoints.append(cls._build_endpoint(ws_url, "WS", source_file, idx, "websocket"))

            # 5. Generic API path constants
            for m in cls.API_PATH_PATTERN.finditer(line):
                path = m.group(1).strip()
                if path and path not in seen and not any(ext in path for ext in (".js", ".css", ".png", ".svg", ".woff")):
                    seen.add(path)
                    endpoints.append(cls._build_endpoint(path, "GET", source_file, idx, "path_constant"))

        return endpoints

    @classmethod
    def _build_endpoint(cls, path: str, method: str, source_file: str, line_no: int, discovery_type: str) -> DiscoveredEndpoint:
        params: List[str] = []
        if "?" in path:
            qs = parse_qs(urlparse(path).query)
            params = list(qs.keys())

        # Auth hint detection
        auth_hint = None
        p_lower = path.lower()
        if "auth" in p_lower or "token" in p_lower or "login" in p_lower:
            auth_hint = "bearer_or_cookie"
        elif "admin" in p_lower:
            auth_hint = "privileged"

        return DiscoveredEndpoint(
            url_or_path=path,
            method=method,
            source_file=source_file,
            line_number=line_no,
            parameters=params,
            auth_hint=auth_hint,
            discovery_type=discovery_type
        )