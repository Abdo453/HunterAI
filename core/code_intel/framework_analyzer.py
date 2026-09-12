"""
Framework-Aware Analyzer
========================
Deep specialized analysis for Next.js, React, Vue:
Analyzes __NEXT_DATA__, dynamic routes, client/server component boundaries,
exposed environment variables (NEXT_PUBLIC_*), and source maps.
"""
import json
import logging
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hunter_ai.code_intel.framework")


class FrameworkAnalyzer:
    """Specialized analyzer for modern JavaScript frameworks"""

    @classmethod
    def analyze_nextjs(cls, next_data: Optional[Dict[str, Any]], raw_html: str, target_url: str) -> Dict[str, Any]:
        result = {
            "framework": "Next.js",
            "detected": False,
            "build_id": None,
            "page": None,
            "dynamic_routes": [],
            "exposed_env": [],
            "observations": []
        }

        if next_data and isinstance(next_data, dict):
            result["detected"] = True
            result["build_id"] = next_data.get("buildId")
            result["page"] = next_data.get("page")
            props = next_data.get("props", {})
            page_props = props.get("pageProps", {})

            result["observations"].append(f"Next.js buildId={result['build_id']} on page={result['page']}")

            # Extract exposed env / state
            if isinstance(page_props, dict):
                for k, v in page_props.items():
                    if any(sec in k.lower() for sec in ("key", "secret", "token", "auth")):
                        result["exposed_env"].append({"key": k, "value": str(v)[:50]})

            # Dynamic routes
            query = next_data.get("query", {})
            if query:
                result["dynamic_routes"].extend(list(query.keys()))

        # Check for Next.js static asset patterns in HTML
        if "_next/static" in raw_html:
            result["detected"] = True
            m_build = re.search(r"/_next/static/([a-zA-Z0-9_-]{10,})/_buildManifest\.js", raw_html)
            if m_build and not result["build_id"]:
                result["build_id"] = m_build.group(1)

        # Look for NEXT_PUBLIC_ variables
        next_pub_m = re.findall(r"NEXT_PUBLIC_([A-Za-z0-9_]+)", raw_html)
        if next_pub_m:
            for var in dict.fromkeys(next_pub_m):
                result["exposed_env"].append({"variable": f"NEXT_PUBLIC_{var}"})

        return result