"""
Deep Parameter Miner & Input Surface Synthesizer (ParamMiner)
=============================================================
Identifies, mines, and classifies HTTP parameters across GET and POST requests
inspired by arjun, paramspider, x8, and SecLists burp-parameter-names.

Capabilities:
1. Ingests raw URLs and extracts embedded query parameters.
2. Ingests and parses Arjun JSON/CLI discovery outputs for GET and POST endpoints.
3. Automatically classifies parameters into vulnerability attack vectors:
   - IDOR / BOLA
   - SSRF & Out-of-Band Callbacks
   - SQL Injection (BEUSTQ)
   - LFI / Path Traversal
   - Remote Command Execution
   - Open Redirect
   - Mass Assignment / Privilege Escalation
4. Synthesizes probe URLs and request payloads (qsreplace FUZZ, SQLMap marker *).
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse


@dataclass
class ParameterTarget:
    url: str
    method: str  # "GET" or "POST"
    parameter_name: str
    vulnerability_category: str
    probe_url: str
    suggested_tool: str
    post_body: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ParamMiner:
    """Heuristic and tool-assisted HTTP parameter miner and classifier."""

    PARAM_CATEGORIES: Dict[str, Dict[str, Any]] = {
        "IDOR_BOLA": {
            "keywords": {
                "id", "user_id", "uid", "account", "account_id", "org_id",
                "doc_id", "uuid", "profile_id", "order_id", "item_id",
                "file_id", "invoice_id", "customer_id", "member_id", "user",
            },
            "tool": "dual_session_replay",
            "probe_val": "CANARY_IDOR_PROBE",
        },
        "SSRF": {
            "keywords": {
                "url", "dest", "destination", "redirect", "uri", "webhook",
                "feed", "proxy", "target", "host", "callback", "fetch",
                "domain", "endpoint", "api_url", "image_url", "load_from",
            },
            "tool": "canary_oob_listener",
            "probe_val": "http://127.0.0.1:80",
        },
        "SQLI": {
            "keywords": {
                "query", "search", "filter", "sort", "order", "dir", "by",
                "cat", "category", "offset", "limit", "column", "tbl",
                "page_id", "item", "select", "keyword", "keywords",
            },
            "tool": "sqlmap",
            "probe_val": "*",
        },
        "LFI_TRAVERSAL": {
            "keywords": {
                "file", "path", "template", "include", "page", "doc",
                "folder", "view", "layout", "load", "style", "theme",
            },
            "tool": "path_traversal_fuzzer",
            "probe_val": "....//....//etc/passwd",
        },
        "COMMAND_INJECTION": {
            "keywords": {
                "cmd", "exec", "command", "ping", "ip", "host", "run",
                "payload", "script", "shell", "eval", "code",
            },
            "tool": "commix",
            "probe_val": ";id",
        },
        "OPEN_REDIRECT": {
            "keywords": {
                "next", "return", "return_to", "rurl", "goto", "checkout_url",
                "continue", "forward", "back", "target_url",
            },
            "tool": "redirect_fuzzer",
            "probe_val": "https://example.com",
        },
        "MASS_ASSIGNMENT": {
            "keywords": {
                "role", "admin", "is_admin", "tier", "group", "privilege",
                "status", "balance", "verified", "permission", "is_superuser",
            },
            "tool": "privilege_tamper",
            "probe_val": "true",
        },
    }

    def __init__(self):
        # Flattened fast lookup table
        self.keyword_to_category: Dict[str, Tuple[str, str, str]] = {}
        for cat, meta in self.PARAM_CATEGORIES.items():
            for kw in meta["keywords"]:
                self.keyword_to_category[kw] = (cat, meta["tool"], meta["probe_val"])

    def classify_parameter(self, param_name: str) -> Tuple[str, str, str]:
        """Classifies a parameter name into (Category, Suggested Tool, Probe Value)."""
        clean_name = param_name.strip().lower()
        if clean_name in self.keyword_to_category:
            return self.keyword_to_category[clean_name]

        # Substring / pattern matching
        for kw, (cat, tool, probe) in self.keyword_to_category.items():
            if kw in clean_name or clean_name.startswith(kw) or clean_name.endswith(kw):
                return (cat, tool, probe)

        return ("GENERIC_INPUT", "fuzzer", "FUZZ")

    def extract_from_urls(self, urls: List[str]) -> List[ParameterTarget]:
        """Extracts and classifies all parameters present in a list of URLs."""
        results: List[ParameterTarget] = []
        seen: Set[Tuple[str, str, str]] = set()

        for u in urls:
            u_clean = u.strip()
            if not u_clean or "://" not in u_clean:
                continue

            parsed = urlparse(u_clean)
            if not parsed.query:
                continue

            q_params = parse_qs(parsed.query, keep_blank_values=True)
            for param_name in q_params.keys():
                cat, tool, probe_val = self.classify_parameter(param_name)
                sig = (parsed.path, "GET", param_name)
                if sig in seen:
                    continue
                seen.add(sig)

                # Generate probe URL using qsreplace logic
                probe_query = dict(q_params)
                probe_query[param_name] = [probe_val]
                encoded_query = urlencode(probe_query, doseq=True)
                probe_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    encoded_query,
                    parsed.fragment,
                ))

                results.append(ParameterTarget(
                    url=u_clean,
                    method="GET",
                    parameter_name=param_name,
                    vulnerability_category=cat,
                    probe_url=probe_url,
                    suggested_tool=tool,
                    post_body=None,
                ))

        return results

    def parse_arjun_json(self, arjun_output: Dict[str, Any]) -> List[ParameterTarget]:
        """Parses output from Arjun (-oJ / JSON export) for GET and POST discoveries."""
        targets: List[ParameterTarget] = []
        if not isinstance(arjun_output, dict):
            return targets

        for url, params in arjun_output.items():
            if not isinstance(params, list):
                continue

            for p in params:
                param_name = str(p).strip()
                cat, tool, probe_val = self.classify_parameter(param_name)

                # Synthesize GET target
                parsed = urlparse(url)
                probe_url = f"{url}{'&' if '?' in url else '?'}{param_name}={probe_val}"

                targets.append(ParameterTarget(
                    url=url,
                    method="GET",
                    parameter_name=param_name,
                    vulnerability_category=cat,
                    probe_url=probe_url,
                    suggested_tool=tool,
                    post_body=f"{param_name}={probe_val}",
                ))

        return targets

    def synthesize_sqlmap_command(self, target: ParameterTarget) -> str:
        """Synthesizes high-impact SQLMap commands with BEUSTQ techniques and batch modes."""
        if target.method == "POST":
            return (
                f'sqlmap -u "{target.url}" --data "{target.post_body}" '
                f'-p {target.parameter_name} --technique=BEUSTQ --batch --random-agent --banner --dbs'
            )
        return (
            f'sqlmap -u "{target.probe_url}" -p {target.parameter_name} '
            f'--technique=BEUSTQ --batch --random-agent --banner --dbs --ignore-code 403'
        )
