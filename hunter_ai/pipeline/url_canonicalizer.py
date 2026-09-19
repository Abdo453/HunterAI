"""
HunterAI URL Canonicalizer & Endpoint Cluster Engine
===================================================
Normalizes, canonicalizes, deduplicates, and clusters discovered URLs across all sensors.
Provides:
1. URL Canonicalization: stripping tracking hashes, normalising paths, canonical sorting of query keys.
2. Endpoint Pattern Recognition: clustering dynamic parameterized endpoints into canonical families.
3. Live Host Correlation: linking crawled URLs to verified live hosts.
4. Parameter Extraction with Semantic Role Tagging via ParameterIntelligenceEngine.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlparse, urlsplit, urlunsplit, urlencode

from hunter_ai.pipeline.parameter_intelligence import ParameterIntelligenceEngine, ParameterClassification, ParameterRole
from hunter_ai.pipeline.schemas import EndpointRecord, ParameterRecord


@dataclass
class CanonicalEndpointFamily:
    pattern_id: str
    sample_url: str
    path_pattern: str
    method: str
    category: str
    raw_urls_count: int
    parameters: Dict[str, ParameterClassification] = field(default_factory=dict)
    live_host: str = ""


class URLCanonicalizer:
    """
    Consolidates thousands of raw crawled URLs (GAU, Katana, Wayback, Browser)
    into clean, normalized, clustered canonical endpoints.
    """

    UUID_REGEX = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
    HEX_HASH_REGEX = re.compile(r"[0-9a-f]{16,64}", re.I)
    NUMERIC_ID_REGEX = re.compile(r"/(?:[0-9]{1,12})(?=/|$)", re.I)

    @classmethod
    def canonicalize_url(cls, url: str) -> str:
        """Strips fragments and sorts query parameters for canonical consistency."""
        parts = urlsplit(url.strip())
        path = parts.path or "/"
        # Normalize double slashes
        while "//" in path:
            path = path.replace("//", "/")

        params = parse_qsl(parts.query, keep_blank_values=True)
        # Filter out noisy tracking params during canonicalization
        clean_params = [
            (k, v) for k, v in params
            if k.lower() not in ParameterIntelligenceEngine.TRACKING_PARAMS
        ]
        clean_params.sort(key=lambda x: x[0])
        new_query = urlencode(clean_params)

        netloc = parts.netloc.lower()
        if (parts.scheme.lower() == "https" and netloc.endswith(":443")) or (parts.scheme.lower() == "http" and netloc.endswith(":80")):
            netloc = netloc.rsplit(":", 1)[0]

        return urlunsplit((parts.scheme.lower(), netloc, path, new_query, ""))

    @classmethod
    def get_path_pattern(cls, path: str) -> str:
        """Generalizes dynamic segments (UUIDs, hashes, numeric IDs) into pattern variables."""
        p = cls.UUID_REGEX.sub("{uuid}", path)
        p = cls.HEX_HASH_REGEX.sub("{hash}", p)
        p = cls.NUMERIC_ID_REGEX.sub("/{id}", p)
        return p

    @classmethod
    def process_url_inventory(
        cls,
        raw_urls: List[str],
        live_hosts: Set[str],
        target_domain: str,
    ) -> Tuple[List[EndpointRecord], List[ParameterRecord], List[CanonicalEndpointFamily]]:
        """
        Takes raw URLs from all sensors, canonicalizes and clusters them,
        and returns clean EndpointRecords and ParameterRecords.
        """
        seen_canonical: Set[str] = set()
        families: Dict[str, CanonicalEndpointFamily] = {}
        endpoints: List[EndpointRecord] = []
        parameters: List[ParameterRecord] = []
        seen_param_keys: Set[str] = set()

        for raw_u in raw_urls:
            if not isinstance(raw_u, str) or not raw_u.strip():
                continue

            canon_u = cls.canonicalize_url(raw_u)
            parts = urlsplit(canon_u)
            host = parts.netloc.lower().split(":")[0]

            # In-scope and domain verification
            if target_domain not in host:
                continue

            path = parts.path or "/"
            path_pat = cls.get_path_pattern(path)
            category = "API" if ("/api" in path or path.startswith("/v1") or path.startswith("/v2")) else (
                "ADMIN" if "admin" in path else (
                    "IMAGE" if any(path.endswith(ext) for ext in ParameterIntelligenceEngine.STATIC_EXTENSIONS) else "WEB"
                )
            )

            # Cluster Family Key: method:host:path_pattern
            fam_key = f"GET:{host}:{path_pat}"
            if fam_key not in families:
                families[fam_key] = CanonicalEndpointFamily(
                    pattern_id=fam_key,
                    sample_url=canon_u,
                    path_pattern=path_pat,
                    method="GET",
                    category=category,
                    raw_urls_count=1,
                    live_host=host,
                )
            else:
                families[fam_key].raw_urls_count += 1

            # Only add distinct canonical URLs to endpoints (max 10 per family cluster)
            if canon_u not in seen_canonical:
                seen_canonical.add(canon_u)
                if families[fam_key].raw_urls_count <= 10:
                    endpoints.append(EndpointRecord(
                        url=canon_u,
                        path=path,
                        method="GET",
                        category=category,
                        source="crawled_canonical",
                    ))

            # Process parameters with ParameterIntelligenceEngine
            if parts.query:
                query_tuples = parse_qsl(parts.query, keep_blank_values=True)
                for p_name, p_val in query_tuples:
                    p_name_clean = p_name.strip()
                    if not p_name_clean:
                        continue

                    classification = ParameterIntelligenceEngine.classify(
                        endpoint_url=canon_u,
                        param_name=p_name_clean,
                        sample_value=p_val,
                    )

                    families[fam_key].parameters[p_name_clean] = classification

                    # Deduplicate parameters: 1 per parameter per endpoint family!
                    param_fingerprint = f"{fam_key}::{p_name_clean}"
                    if param_fingerprint not in seen_param_keys:
                        seen_param_keys.add(param_fingerprint)
                        param_rec = ParameterRecord(
                            parameter=p_name_clean,
                            endpoint=canon_u,
                            method="GET",
                            source="crawled_query",
                            potential_classes=classification.potential_vulns,
                            sample_value=p_val,
                            context={
                                "role": classification.role.value,
                                "risk_level": classification.risk_level,
                                "is_active_candidate": classification.is_active_candidate,
                                "rationale": classification.rationale,
                                "family_pattern": path_pat,
                            },
                        )
                        parameters.append(param_rec)

        return endpoints, parameters, list(families.values())
