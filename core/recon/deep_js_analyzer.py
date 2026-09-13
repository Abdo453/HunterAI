"""
HunterAI Deep JavaScript Intelligence Extractor
================================================
Comprehensive extraction of client-side attack surface from JavaScript bundles:
- Hidden REST/GraphQL endpoints and fetch/axios calls
- Feature flags & Beta toggles (e.g. isFeatureEnabled, FLAG_*)
- Microservice & internal service names (e.g. auth-service, payment-worker)
- Sensitive admin, debug, and internal routes
- GraphQL query and mutation schemas
- Hardcoded environment tokens & secrets (REACT_APP_*, VITE_*)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Set


@dataclass
class JSIntelligenceReport:
    source_file: str
    endpoints: List[str] = field(default_factory=list)
    feature_flags: List[str] = field(default_factory=list)
    service_names: List[str] = field(default_factory=list)
    admin_paths: List[str] = field(default_factory=list)
    graphql_operations: List[str] = field(default_factory=list)
    env_keys: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_file": self.source_file,
            "endpoints_count": len(self.endpoints),
            "endpoints": sorted(self.endpoints),
            "feature_flags": sorted(self.feature_flags),
            "service_names": sorted(self.service_names),
            "admin_paths": sorted(self.admin_paths),
            "graphql_operations": sorted(self.graphql_operations),
            "env_keys": sorted(self.env_keys),
        }


class DeepJSAnalyzer:
    """Extracts rich architectural security intelligence from JavaScript sources"""

    # Patterns
    ENDPOINT_PATTERN = re.compile(
        r"""(?:fetch|axios(?:\.[a-z]+)?|\.open)\s*\(\s*['"`](/(?:api|v[0-9]|graphql|auth|user|order|pay|admin|internal)/[^'"`\s\)]+)['"`]""",
        re.I
    )
    GENERIC_PATH_PATTERN = re.compile(
        r"""['"`](/(?:api|v1|v2|v3|graphql|auth|user|order|admin|debug|internal|manage)/[^'"`\s\)\{\}]+)['"`]""",
        re.I
    )
    FEATURE_FLAG_PATTERN = re.compile(
        r"""(?:isFeatureEnabled|hasFeature|featureFlags?|features)\s*(?:\.|\()\s*['"`]([a-zA-Z0-9_\-\.]+)['"`]|(?:FLAG_[A-Z0-9_]+)""",
        re.I
    )
    SERVICE_NAME_PATTERN = re.compile(
        r"""(?:serviceName|targetService|service|microservice)\s*[:=]\s*['"`]([a-zA-Z0-9_\-]+(?:-service|-svc|-api|-worker))['"`]""",
        re.I
    )
    ADMIN_PATH_PATTERN = re.compile(
        r"""['"`](/(?:admin|manage|internal|dashboard|debug|superadmin|root|console|actuator|metrics)[^'"`\s\)]*)['"`]""",
        re.I
    )
    GRAPHQL_PATTERN = re.compile(
        r"""(?:query|mutation|subscription)\s+([A-Za-z0-9_]+)\s*(?:\([^\)]*\))?\s*\{""",
        re.M
    )
    ENV_KEY_PATTERN = re.compile(
        r"\b((?:REACT_APP_|VITE_|NEXT_PUBLIC_|API_KEY|JWT_SECRET|AUTH_TOKEN)[A-Za-z0-9_]*)\b",
        re.I
    )

    @classmethod
    def analyze_script(cls, js_content: str, source_file: str = "bundle.js") -> JSIntelligenceReport:
        report = JSIntelligenceReport(source_file=source_file)

        # 1. Endpoints
        endpoints_set: Set[str] = set()
        for m in cls.ENDPOINT_PATTERN.finditer(js_content):
            endpoints_set.add(m.group(1))
        for m in cls.GENERIC_PATH_PATTERN.finditer(js_content):
            endpoints_set.add(m.group(1))
        report.endpoints = list(endpoints_set)

        # 2. Feature flags
        flags_set: Set[str] = set()
        for m in cls.FEATURE_FLAG_PATTERN.finditer(js_content):
            flag = m.group(1) if m.group(1) else m.group(0)
            if flag and len(flag) > 2:
                flags_set.add(flag.strip())
        report.feature_flags = list(flags_set)

        # 3. Service names
        services_set: Set[str] = set()
        for m in cls.SERVICE_NAME_PATTERN.finditer(js_content):
            svc = m.group(1).strip()
            if svc:
                services_set.add(svc)
        report.service_names = list(services_set)

        # 4. Admin and Internal paths
        admin_set: Set[str] = set()
        for m in cls.ADMIN_PATH_PATTERN.finditer(js_content):
            admin_set.add(m.group(1).strip())
        report.admin_paths = list(admin_set)

        # 5. GraphQL operations
        gql_set: Set[str] = set()
        for m in cls.GRAPHQL_PATTERN.finditer(js_content):
            op = m.group(1).strip()
            if op:
                gql_set.add(op)
        report.graphql_operations = list(gql_set)

        # 6. Environment keys
        env_set: Set[str] = set()
        for m in cls.ENV_KEY_PATTERN.finditer(js_content):
            key = m.group(1).strip()
            if key:
                env_set.add(key)
        report.env_keys = list(env_set)

        return report
