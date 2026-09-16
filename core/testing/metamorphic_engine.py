"""
HunterAI Metamorphic Security Testing Engine
============================================
Tests semantic equivalence invariance:
If Request A is rejected, an equivalent Request A' (shuffled parameters,
alternative encoding, whitespace variance) MUST also be rejected.
A divergence indicates a security inconsistency or gateway parser desync.
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlencode

logger = logging.getLogger("hunter_ai.metamorphic_engine")


class MetamorphicRelationType(str, Enum):
    PARAMETER_ORDER_SHUFFLE = "PARAMETER_ORDER_SHUFFLE"
    URL_ENCODING_EQUIVALENCE = "URL_ENCODING_EQUIVALENCE"
    JSON_KEY_ORDER_SHUFFLE = "JSON_KEY_ORDER_SHUFFLE"
    CASE_NORMALIZATION = "CASE_NORMALIZATION"


@dataclass
class MetamorphicInconsistencyReport:
    report_id: str
    endpoint: str
    relation_type: MetamorphicRelationType
    baseline_request: Dict[str, Any]
    baseline_status: int
    transformed_request: Dict[str, Any]
    transformed_status: int
    inconsistency_rationale: str
    severity: str = "HIGH"


class MetamorphicEngine:
    """
    Applies meaning-preserving transformations to requests and checks security invariance.
    """

    def __init__(self):
        self.inconsistencies: List[MetamorphicInconsistencyReport] = []

    def test_parameter_order_invariance(
        self,
        endpoint: str,
        params: Dict[str, Any],
        request_fn
    ) -> Optional[MetamorphicInconsistencyReport]:
        """
        Tests whether reversing parameter order alters authorization or security decisions.
        """
        # Baseline order
        r1 = request_fn(params)
        s1 = r1.get("status", 403)

        # Reversed order
        rev_params = dict(reversed(list(params.items())))
        r2 = request_fn(rev_params)
        s2 = r2.get("status", 403)

        # Inconsistency: One denied (403/401) while other allowed (200)
        if (s1 in (401, 403) and s2 == 200) or (s2 in (401, 403) and s1 == 200):
            report = MetamorphicInconsistencyReport(
                report_id=f"META-{uuid.uuid4().hex[:6].upper()}",
                endpoint=endpoint,
                relation_type=MetamorphicRelationType.PARAMETER_ORDER_SHUFFLE,
                baseline_request={"params": params},
                baseline_status=s1,
                transformed_request={"params": rev_params},
                transformed_status=s2,
                inconsistency_rationale=(
                    f"Security Inconsistency: Baseline returned HTTP {s1}, but equivalent reversed "
                    f"parameter order returned HTTP {s2} on {endpoint}."
                ),
                severity="HIGH"
            )
            self.inconsistencies.append(report)
            return report
        return None

    def test_encoding_equivalence_invariance(
        self,
        endpoint: str,
        raw_param: str,
        encoded_param: str,
        request_fn
    ) -> Optional[MetamorphicInconsistencyReport]:
        """
        Tests whether equivalent URL encoding bypasses perimeter filters.
        """
        r1 = request_fn(raw_param)
        s1 = r1.get("status", 403)

        r2 = request_fn(encoded_param)
        s2 = r2.get("status", 403)

        if s1 in (401, 403) and s2 == 200:
            report = MetamorphicInconsistencyReport(
                report_id=f"META-{uuid.uuid4().hex[:6].upper()}",
                endpoint=endpoint,
                relation_type=MetamorphicRelationType.URL_ENCODING_EQUIVALENCE,
                baseline_request={"param": raw_param},
                baseline_status=s1,
                transformed_request={"param": encoded_param},
                transformed_status=s2,
                inconsistency_rationale="Encoding Bypass: Raw payload blocked by WAF/Gateway, but URL encoded equivalent accepted by backend.",
                severity="CRITICAL"
            )
            self.inconsistencies.append(report)
            return report
        return None
