"""
CVSS v3.1 Base Score Calculator & Metric Mapper
Calculates exact CVSS v3.1 Base Scores from Attack Vector, Complexity, Privileges, User Interaction, Scope, and Impact metrics.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class CVSSMetrics:
    attack_vector: str = "N"          # N (Network), A (Adjacent), L (Local), P (Physical)
    attack_complexity: str = "L"      # L (Low), H (High)
    privileges_required: str = "N"    # N (None), L (Low), H (High)
    user_interaction: str = "N"       # N (None), R (Required)
    scope: str = "U"                  # U (Unchanged), C (Changed)
    confidentiality: str = "H"        # N (None), L (Low), H (High)
    integrity: str = "H"              # N (None), L (Low), H (High)
    availability: str = "N"           # N (None), L (Low), H (High)


# CVSS 3.1 Numerical Value Maps
AV_VALS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC_VALS = {"L": 0.77, "H": 0.44}
PR_VALS_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_VALS_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
UI_VALS = {"N": 0.85, "R": 0.62}
CIA_VALS = {"N": 0.0, "L": 0.22, "H": 0.56}


class CVSSCalculator:
    """
    حاسبة نقاط ومعايير CVSS v3.1 القياسية
    """

    @staticmethod
    def calculate_base_score(metrics: CVSSMetrics) -> float:
        """
        حساب Base Score وفق معادلات FIRST CVSS v3.1 الرسمية
        """
        av = AV_VALS.get(metrics.attack_vector.upper(), 0.85)
        ac = AC_VALS.get(metrics.attack_complexity.upper(), 0.77)
        ui = UI_VALS.get(metrics.user_interaction.upper(), 0.85)

        is_changed = metrics.scope.upper() == "C"
        pr_map = PR_VALS_CHANGED if is_changed else PR_VALS_UNCHANGED
        pr = pr_map.get(metrics.privileges_required.upper(), 0.85)

        c = CIA_VALS.get(metrics.confidentiality.upper(), 0.0)
        i = CIA_VALS.get(metrics.integrity.upper(), 0.0)
        a = CIA_VALS.get(metrics.availability.upper(), 0.0)

        # 1. Calculate ISS (Impact Sub-Score Base)
        iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

        # 2. Calculate Impact Sub-Score
        if not is_changed:
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        # 3. Calculate Exploitability Sub-Score
        exploitability = 8.22 * av * ac * pr * ui

        # 4. Calculate Base Score
        if impact <= 0:
            return 0.0

        if not is_changed:
            base_unrounded = min(impact + exploitability, 10.0)
        else:
            base_unrounded = min(1.08 * (impact + exploitability), 10.0)

        # CVSS Roundup function (to nearest 0.1)
        return CVSSCalculator.roundup(base_unrounded)

    @staticmethod
    def roundup(value: float) -> float:
        """FIRST CVSS v3.1 Roundup function"""
        int_input = math.floor(value * 100000 + 0.5)
        if int_input % 10000 == 0:
            return int_input / 100000.0
        else:
            return (math.floor(int_input / 10000) + 1) / 10.0

    @staticmethod
    def derive_from_vrt(vrt_id: str, severity: str = "Medium") -> float:
        """اشتقاق وحساب CVSS بناءً على نوع الثغرة ومستوى الخطورة"""
        vid = vrt_id.lower()
        if "remote_code_execution" in vid or "rce" in vid:
            return CVSSCalculator.calculate_base_score(CVSSMetrics(
                attack_vector="N", attack_complexity="L", privileges_required="N",
                user_interaction="N", scope="C", confidentiality="H", integrity="H", availability="H"
            ))  # ~10.0
        elif "sql_injection" in vid or "sqli" in vid:
            return CVSSCalculator.calculate_base_score(CVSSMetrics(
                attack_vector="N", attack_complexity="L", privileges_required="N",
                user_interaction="N", scope="U", confidentiality="H", integrity="H", availability="L"
            ))  # ~9.4
        elif "ssrf.cloud" in vid:
            return CVSSCalculator.calculate_base_score(CVSSMetrics(
                attack_vector="N", attack_complexity="L", privileges_required="N",
                user_interaction="N", scope="C", confidentiality="H", integrity="L", availability="N"
            ))  # ~9.3
        elif "idor" in vid or "broken_access" in vid:
            return CVSSCalculator.calculate_base_score(CVSSMetrics(
                attack_vector="N", attack_complexity="L", privileges_required="L",
                user_interaction="N", scope="U", confidentiality="H", integrity="H", availability="N"
            ))  # ~8.1
        elif "stored_xss" in vid or "xss" in vid:
            return CVSSCalculator.calculate_base_score(CVSSMetrics(
                attack_vector="N", attack_complexity="L", privileges_required="N",
                user_interaction="R", scope="C", confidentiality="L", integrity="L", availability="N"
            ))  # ~6.1
        elif "graphql_introspection" in vid or "information_disclosure" in vid:
            return CVSSCalculator.calculate_base_score(CVSSMetrics(
                attack_vector="N", attack_complexity="L", privileges_required="N",
                user_interaction="N", scope="U", confidentiality="L", integrity="N", availability="N"
            ))  # ~5.3
        
        # Default fallback based on severity string
        sev = severity.capitalize()
        if sev == "Critical":
            return 9.8
        elif sev == "High":
            return 8.2
        elif sev == "Medium":
            return 6.1
        elif sev == "Low":
            return 3.5
        return 0.0
