"""
HunterAI Semantic Mutation Grammar Engine
=========================================
Generates systematic, deterministic candidate mutations based on parameter semantic roles:
- FINANCIAL_VALUE -> negative, zero, boundary, decimal, overflow
- IDENTITY_REFERENCE -> sequence delta, uuid mutation, cross-tenant, null
- ROLE_FLAG -> admin injection, boolean inversion, string elevation
- REDIRECT_TARGET -> protocol-relative, crlf, subdomain collision
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hunter_ai.mutation_grammar")


class MutationCategory(str, Enum):
    NUMERIC_BOUNDARY = "NUMERIC_BOUNDARY"
    NEGATIVE_ARITHMETIC = "NEGATIVE_ARITHMETIC"
    TYPE_CONFUSION = "TYPE_CONFUSION"
    SPECIAL_VALUE = "SPECIAL_VALUE"
    PRIVILEGE_INVERSION = "PRIVILEGE_INVERSION"
    SEQUENCE_STEP = "SEQUENCE_STEP"
    SYNTAX_ESCAPE = "SYNTAX_ESCAPE"


@dataclass
class CandidateMutation:
    category: MutationCategory
    label: str
    mutated_value: Any
    risk_rationale: str


class MutationGrammarEngine:
    """
    Generates grammar-driven mutation sets for a target parameter.
    """

    @classmethod
    def generate_mutations(cls, semantic_role: str, original_value: Any = None) -> List[CandidateMutation]:
        role_upper = semantic_role.upper()
        mutations: List[CandidateMutation] = []

        if "FINANCIAL" in role_upper:
            mutations.extend([
                CandidateMutation(MutationCategory.NEGATIVE_ARITHMETIC, "Negative Subtraction", -1, "Test if cart total or balance inverts negatively."),
                CandidateMutation(MutationCategory.NUMERIC_BOUNDARY, "Zero Fee", 0, "Test zero payment bypass or free order fulfillment."),
                CandidateMutation(MutationCategory.NUMERIC_BOUNDARY, "Fractional Precision", 0.000001, "Test rounding exploit in financial transactions."),
                CandidateMutation(MutationCategory.SPECIAL_VALUE, "32-bit Integer Overflow", 2147483648, "Test integer wrap-around vulnerability."),
                CandidateMutation(MutationCategory.TYPE_CONFUSION, "String Number Injection", "0.00", "Test parser type confusion bypass."),
            ])

        elif "IDENTITY" in role_upper:
            mutations.extend([
                CandidateMutation(MutationCategory.SEQUENCE_STEP, "Adjacent Object ID (+1)", 2 if original_value == 1 else 1, "Test sequential BOLA / IDOR access."),
                CandidateMutation(MutationCategory.SPECIAL_VALUE, "Null Object Reference", "null", "Test handling of null/anonymous identity binding."),
                CandidateMutation(MutationCategory.SYNTAX_ESCAPE, "SQL Quote Break", "1' OR '1'='1", "Test injection in identity lookup."),
                CandidateMutation(MutationCategory.TYPE_CONFUSION, "Array Wrapped ID", [1], "Test array parameter pollution on object reference."),
            ])

        elif "ROLE" in role_upper:
            mutations.extend([
                CandidateMutation(MutationCategory.PRIVILEGE_INVERSION, "Admin String Elevation", "admin", "Test mass assignment of administrator role."),
                CandidateMutation(MutationCategory.PRIVILEGE_INVERSION, "Boolean Truth Inversion", True, "Test truthy flag for privilege grant."),
                CandidateMutation(MutationCategory.PRIVILEGE_INVERSION, "Superuser Role", "SUPERUSER", "Test elevated system tier override."),
            ])

        elif "REDIRECT" in role_upper:
            mutations.extend([
                CandidateMutation(MutationCategory.SPECIAL_VALUE, "Protocol-Relative URL", "//evil-attacker.com", "Test scheme-agnostic open redirect."),
                CandidateMutation(MutationCategory.SYNTAX_ESCAPE, "CRLF Header Injection", "https://trusted.com%0d%0aSet-Cookie:malicious=1", "Test header injection in redirection."),
                CandidateMutation(MutationCategory.SPECIAL_VALUE, "Subdomain Reflection", "https://trusted.com.attacker.com", "Test regex domain boundary flaw."),
            ])

        else:
            mutations.extend([
                CandidateMutation(MutationCategory.SPECIAL_VALUE, "Empty String", "", "Test missing parameter behavior."),
                CandidateMutation(MutationCategory.SPECIAL_VALUE, "Null Value", None, "Test null dereference."),
            ])

        return mutations
