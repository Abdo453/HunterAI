"""
Proof-of-Execution (PoE) Engine
===============================
Deterministic engine that differentiates strictly between REFLECTION and EXECUTION:
1. Command Injection: Requires verified arithmetic calculation ($((53+19)) -> 72)
   and asserts the absence of the raw command syntax in the response.
2. SQL Injection: Requires extracted database banner/version or stable multi-probe differential.
3. Path Traversal / LFI: Validates exact system file signatures.
4. XSS: Validates unencoded execution context in HTML/DOM.
"""
import re
from typing import Dict, Any, Tuple


class ProofOfExecutionEngine:
    """Evaluates whether an observed HTTP response constitutes execution proof or mere reflection"""

    @classmethod
    def verify_command_injection(
        cls,
        response_text: str,
        expected_arithmetic_result: str = "72",
        probed_expression: str = "53+19"
    ) -> Tuple[bool, str]:
        """
        Inviolable Command Injection Rule:
        Must find expected result (e.g. 72) WITHOUT the command syntax or literal expression echoing.
        """
        if not response_text:
            return False, "Empty response"

        # 1. Reflection Check: If the command syntax or arithmetic expression echoes, it is reflection!
        syntax_echo = (
            f"$(({probed_expression}))" in response_text or
            f"expr {probed_expression}" in response_text or
            f"; echo " in response_text or
            f"__PTST_CMD" in response_text
        )
        if syntax_echo:
            return False, f"Literal command syntax echo detected (Reflection != Execution)"

        # Check for Next.js / JSON script reflection
        json_script_pat = r'["\']?[a-zA-Z0-9_]+["\']?\s*:\s*["\'][^"\']*' + re.escape(probed_expression)
        if re.search(json_script_pat, response_text):
            return False, "JSON / Script parameter reflection detected"

        # 2. Arithmetic Result Check
        # Result must appear as an isolated token or output word
        if re.search(rf"(?:^|\s|>|\b){re.escape(expected_arithmetic_result)}(?:$|\s|<|\b)", response_text):
            return True, f"Arithmetic execution confirmed: evaluated {probed_expression} to {expected_arithmetic_result}."

        return False, f"Expected arithmetic result '{expected_arithmetic_result}' not found in response."

    @classmethod
    def verify_sqli_extraction(cls, response_text: str) -> Tuple[bool, str, str]:
        """
        Validates database extraction proof (banner, DBMS version, table schema).
        Returns: (verified, dbms_type, proof_detail)
        """
        if not response_text:
            return False, "unknown", "Empty response"

        # Postgres version signature
        m_pg = re.search(r"(PostgreSQL\s+\d+\.\d+[\w\.\s,-]+)", response_text, re.I)
        if m_pg:
            return True, "postgresql", m_pg.group(1).strip()

        # MySQL / MariaDB version signature
        m_my = re.search(r"(\d+\.\d+\.\d+-(?:MariaDB|community)[\w\.\s,-]*)", response_text, re.I)
        if m_my:
            return True, "mysql", m_my.group(1).strip()

        # SQLite version signature
        m_sq = re.search(r"(3\.\d+\.\d+)", response_text)
        if m_sq and "sqlite" in response_text.lower():
            return True, "sqlite", f"SQLite version {m_sq.group(1)}"

        return False, "unknown", "No database version banner extracted."

    @classmethod
    def verify_lfi_extraction(cls, response_text: str) -> Tuple[bool, str]:
        """Validates LFI proof against known system files"""
        if not response_text:
            return False, "Empty response"

        if re.search(r"root:x:0:0:[^:]*:/root:", response_text):
            return True, "Linux /etc/passwd user entry confirmed."

        if "[boot loader]" in response_text.lower() or "[extensions]" in response_text.lower():
            return True, "Windows ini system configuration confirmed."

        return False, "No recognized OS file format detected in response."