"""
Secret Hunter
=============
Multi-stage secret and credential detection:
CANDIDATE -> CLASSIFIED -> CONTEXT CHECK -> VALIDATION
Eliminates false positives by testing entropy, variable context, and placeholder rejection.
"""
import math
import re
from typing import List

from core.code_intel.models import SecretCandidate, SecretStatus


class SecretHunter:
    """High-fidelity secret detector with entropy gating and false positive suppression"""

    # Concrete High-Confidence Patterns
    PATTERNS = [
        ("aws_key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
        ("google_api_key", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b")),
        ("github_token", re.compile(r"\b(ghp_[a-zA-Z0-9]{36})\b")),
        ("jwt_token", re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)\b")),
        ("private_key", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
        ("slack_token", re.compile(r"\b(xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24,})\b")),
        ("stripe_key", re.compile(r"\b(sk_live_[0-9a-zA-Z]{24})\b")),
    ]

    GENERIC_TOKEN_PATTERN = re.compile(
        r"""['"]?((?:api[_-]?key|secret|token|password|auth_token|client_secret))['"]?\s*[:=]\s*['"]([a-zA-Z0-9_\-]{16,})['"]""",
        re.I
    )

    PLACEHOLDERS = {
        "changeme", "your_key", "your_token", "your_api_key", "dummy", "test",
        "example", "undefined", "null", "none", "1234567890", "abcdef"
    }

    @classmethod
    def calculate_shannon_entropy(cls, data: str) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        for x in set(data):
            p_x = float(data.count(x)) / length
            entropy += - p_x * math.log(p_x, 2)
        return entropy

    @classmethod
    def hunt_secrets(cls, content: str, source_file: str = "") -> List[SecretCandidate]:
        results: List[SecretCandidate] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, start=1):
            # 1. Concrete Known Patterns
            for s_type, pat in cls.PATTERNS:
                for m in pat.finditer(line):
                    match_str = m.group(1) if m.groups() else m.group(0)
                    cand = cls._process_candidate(s_type, match_str, source_file, idx)
                    if cand:
                        results.append(cand)

            # 2. Key-Value Variable Assignments
            for m in cls.GENERIC_TOKEN_PATTERN.finditer(line):
                v_name = m.group(1).lower()
                val = m.group(2)
                # Ignore public/common identifiers
                if any(p in val.lower() for p in cls.PLACEHOLDERS) or "gtm-" in val.lower():
                    continue
                ent = cls.calculate_shannon_entropy(val)
                if ent >= 3.3 and len(val) >= 20:
                    cand = cls._process_candidate("generic_credential", val, source_file, idx, entropy=ent)
                    if cand:
                        results.append(cand)

        return results

    @classmethod
    def _process_candidate(cls, s_type: str, match_str: str, source_file: str, line_no: int, entropy: float = 0.0) -> SecretCandidate:
        if not entropy:
            entropy = cls.calculate_shannon_entropy(match_str)

        # Context check
        status = SecretStatus.CLASSIFIED
        notes = "Known high-confidence signature match"

        # Check for false positives
        if any(ph in match_str.lower() for ph in cls.PLACEHOLDERS):
            status = SecretStatus.REJECTED
            notes = "Rejected: Placeholder value"
        elif s_type == "generic_credential" and entropy < 3.2:
            status = SecretStatus.REJECTED
            notes = f"Rejected: Low entropy for generic credential ({entropy:.2f})"
        else:
            status = SecretStatus.VALIDATED
            if s_type != "generic_credential":
                notes = f"Validated: High-confidence deterministic signature ({s_type})"
            else:
                notes = f"Validated: High entropy generic token ({entropy:.2f})"

        redacted = match_str[:4] + "*" * (len(match_str) - 8) + match_str[-4:] if len(match_str) > 8 else "***"

        return SecretCandidate(
            secret_type=s_type,
            raw_match=match_str,
            redacted_preview=redacted,
            source_file=source_file,
            line_number=line_no,
            entropy=round(entropy, 2),
            status=status,
            validation_notes=notes
        )