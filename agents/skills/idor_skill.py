"""
IDOR & BOLA Autonomous Skill (v2.0) — Broken Object Level Authorization Engine
==============================================================================
Autonomous assessment for Insecure Direct Object References and Authorization
Bypasses via Multi-Identity Differential Testing, Verb Tampering, and ID Matrix.

State Machine:
  IDENTIFY_REFS -> CLASSIFY_ENCODING -> GENERATE_CANDIDATES -> TEST_UNAUTH
  -> TEST_CROSS_TENANT -> TEST_VERB_TAMPER -> EVALUATE_ACCESS -> COMPLETE | FAILED
"""

import re
import json
import time
import base64
import hashlib
import logging
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Set
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

log = logging.getLogger("idor_skill")


class IDORState(Enum):
    IDENTIFY_REFS       = auto()
    CLASSIFY_ENCODING   = auto()
    GENERATE_CANDIDATES = auto()
    TEST_UNAUTH         = auto()
    TEST_CROSS_TENANT   = auto()
    TEST_VERB_TAMPER    = auto()
    EVALUATE_ACCESS     = auto()
    COMPLETE            = auto()
    FAILED              = auto()


class IDType(Enum):
    NUMERIC_SEQUENTIAL = "numeric_sequential"
    UUID_V4            = "uuid_v4"
    BASE64_ENCODED     = "base64_encoded"
    HEX_HASH           = "hex_hash"
    ALPHANUMERIC       = "alphanumeric"
    UNKNOWN            = "unknown"


@dataclass
class IDORContext:
    target_url: str
    param_name: str
    original_value: str = ""
    proxy: Optional[str] = None
    state: IDORState = IDORState.IDENTIFY_REFS
    id_type: IDType = IDType.UNKNOWN
    vulnerable_id: str = ""
    vulnerable_verb: str = "GET"
    leak_evidence: str = ""
    confidence: float = 0.0
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    logs: List[str] = field(default_factory=list)

    def log(self, msg: str):
        log.info(msg)
        self.logs.append(msg)


# ─────────────────────────────────────────────────────────────────────────────
# ID Classifier & Permutation Generator
# ─────────────────────────────────────────────────────────────────────────────

class IDPermutator:
    """Generates adjacent and edge-case identifier permutations"""

    @classmethod
    def classify(cls, val_str: str) -> Tuple[IDType, Any]:
        val = str(val_str).strip()
        # 1. Numeric
        if val.isdigit():
            return IDType.NUMERIC_SEQUENTIAL, int(val)
        # 2. UUID
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', val, re.I):
            return IDType.UUID_V4, val
        # 3. Base64 encoded
        if len(val) >= 4 and len(val) % 4 == 0 and re.match(r'^[A-Za-z0-9+/=]+$', val):
            try:
                decoded = base64.b64decode(val).decode('utf-8', errors='ignore')
                if len(decoded) > 1 and any(c.isalnum() for c in decoded):
                    return IDType.BASE64_ENCODED, decoded
            except Exception:
                pass
        # 4. Hex hash (MD5 / SHA1 / SHA256)
        if re.match(r'^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$', val, re.I):
            return IDType.HEX_HASH, val

        return IDType.ALPHANUMERIC, val

    @classmethod
    def generate_permutations(cls, val_str: str) -> List[str]:
        id_type, meta = cls.classify(val_str)
        candidates = []

        if id_type == IDType.NUMERIC_SEQUENTIAL:
            num = meta
            # Adjacent IDs
            if num > 1:
                candidates.extend([str(num - 1), str(num + 1), str(num - 2), str(num + 2)])
            else:
                candidates.extend(["2", "3", "4", "100", "1000"])
            # Boundary IDs
            candidates.extend(["1", "0", "-1", "999999"])

        elif id_type == IDType.BASE64_ENCODED:
            decoded = meta
            if decoded.isdigit():
                d_num = int(decoded)
                for adj in [d_num - 1, d_num + 1, 1, 0]:
                    candidates.append(base64.b64encode(str(adj).encode()).decode())
            else:
                # Try generic base64 permutations
                for test_txt in ["1", "admin", "guest", "0"]:
                    candidates.append(base64.b64encode(test_txt.encode()).decode())

        elif id_type == IDType.ALPHANUMERIC:
            candidates.extend(["1", "admin", "test", "root", "guest", "0", "user1", "user2"])

        return [c for c in candidates if c != val_str]


# ─────────────────────────────────────────────────────────────────────────────
# IDOR Autonomous Skill Orchestrator
# ─────────────────────────────────────────────────────────────────────────────

class IDORSkill:
    """
    Autonomous IDOR/BOLA Assessment Engine:
    Tests parameter mutations against authorization barriers, verifies
    cross-object data leaks, and attempts HTTP verb tampering.
    """

    def __init__(self, proxy: Optional[str] = None):
        self.proxy = proxy

    async def run(
        self,
        target_url: str,
        param_name: str,
        auth_headers_a: Optional[Dict[str, str]] = None,
        auth_headers_b: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        ctx = IDORContext(target_url=target_url, param_name=param_name, proxy=self.proxy)
        ctx.log(f"[IDORSkill] Starting BOLA/IDOR analysis on parameter={param_name!r}")

        parsed = urlparse(target_url)
        base_qs = parse_qs(parsed.query)
        orig_val = base_qs.get(param_name, ["1"])[0]
        ctx.original_value = orig_val

        client_kwargs = {"verify": False, "follow_redirects": True, "timeout": 8.0}
        if self.proxy:
            import httpx as _hx
            ver = tuple(int(x) for x in _hx.__version__.split(".")[:2])
            if ver >= (0, 28):
                client_kwargs["proxy"] = self.proxy
            else:
                client_kwargs["proxies"] = {"http://": self.proxy, "https://": self.proxy}

        async with httpx.AsyncClient(**client_kwargs) as client:
            # ── 1. Baseline with Original ID ──────────────────────────────────
            try:
                r_base = await client.get(target_url, headers=auth_headers_a)
                base_len = len(r_base.text)
                base_status = r_base.status_code
            except Exception as e:
                ctx.log(f"[IDORSkill] Baseline failed: {e}")
                ctx.state = IDORState.FAILED
                return self._build_result(ctx)

            # ── 2. Permutation Generation ────────────────────────────────────
            ctx.state = IDORState.GENERATE_CANDIDATES
            id_type, _ = IDPermutator.classify(orig_val)
            ctx.id_type = id_type
            candidates = IDPermutator.generate_permutations(orig_val)
            ctx.log(f"[STATE] -> GENERATE_CANDIDATES: Classified as {id_type.value} with {len(candidates)} candidates")

            # ── 3. Test Unauthenticated Access with Altered IDs ──────────────
            ctx.state = IDORState.TEST_UNAUTH
            for cand in candidates[:4]:
                qs = {k: v[0] for k, v in base_qs.items()}
                qs[param_name] = cand
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', urlencode(qs), ''))
                try:
                    r_unauth = await client.get(test_url)
                    # If unauthenticated access returns 200 with substantial distinct data
                    if r_unauth.status_code == 200 and len(r_unauth.text) > 80:
                        # Ensure it's not a generic 200 error page or empty list
                        if abs(len(r_unauth.text) - base_len) > 20 and "login" not in r_unauth.text.lower():
                            ctx.vulnerable_id = cand
                            ctx.confidence = 0.92
                            ctx.leak_evidence = r_unauth.text[:250]
                            ctx.evidence.append({
                                "type": "unauthenticated_object_access",
                                "original_id": orig_val,
                                "tested_id": cand,
                                "status": r_unauth.status_code,
                                "length": len(r_unauth.text)
                            })
                            ctx.log(f"[TEST_UNAUTH] ✅ Unauthenticated object access confirmed for ID={cand!r}")
                            ctx.state = IDORState.COMPLETE
                            return self._build_result(ctx)
                except Exception:
                    continue

            # ── 4. Test Cross-Tenant Matrix (if Tenant B headers provided) ───
            if auth_headers_b:
                ctx.state = IDORState.TEST_CROSS_TENANT
                ctx.log("[STATE] -> TEST_CROSS_TENANT: Testing cross-tenant boundary")
                try:
                    # Tenant B requests Tenant A's object
                    r_cross = await client.get(target_url, headers=auth_headers_b)
                    if r_cross.status_code == 200 and abs(len(r_cross.text) - base_len) < 50:
                        ctx.vulnerable_id = orig_val
                        ctx.confidence = 0.95
                        ctx.leak_evidence = r_cross.text[:250]
                        ctx.evidence.append({
                            "type": "cross_tenant_access",
                            "accessed_id": orig_val,
                            "accessor": "Tenant B Context",
                            "status": r_cross.status_code
                        })
                        ctx.log(f"[TEST_CROSS_TENANT] ✅ Cross-tenant authorization bypass confirmed!")
                        ctx.state = IDORState.COMPLETE
                        return self._build_result(ctx)
                except Exception:
                    pass

            # ── 5. Test HTTP Verb Tampering ──────────────────────────────────
            ctx.state = IDORState.TEST_VERB_TAMPER
            for alt_verb in ["POST", "PUT", "PATCH", "OPTIONS"]:
                try:
                    r_verb = await client.request(alt_verb, target_url, headers=auth_headers_a)
                    if r_verb.status_code in (200, 201, 204) and r_verb.status_code != base_status:
                        ctx.log(f"[TEST_VERB_TAMPER] Alternative verb {alt_verb} accepted (status={r_verb.status_code})")
                        ctx.vulnerable_verb = alt_verb
                        ctx.evidence.append({
                            "type": "verb_tampering_bypass",
                            "verb": alt_verb,
                            "status": r_verb.status_code
                        })
                except Exception:
                    continue

            ctx.state = IDORState.FAILED
            ctx.log("[IDORSkill] No IDOR/BOLA vulnerability verified.")
            return self._build_result(ctx)

    def _build_result(self, ctx: IDORContext) -> Dict[str, Any]:
        is_success = (ctx.state == IDORState.COMPLETE)
        return {
            "state": ctx.state.name,
            "objective_met": is_success,
            "id_type": ctx.id_type.value,
            "original_id": ctx.original_value,
            "vulnerable_id": ctx.vulnerable_id,
            "vulnerable_verb": ctx.vulnerable_verb,
            "confidence": ctx.confidence,
            "evidence_snippet": ctx.leak_evidence,
            "evidence": ctx.evidence,
            "logs": ctx.logs
        }


async def run_idor_skill(target_url: str, param_name: str, proxy: Optional[str] = None) -> Dict[str, Any]:
    skill = IDORSkill(proxy=proxy)
    return await skill.run(target_url, param_name)
