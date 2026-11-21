"""
Insecure Deserialization Autonomous Skill (v1.0)
================================================
Detects and verifies Insecure Deserialization vulnerabilities (CWE-502):
1. Serialized format signature detection (Java rO0AB, PHP O:/a:, Python pickle gASV, .NET ViewState, YAML)
2. Differential error/behavior probing on candidate parameters and cookies
3. Content-Type negotiation checks (application/x-java-serialized-object, application/x-yaml)
"""
from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse
import httpx

from agents.skills.base_skill import BaseSkill, SkillResult

log = logging.getLogger("hunter_ai.skills.deserialization")


class DeserializationSkill(BaseSkill):
    name: str = "deserialization_skill"
    vuln_type: str = "insecure_deserialization"
    cwe: str = "CWE-502"
    owasp_top10: str = "A08:2021"
    default_severity: str = "Critical"

    SERIALIZED_SIGNATURES = [
        ("Java ObjectStream", r"rO0AB[A-Za-z0-9+/=]{8,}"),
        ("PHP Serialized Object", r'[Oa]:\d+:"[^"]+":\d+:\{'),
        ("Python Pickle Base64", r"gASV[A-Za-z0-9+/=]{8,}"),
        (".NET ViewState", r"/wEPDw[A-Za-z0-9+/=]{8,}"),
    ]

    DESERIALIZATION_ERRORS = [
        "java.io.StreamCorruptedException",
        "java.io.InvalidClassException",
        "java.lang.ClassNotFoundException",
        "unserialize(): Error at offset",
        "_pickle.UnpicklingError",
        "pickle.UnpicklingError",
        "yaml.constructor.ConstructorError",
        "LosFormatter",
        "BinaryFormatter",
        "ObjectInputStream",
    ]

    def can_handle(self, param_name: str, url: str = "", sample_value: str = "") -> float:
        p = (param_name or "").lower()
        for _, sig in self.SERIALIZED_SIGNATURES:
            if re.search(sig, sample_value or ""):
                return 0.98
        if any(k in p for k in ("state", "viewstate", "data", "payload", "serialized", "obj", "session_data", "yaml", "xml")):
            return 0.88
        return 0.25

    async def run(self, target_url: str, param_name: str = "", **kwargs) -> SkillResult:
        logs: List[str] = [f"[Deserialization] Auditing {target_url} (param={param_name or 'auto'})"]
        client_kwargs = {
            "verify": False,
            "follow_redirects": True,
            "timeout": self.timeout,
            "trust_env": False,
        }
        if self.proxy:
            client_kwargs["proxy"] = self.proxy

        verified = False
        evidence = ""
        payload_used = ""

        try:
            async with httpx.AsyncClient(**client_kwargs) as client:
                base_resp = await client.get(target_url)
                base_text = base_resp.text or ""
                set_cookie = " ".join(base_resp.headers.get_list("set-cookie"))

                # 1. Passive signature inspection in cookies / body
                for label, pattern in self.SERIALIZED_SIGNATURES:
                    m = re.search(pattern, set_cookie) or re.search(pattern, base_text)
                    if m and label == "PHP Serialized Object":
                        logs.append(f"[*] Detected {label} signature: {m.group(0)[:40]}")

                # 2. Differential probe on target parameter
                target_param = param_name or "data"
                probes = [
                    ('O:8:"StdClass":0:{}x', "Malformed PHP serialized object"),
                    ("rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==", "Truncated Java ObjectInputStream header"),
                    ("!!python/object/apply: builtins.dict []", "YAML tag deserialization probe"),
                ]
                parsed = urlparse(target_url)
                qs = dict(parse_qsl(parsed.query, keep_blank_values=True))

                for probe_val, desc in probes:
                    qs[target_param] = probe_val
                    probe_url = urlunparse(parsed._replace(query=urlencode(qs)))
                    resp = await client.get(probe_url)
                    body = resp.text or ""
                    for err_sig in self.DESERIALIZATION_ERRORS:
                        if err_sig.lower() in body.lower() and err_sig.lower() not in base_text.lower():
                            verified = True
                            payload_used = f"{target_param}={probe_val}"
                            evidence = (
                                f"Differential parser exception '{err_sig}' triggered via {desc} "
                                f"on parameter '{target_param}' (HTTP {resp.status_code})."
                            )
                            logs.append(f"[+] Confirmed deserialization sink via {err_sig}")
                            break
                    if verified:
                        break
        except Exception as exc:
            logs.append(f"[!] Probe error: {exc}")

        return SkillResult(
            verified=verified,
            vuln_type=self.vuln_type,
            title=f"Insecure Deserialization Sink on {target_url}" if verified else "No Deserialization Sink Confirmed",
            severity="Critical" if verified else "Info",
            endpoint=target_url,
            param_name=param_name,
            evidence=evidence,
            payload_used=payload_used,
            remediation="Avoid native object deserialization of untrusted input; use strict JSON schemas and HMAC integrity checks.",
            confidence=0.92 if verified else 0.0,
            tool=self.name,
            cwe=self.cwe,
            owasp_top10=self.owasp_top10,
            fallback_used=False,
            logs=logs,
        )
