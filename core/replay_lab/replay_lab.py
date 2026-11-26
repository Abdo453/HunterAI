"""
HunterAI Replay Lab & Evidence Drift Engine
===========================================
Freezes findings into self-contained, parameterized JSON replay bundles:
data/replays/finding_<id>/
  - request.txt
  - response.txt
  - baseline.txt
  - metadata.json
  - replay_spec.json (parameterized JSON replay specification — never raw code interpolation)
  - replay.py        (standalone differential invariant runner)

Detects Evidence Drift via differential baseline vs probe verification:
- Original CONFIRMED vs Replay CONFIRMED -> Drift: NONE
- Original CONFIRMED vs Replay REJECTED  -> Drift: DETECTED (Target patched or flaky)
- Transport unavailable / timeout        -> UNAVAILABLE (never fabricated CONFIRMED)
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from core.evidence_court import CourtVerdict, EvidenceCourt, ProofPayload, ProofStrength

logger = logging.getLogger("hunter_ai.replay_lab")


def _extract_http_body(raw_http: str) -> str:
    """Return the body portion of a raw HTTP message (or raw text if no header delimiter)."""
    if not raw_http:
        return ""
    for sep in ("\r\n\r\n", "\n\n"):
        if sep in raw_http:
            return raw_http.split(sep, 1)[1]
    return raw_http


def _derive_baseline_url(target_url: str, parameter: str = "", benign_value: str = "baseline_safe") -> str:
    """Build a benign baseline URL by replacing the probed query parameter value."""
    parsed = urlparse(target_url)
    if not parsed.query:
        return target_url
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if parameter and parameter in qs:
        qs[parameter] = [benign_value]
    else:
        first_key = next(iter(qs.keys()), None)
        if first_key:
            qs[first_key] = [benign_value]
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))


def _build_standalone_replay_script(spec: Dict[str, Any]) -> str:
    """Build standalone replay.py using json.dumps parameterization (ZERO raw interpolation)."""
    encoded_spec = json.dumps(spec, indent=2, ensure_ascii=False)
    lines = [
        "#!/usr/bin/env python3",
        "# Standalone Parameterized Differential Replay Runner (HunterAI ReplayLab)",
        "from __future__ import annotations",
        "",
        "import hashlib",
        "import json",
        "import pathlib",
        "import sys",
        "import urllib.error",
        "import urllib.request",
        "from typing import Any, Callable, Dict, Optional",
        "",
        f"EMBEDDED_SPEC = json.loads({json.dumps(encoded_spec)})",
        "",
        "",
        "def load_spec(spec_path: Optional[str] = None) -> Dict[str, Any]:",
        "    if spec_path:",
        "        return json.loads(pathlib.Path(spec_path).read_text(encoding='utf-8'))",
        "    sibling = pathlib.Path(__file__).with_name('replay_spec.json')",
        "    if sibling.exists():",
        "        return json.loads(sibling.read_text(encoding='utf-8'))",
        "    return dict(EMBEDDED_SPEC)",
        "",
        "",
        "def _default_transport(req_spec: Dict[str, Any]) -> Dict[str, Any]:",
        "    method = str(req_spec.get('method', 'GET')).upper()",
        "    url = str(req_spec.get('url', ''))",
        "    headers = dict(req_spec.get('headers') or {})",
        "    headers.setdefault('User-Agent', 'HunterAI-Replay/3.0')",
        "    body = req_spec.get('body') or ''",
        "    data = body.encode('utf-8') if (body and method not in ('GET', 'HEAD')) else None",
        "    req = urllib.request.Request(url, data=data, headers=headers, method=method)",
        "    try:",
        "        with urllib.request.urlopen(req, timeout=10) as resp:",
        "            raw = resp.read().decode('utf-8', errors='replace')",
        "            return {'status_code': resp.status, 'headers': dict(resp.headers), 'body': raw}",
        "    except urllib.error.HTTPError as err:",
        "        raw = err.read().decode('utf-8', errors='replace')",
        "        return {'status_code': err.code, 'headers': dict(err.headers), 'body': raw}",
        "",
        "",
        "def run_differential_replay(",
        "    spec_path: Optional[str] = None,",
        "    transport: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,",
        ") -> Dict[str, Any]:",
        "    spec = load_spec(spec_path)",
        "    send = transport or _default_transport",
        "    try:",
        "        base_resp = send({",
        "            'method': spec.get('method', 'GET'),",
        "            'url': spec.get('baseline_url') or spec.get('target_url'),",
        "            'headers': spec.get('headers') or {},",
        "            'body': spec.get('baseline_body') or '',",
        "        })",
        "        probe_resp = send({",
        "            'method': spec.get('method', 'GET'),",
        "            'url': spec.get('target_url'),",
        "            'headers': spec.get('headers') or {},",
        "            'body': spec.get('body') or '',",
        "        })",
        "    except (OSError, TimeoutError, urllib.error.URLError) as exc:",
        "        return {'verdict': 'UNAVAILABLE', 'reproducible': False, 'error': str(exc)}",
        "    except Exception as exc:",
        "        return {'verdict': 'ERROR', 'reproducible': False, 'error': str(exc)}",
        "",
        "    base_body = str(base_resp.get('body') or '')",
        "    probe_body = str(probe_resp.get('body') or '')",
        "    probe_sha = hashlib.sha256(probe_body.encode('utf-8', errors='replace')).hexdigest()",
        "",
        "    try:",
        "        from core.evidence_court import CourtVerdict, EvidenceCourt, ProofPayload, ProofStrength",
        "        payload_obj = ProofPayload(",
        "            response_text=probe_body,",
        "            baseline_text=base_body,",
        "            artifact_type=str(spec.get('vuln_class') or ('token' if spec.get('expected_token') else '')),",
        "            probed_expression=str(spec.get('probed_expression') or spec.get('payload') or ''),",
        "            expected_result=str(spec.get('expected_result') or ''),",
        "            expected_token=str(spec.get('expected_token') or ''),",
        "            metadata={'status_code': probe_resp.get('status_code', 0), 'headers': probe_resp.get('headers', {})},",
        "        )",
        "        judgment = EvidenceCourt.adjudicate(",
        "            target_url=str(spec.get('target_url') or ''),",
        "            parameter=str(spec.get('parameter') or ''),",
        "            vuln_class=str(spec.get('vuln_class') or ''),",
        "            verifier_result={'reproduced': True, 'status_code': probe_resp.get('status_code', 0)},",
        "            proof_payload=payload_obj,",
        "            allow_declared_proof=False,",
        "        )",
        "        confirmed = judgment.verdict == CourtVerdict.CONFIRMED and judgment.proof_strength == ProofStrength.DERIVED.value",
        "        return {",
        "            'finding_id': spec.get('finding_id', ''),",
        "            'verdict': judgment.canonical_verdict.value,",
        "            'proof_strength': judgment.proof_strength,",
        "            'reproducible': confirmed,",
        "            'status_code': probe_resp.get('status_code', 0),",
        "            'response_sha256': probe_sha,",
        "            'rationale': judgment.adjudication_rationale,",
        "        }",
        "    except Exception:",
        "        token = str(spec.get('expected_token') or spec.get('expected_result') or '')",
        "        expr = str(spec.get('probed_expression') or '')",
        "        in_probe = bool(token) and (token in probe_body)",
        "        in_base = bool(token) and (token in base_body)",
        "        only_echo = bool(expr) and (expr in probe_body) and (token not in probe_body.replace(expr, ''))",
        "        confirmed = in_probe and (not in_base) and (not only_echo)",
        "        return {",
        "            'finding_id': spec.get('finding_id', ''),",
        "            'verdict': 'CONFIRMED' if confirmed else 'REJECTED',",
        "            'reproducible': confirmed,",
        "            'status_code': probe_resp.get('status_code', 0),",
        "            'response_sha256': probe_sha,",
        "        }",
        "",
        "",
        "if __name__ == '__main__':",
        "    arg_spec = sys.argv[1] if len(sys.argv) > 1 else None",
        "    outcome = run_differential_replay(arg_spec)",
        "    print(json.dumps(outcome, indent=2, ensure_ascii=False))",
        "    sys.exit(0 if outcome.get('reproducible') else 1)",
        "",
    ]
    return "\n".join(lines)


@dataclass
class ReplayDriftResult:
    finding_id: str
    original_verdict: str
    replay_verdict: str
    evidence_drift_detected: bool
    is_reproducible: bool
    drift_details: str = ""
    canonical_verdict: str = "UNVERIFIED"
    proof_strength: str = "NONE"
    timestamp: float = field(default_factory=time.time)

    def format_summary(self) -> str:
        status_icon = "OK" if not self.evidence_drift_detected else "DRIFT"
        return (
            f"[{status_icon}] [REPLAY LAB] Finding {self.finding_id}:\n"
            f"   - Original Verdict: {self.original_verdict}\n"
            f"   - Replay Verdict:   {self.replay_verdict}\n"
            f"   - Evidence Drift:   {'DETECTED' if self.evidence_drift_detected else 'NONE'}\n"
            f"   - Reproducible:     {'YES' if self.is_reproducible else 'NO'}"
        )


class ReplayLab:
    """Manages frozen parameterized replay bundles and differential replay verification."""

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir or (Path(__file__).resolve().parent.parent.parent / "data" / "replays")
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def freeze_finding(
        self,
        finding_id: str,
        target_url: str,
        method: str,
        parameter: str,
        payload: str,
        raw_request: str,
        raw_response: str,
        raw_baseline: str,
        verdict: str = "CONFIRMED",
        *,
        vuln_class: str = "",
        expected_token: str = "",
        probed_expression: str = "",
        expected_result: str = "",
        baseline_url: str = "",
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
        baseline_body: str = "",
    ) -> Path:
        """Freezes a finding into a permanent, parameterized JSON replay bundle."""
        bundle_dir = self.base_dir / f"finding_{finding_id}"
        bundle_dir.mkdir(parents=True, exist_ok=True)

        (bundle_dir / "request.txt").write_text(raw_request, encoding="utf-8")
        (bundle_dir / "response.txt").write_text(raw_response, encoding="utf-8")
        (bundle_dir / "baseline.txt").write_text(raw_baseline, encoding="utf-8")

        resp_body_only = _extract_http_body(raw_response)
        base_body_only = _extract_http_body(raw_baseline)
        resp_sha = hashlib.sha256(resp_body_only.encode("utf-8", errors="replace")).hexdigest()
        base_sha = hashlib.sha256(base_body_only.encode("utf-8", errors="replace")).hexdigest()

        spec: Dict[str, Any] = {
            "schema": "hunterai.replay_spec.v2",
            "finding_id": finding_id,
            "target_url": target_url,
            "baseline_url": baseline_url or _derive_baseline_url(target_url, parameter),
            "method": (method or "GET").upper(),
            "parameter": parameter,
            "payload": payload,
            "vuln_class": vuln_class,
            "expected_token": expected_token,
            "probed_expression": probed_expression,
            "expected_result": expected_result,
            "headers": dict(headers or {}),
            "body": body,
            "baseline_body": baseline_body,
            "original_verdict": verdict,
            "response_sha256": resp_sha,
            "baseline_sha256": base_sha,
            "frozen_at": time.time(),
        }

        (bundle_dir / "metadata.json").write_text(json.dumps(spec, indent=2, ensure_ascii=False), encoding="utf-8")
        (bundle_dir / "replay_spec.json").write_text(json.dumps(spec, indent=2, ensure_ascii=False), encoding="utf-8")
        (bundle_dir / "replay.py").write_text(_build_standalone_replay_script(spec), encoding="utf-8")
        return bundle_dir

    def evaluate_replay(
        self,
        finding_id: str,
        re_executed_response_body: str,
        expected_indicator: str,
        baseline_body: Optional[str] = None,
    ) -> ReplayDriftResult:
        """Evaluates replay execution against original verdict and baseline to detect drift."""
        bundle_dir = self.base_dir / f"finding_{finding_id}"
        meta_file = bundle_dir / "metadata.json"
        original_verdict = "CONFIRMED"
        meta: Dict[str, Any] = {}
        if meta_file.exists():
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
            original_verdict = meta.get("original_verdict", "CONFIRMED")

        if baseline_body is None and (bundle_dir / "baseline.txt").exists():
            baseline_body = _extract_http_body((bundle_dir / "baseline.txt").read_text(encoding="utf-8"))
        baseline_text = baseline_body or ""

        # Differential check: indicator must appear in replayed body AND be absent from baseline
        in_replayed = bool(expected_indicator) and (expected_indicator in re_executed_response_body)
        in_baseline = bool(expected_indicator) and (expected_indicator in baseline_text)

        if in_replayed and not in_baseline:
            replay_verdict = "CONFIRMED"
            proof_strength = ProofStrength.DERIVED.value
            details = "Target state matches original evidence and indicator is absent from baseline."
        elif in_baseline:
            replay_verdict = "REJECTED"
            proof_strength = ProofStrength.REFUTED.value
            details = "Expected indicator already present in baseline (not causally induced)."
        else:
            replay_verdict = "REJECTED"
            proof_strength = ProofStrength.REFUTED.value
            details = "Target state changed: expected indicator no longer reproduces."

        drift = original_verdict != replay_verdict
        return ReplayDriftResult(
            finding_id=finding_id,
            original_verdict=original_verdict,
            replay_verdict=replay_verdict,
            canonical_verdict=replay_verdict,
            proof_strength=proof_strength,
            evidence_drift_detected=drift,
            is_reproducible=(replay_verdict == "CONFIRMED"),
            drift_details=details,
        )

    def replay_against_target(
        self,
        finding_id: str,
        transport_fn: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
    ) -> ReplayDriftResult:
        """Execute a live (or hermetic injected-transport) differential HTTP replay for a frozen finding."""
        bundle_dir = self.base_dir / f"finding_{finding_id}"
        spec_file = bundle_dir / "replay_spec.json"
        if not spec_file.exists():
            spec_file = bundle_dir / "metadata.json"
        if not spec_file.exists():
            return ReplayDriftResult(
                finding_id=finding_id,
                original_verdict="UNKNOWN",
                replay_verdict="UNAVAILABLE",
                canonical_verdict=CourtVerdict.UNAVAILABLE.value,
                evidence_drift_detected=True,
                is_reproducible=False,
                drift_details=f"Replay spec not found for finding {finding_id}.",
            )

        spec = json.loads(spec_file.read_text(encoding="utf-8"))
        original_verdict = str(spec.get("original_verdict", "CONFIRMED"))

        def _live_httpx_transport(req_spec: Dict[str, Any]) -> Dict[str, Any]:
            import httpx
            with httpx.Client(timeout=10.0, verify=True, trust_env=False, follow_redirects=False) as client:
                r = client.request(
                    method=str(req_spec.get("method", "GET")).upper(),
                    url=str(req_spec.get("url", "")),
                    headers=dict(req_spec.get("headers") or {}),
                    content=(str(req_spec.get("body") or "").encode("utf-8") if req_spec.get("body") else None),
                )
                return {"status_code": r.status_code, "headers": dict(r.headers), "body": r.text}

        send = transport_fn or _live_httpx_transport
        try:
            base_resp = send({
                "method": spec.get("method", "GET"),
                "url": spec.get("baseline_url") or spec.get("target_url"),
                "headers": spec.get("headers") or {},
                "body": spec.get("baseline_body") or "",
            })
            probe_resp = send({
                "method": spec.get("method", "GET"),
                "url": spec.get("target_url"),
                "headers": spec.get("headers") or {},
                "body": spec.get("body") or "",
            })
        except (OSError, TimeoutError) as exc:
            return ReplayDriftResult(
                finding_id=finding_id,
                original_verdict=original_verdict,
                replay_verdict="UNAVAILABLE",
                canonical_verdict=CourtVerdict.UNAVAILABLE.value,
                evidence_drift_detected=True,
                is_reproducible=False,
                drift_details=f"Replay target unavailable: {exc}",
            )
        except Exception as exc:
            return ReplayDriftResult(
                finding_id=finding_id,
                original_verdict=original_verdict,
                replay_verdict="ERROR",
                canonical_verdict=CourtVerdict.ERROR.value,
                evidence_drift_detected=True,
                is_reproducible=False,
                drift_details=f"Replay execution error: {exc}",
            )

        base_body = str(base_resp.get("body") or "")
        probe_body = str(probe_resp.get("body") or "")
        proof_payload = ProofPayload(
            response_text=probe_body,
            baseline_text=base_body,
            artifact_type=str(spec.get("vuln_class") or ("token" if spec.get("expected_token") else "")),
            probed_expression=str(spec.get("probed_expression") or spec.get("payload") or ""),
            expected_result=str(spec.get("expected_result") or ""),
            expected_token=str(spec.get("expected_token") or ""),
            metadata={"status_code": probe_resp.get("status_code", 0), "headers": probe_resp.get("headers", {})},
        )
        judgment = EvidenceCourt.adjudicate(
            target_url=str(spec.get("target_url") or ""),
            parameter=str(spec.get("parameter") or ""),
            vuln_class=str(spec.get("vuln_class") or ""),
            verifier_result={"reproduced": True, "status_code": probe_resp.get("status_code", 0)},
            proof_payload=proof_payload,
            allow_declared_proof=False,
        )
        canon = judgment.canonical_verdict.value
        reproduced = (
            judgment.verdict == CourtVerdict.CONFIRMED
            and judgment.proof_strength == ProofStrength.DERIVED.value
        )
        return ReplayDriftResult(
            finding_id=finding_id,
            original_verdict=original_verdict,
            replay_verdict=canon,
            canonical_verdict=canon,
            proof_strength=judgment.proof_strength,
            evidence_drift_detected=(original_verdict != canon),
            is_reproducible=reproduced,
            drift_details=judgment.adjudication_rationale,
        )
