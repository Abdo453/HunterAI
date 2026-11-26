"""
HunterAI Verifier — Independent Differential HTTP Re-Verification Gate
======================================================================
Independently re-derives a finding from its PoC bundle via real differential
HTTP replay (with injectable ``transport`` for hermetic tests) before reporting.

Truthfulness Guarantees:
- Never verifies via static local file-grep ``len(response_text) > 0``.
- Fixes ``original_sha256`` vs ``current_sha256`` body-vs-file mismatch by
  hashing ONLY the HTTP response body (matching ``PocBundler.capture``).
- Enforces safe HTTP methods: refuses PUT/DELETE/PATCH without ``confirm_unsafe=True``.
- Executes differential baseline + probe HTTP replay and delegates final proof
  validation to canonical ``core.evidence_court.EvidenceCourt.adjudicate``.
- PROVEN only if BOTH original captured response body AND live replayed body
  satisfy canonical ``CourtVerdict.CONFIRMED`` with ``ProofStrength.DERIVED``
  against the baseline!
"""
from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from core.evidence_court import (
    CourtVerdict,
    EvidenceCourt,
    ProofPayload,
    ProofStrength,
)

UNSAFE_METHODS = frozenset({"PUT", "DELETE", "PATCH"})


def _extract_http_body(raw_http: str) -> str:
    """Return ONLY the HTTP message body (stripping status/request line and headers)."""
    if not raw_http:
        return ""
    for sep in ("\r\n\r\n", "\n\n"):
        if sep in raw_http:
            return raw_http.split(sep, 1)[1]
    return raw_http


def _parse_http_request_file(raw_request: str, manifest: Dict[str, Any], bundle_dir: Path) -> Dict[str, Any]:
    """Parse ``request.http`` (with ``evidence.har`` fallback) into method, url, headers, body."""
    method = "GET"
    url = ""
    host = ""
    headers: Dict[str, str] = {}
    body = ""

    sep = "\r\n\r\n" if "\r\n\r\n" in raw_request else ("\n\n" if "\n\n" in raw_request else None)
    head_part = raw_request.split(sep, 1)[0] if sep else raw_request
    body = raw_request.split(sep, 1)[1] if sep else ""
    lines = [ln.strip("\r") for ln in head_part.splitlines() if ln.strip()]

    req_path = "/"
    if lines:
        parts = lines[0].split()
        if len(parts) >= 2:
            method = parts[0].upper()
            req_path = parts[1]
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                k_clean = k.strip()
                v_clean = v.strip()
                if k_clean.lower() == "host":
                    host = v_clean
                elif k_clean.lower() != "content-length":
                    headers[k_clean] = v_clean

    # Resolve full URL
    if req_path.startswith(("http://", "https://")):
        url = req_path
    else:
        har_path = bundle_dir / "evidence.har"
        if har_path.exists():
            try:
                har = json.loads(har_path.read_text(encoding="utf-8"))
                har_url = har.get("log", {}).get("entries", [{}])[0].get("request", {}).get("url", "")
                if har_url.startswith(("http://", "https://")):
                    url = har_url
            except Exception:
                pass
        if not url:
            target = str(manifest.get("target") or host or "").strip()
            if target.startswith(("http://", "https://")):
                url = urljoin(target.rstrip("/") + "/", req_path.lstrip("/"))
            elif target:
                scheme = "http" if target.startswith(("127.0.0.1", "localhost")) else "https"
                url = f"{scheme}://{target}/{req_path.lstrip('/')}"

    return {"method": method, "url": url, "host": host, "headers": headers, "body": body}


def _derive_baseline_request(req: Dict[str, Any], manifest: Dict[str, Any]) -> Dict[str, Any]:
    """Construct a benign baseline request from the captured probe request."""
    base_url = str(manifest.get("baseline_url") or "").strip()
    if not base_url:
        parsed = urlparse(req.get("url", ""))
        if parsed.query:
            qs = parse_qs(parsed.query, keep_blank_values=True)
            param = str(manifest.get("parameter") or "")
            if param and param in qs:
                qs[param] = ["baseline_safe"]
            else:
                first_key = next(iter(qs.keys()), None)
                if first_key:
                    qs[first_key] = ["baseline_safe"]
            base_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
        else:
            base_url = req.get("url", "")

    return {
        "method": req.get("method", "GET"),
        "url": base_url,
        "headers": dict(req.get("headers") or {}),
        "body": str(manifest.get("baseline_body") or ""),
    }


def _default_http_transport(req: Dict[str, Any], timeout: float = 10.0) -> Dict[str, Any]:
    """Live HTTP replay transport using httpx with verify=True and trust_env=False."""
    import httpx

    method = str(req.get("method", "GET")).upper()
    url = str(req.get("url", ""))
    headers = dict(req.get("headers") or {})
    body = str(req.get("body") or "")
    with httpx.Client(timeout=timeout, verify=True, trust_env=False, follow_redirects=False) as client:
        resp = client.request(
            method=method,
            url=url,
            headers=headers,
            content=(body.encode("utf-8") if body and method not in ("GET", "HEAD") else None),
        )
        return {
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text,
        }


class Verifier:
    def __init__(
        self,
        require_proof: bool = False,
        transport: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        confirm_unsafe: bool = False,
        timeout: float = 10.0,
    ):
        self.require_proof = require_proof
        self.transport = transport
        self.confirm_unsafe = confirm_unsafe
        self.timeout = timeout

    def _build_proof_payload(
        self,
        response_body: str,
        baseline_body: str,
        manifest: Dict[str, Any],
        status_code: int = 200,
        headers: Optional[Dict[str, Any]] = None,
    ) -> Optional[ProofPayload]:
        vuln_class = str(manifest.get("vuln_class") or "")
        expected_token = str(manifest.get("expected_token") or "")
        probed_expr = str(manifest.get("probed_expression") or "")
        expected_result = str(manifest.get("expected_result") or "")

        if expected_token or expected_result or vuln_class:
            return ProofPayload(
                response_text=response_body,
                baseline_text=baseline_body,
                artifact_type=vuln_class or ("token" if expected_token else ""),
                probed_expression=probed_expr or ("53+19" if "cmd" in vuln_class.lower() or "rce" in vuln_class.lower() else ""),
                expected_result=expected_result or ("72" if "cmd" in vuln_class.lower() or "rce" in vuln_class.lower() else ""),
                expected_token=expected_token,
                metadata={
                    "status_code": status_code,
                    "headers": dict(headers or {}),
                    **(manifest.get("proof_metadata") or {}),
                },
            )
        return ProofPayload.from_vuln_evidence(vuln_class, response_body)

    def check(
        self,
        bundle_dir: str,
        transport: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        confirm_unsafe: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Independently re-verify a bundle via differential HTTP replay + canonical EvidenceCourt."""
        bundle = Path(bundle_dir)
        manifest = json.loads((bundle / "bundle.json").read_text(encoding="utf-8"))
        saved_response_http = (bundle / "response.http").read_text(encoding="utf-8")
        request_http = (bundle / "request.http").read_text(encoding="utf-8")

        # 1. Integrity check on captured HTTP BODY ONLY (matches PocBundler's sha256(resp_body))
        saved_body = _extract_http_body(saved_response_http)
        original_sha = str(manifest.get("response_sha256", ""))
        saved_body_sha = hashlib.sha256(saved_body.encode("utf-8")).hexdigest()
        saved_sha_match = bool(original_sha) and (original_sha == saved_body_sha)

        parsed_req = _parse_http_request_file(request_http, manifest, bundle)
        method = parsed_req["method"]
        allow_unsafe = self.confirm_unsafe if confirm_unsafe is None else confirm_unsafe

        if method in UNSAFE_METHODS and not allow_unsafe:
            return self._finalize(
                bundle=bundle,
                manifest=manifest,
                verdict="UNPROVEN",
                canonical_verdict=CourtVerdict.UNAVAILABLE.value,
                rationale=f"Unsafe HTTP method {method} refused without confirm_unsafe=True.",
                original_sha=original_sha,
                saved_body_sha=saved_body_sha,
                current_sha="",
                saved_sha_match=saved_sha_match,
                proof_strength=ProofStrength.NONE.value,
                replay_status_code=0,
            )

        if not parsed_req.get("url"):
            return self._finalize(
                bundle=bundle,
                manifest=manifest,
                verdict="UNPROVEN",
                canonical_verdict=CourtVerdict.UNAVAILABLE.value,
                rationale="Cannot replay bundle: request URL missing from request.http and manifest.",
                original_sha=original_sha,
                saved_body_sha=saved_body_sha,
                current_sha="",
                saved_sha_match=saved_sha_match,
                proof_strength=ProofStrength.NONE.value,
                replay_status_code=0,
            )

        # 2. Live or hermetic injected-transport differential HTTP replay (Baseline + Probe)
        send_fn = transport or self.transport or (lambda r: _default_http_transport(r, timeout=self.timeout))
        baseline_req = _derive_baseline_request(parsed_req, manifest)

        try:
            baseline_resp = send_fn(baseline_req)
            probe_resp = send_fn(parsed_req)
        except (OSError, TimeoutError) as exc:
            return self._finalize(
                bundle=bundle,
                manifest=manifest,
                verdict="UNPROVEN",
                canonical_verdict=CourtVerdict.UNAVAILABLE.value,
                rationale=f"Target unavailable during live replay: {exc}",
                original_sha=original_sha,
                saved_body_sha=saved_body_sha,
                current_sha="",
                saved_sha_match=saved_sha_match,
                proof_strength=ProofStrength.NONE.value,
                replay_status_code=0,
            )
        except Exception as exc:
            return self._finalize(
                bundle=bundle,
                manifest=manifest,
                verdict="INCONCLUSIVE",
                canonical_verdict=CourtVerdict.ERROR.value,
                rationale=f"Runtime error during live replay: {exc}",
                original_sha=original_sha,
                saved_body_sha=saved_body_sha,
                current_sha="",
                saved_sha_match=saved_sha_match,
                proof_strength=ProofStrength.NONE.value,
                replay_status_code=0,
            )

        live_baseline_body = str(baseline_resp.get("body") or "")
        live_probe_body = str(probe_resp.get("body") or "")
        live_status = int(probe_resp.get("status_code") or 0)
        live_headers = dict(probe_resp.get("headers") or {})
        current_sha = hashlib.sha256(live_probe_body.encode("utf-8")).hexdigest()

        # 3. Verify BOTH original captured body AND live replayed body via canonical EvidenceCourt
        orig_payload = self._build_proof_payload(saved_body, live_baseline_body, manifest, status_code=200)
        orig_judgment = EvidenceCourt.adjudicate(
            target_url=parsed_req["url"],
            parameter=str(manifest.get("parameter") or ""),
            vuln_class=str(manifest.get("vuln_class") or ""),
            verifier_result={"reproduced": True, "status_code": 200},
            proof_payload=orig_payload,
            allow_declared_proof=False,
        )

        replay_payload = self._build_proof_payload(
            live_probe_body, live_baseline_body, manifest, status_code=live_status, headers=live_headers
        )
        replay_judgment = EvidenceCourt.adjudicate(
            target_url=parsed_req["url"],
            parameter=str(manifest.get("parameter") or ""),
            vuln_class=str(manifest.get("vuln_class") or ""),
            verifier_result={"reproduced": live_status > 0, "status_code": live_status},
            proof_payload=replay_payload,
            allow_declared_proof=False,
        )

        orig_confirmed = (
            orig_judgment.verdict == CourtVerdict.CONFIRMED
            and orig_judgment.proof_strength == ProofStrength.DERIVED.value
        )
        replay_confirmed = (
            replay_judgment.verdict == CourtVerdict.CONFIRMED
            and replay_judgment.proof_strength == ProofStrength.DERIVED.value
        )

        if orig_confirmed and replay_confirmed:
            verdict = "PROVEN"
            canon = CourtVerdict.CONFIRMED.value
            rationale = f"Original and live differential replay both CONFIRMED (DERIVED): {replay_judgment.proof_detail}"
        elif live_status <= 0:
            verdict = "UNPROVEN"
            canon = CourtVerdict.UNAVAILABLE.value
            rationale = "Target unreachable during differential replay (HTTP status 0)."
        elif not orig_confirmed:
            verdict = "REFUTED"
            canon = CourtVerdict.REJECTED.value
            rationale = f"Original bundle evidence failed canonical ProofContract: {orig_judgment.adjudication_rationale}"
        elif replay_judgment.canonical_verdict == CourtVerdict.REJECTED:
            verdict = "REFUTED"
            canon = CourtVerdict.REJECTED.value
            rationale = f"Live differential replay REFUTED finding (target patched or false positive): {replay_judgment.adjudication_rationale}"
        else:
            verdict = "UNPROVEN"
            canon = replay_judgment.canonical_verdict.value
            rationale = f"Live replay did not confirm proof: {replay_judgment.adjudication_rationale}"

        return self._finalize(
            bundle=bundle,
            manifest=manifest,
            verdict=verdict,
            canonical_verdict=canon,
            rationale=rationale,
            original_sha=original_sha,
            saved_body_sha=saved_body_sha,
            current_sha=current_sha,
            saved_sha_match=saved_sha_match,
            proof_strength=replay_judgment.proof_strength,
            replay_status_code=live_status,
        )

    def _finalize(
        self,
        *,
        bundle: Path,
        manifest: Dict[str, Any],
        verdict: str,
        canonical_verdict: str,
        rationale: str,
        original_sha: str,
        saved_body_sha: str,
        current_sha: str,
        saved_sha_match: bool,
        proof_strength: str,
        replay_status_code: int,
    ) -> Dict[str, Any]:
        result = {
            "bundle_id": manifest.get("bundle_id", ""),
            "target": manifest.get("target", ""),
            "vuln_class": manifest.get("vuln_class", ""),
            "verdict": verdict,
            "canonical_verdict": canonical_verdict,
            "proof_strength": proof_strength,
            "rationale": rationale,
            "original_sha256": original_sha,
            "saved_body_sha256": saved_body_sha,
            "current_sha256": current_sha,
            "saved_sha_match": saved_sha_match,
            "sha_match": bool(original_sha) and (original_sha == current_sha),
            "replay_status_code": replay_status_code,
            "verified_at": self._timestamp(),
        }

        (bundle / "verification.json").write_text(
            json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8"
        )

        if self.require_proof and verdict != "PROVEN":
            sys.exit(1)

        return result

    def sweep(self, root: str = "findings") -> Dict[str, Any]:
        """Re-verify all bundles under root."""
        root_path = Path(root)
        results = []
        proven = 0
        refuted = 0
        unproven = 0

        for bundle_dir in root_path.rglob("*/evidence/*/"):
            if (bundle_dir / "bundle.json").exists():
                r = self.check(str(bundle_dir))
                results.append(r)
                if r["verdict"] == "PROVEN":
                    proven += 1
                elif r["verdict"] == "REFUTED":
                    refuted += 1
                else:
                    unproven += 1

        return {
            "total": len(results),
            "proven": proven,
            "refuted": refuted,
            "unproven": unproven,
            "results": results,
        }

    @staticmethod
    def _timestamp() -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ")


def main() -> None:
    import argparse

    p = argparse.ArgumentParser(prog="verifier")
    sub = p.add_subparsers(dest="command")

    sp = sub.add_parser("check")
    sp.add_argument("bundle_dir")
    sp.add_argument("--require-proof", action="store_true")
    sp.add_argument("--confirm-unsafe", action="store_true")

    sp = sub.add_parser("sweep")
    sp.add_argument("root", nargs="?", default="findings")
    sp.add_argument("--confirm-unsafe", action="store_true")

    args = p.parse_args()
    verifier = Verifier(
        require_proof=getattr(args, "require_proof", False),
        confirm_unsafe=getattr(args, "confirm_unsafe", False),
    )

    if args.command == "check":
        verifier.check(args.bundle_dir)
    elif args.command == "sweep":
        verifier.sweep(args.root)


if __name__ == "__main__":
    main()
