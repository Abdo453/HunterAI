"""Asynchronous native HTTP/DNS/CT recon and verification scanner for Django Hub runs.

Works cleanly without mandatory external CLI binaries (subfinder/httpx/nuclei)
while still performing genuine DNS resolution, passive CT log lookups,
live HTTP/HTTPS probing, HTML endpoint/form discovery, security header/cookie/CORS
audits, sensitive file checks, and non-destructive query-parameter probes.
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import ipaddress
import logging
import re
import socket
import ssl
import time
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import httpx

logger = logging.getLogger("hunter_ai.live_scanner")

_TITLE_RE = re.compile(r"(?is)<title[^>]*>(.*?)</title>")
_ATTR_LINK_RE = re.compile(r"""(?is)(?:href|src|action)\s*=\s*["']([^"'#\s>]+)["']""")
_FORM_RE = re.compile(r"(?is)<form\b([^>]*)>(.*?)</form>")
_INPUT_NAME_RE = re.compile(r"""(?is)<input\b[^>]*\bname\s*=\s*["']([^"']+)["']""")
_FORM_ACTION_RE = re.compile(r"""(?is)\baction\s*=\s*["']([^"']*)["']""")
_FORM_METHOD_RE = re.compile(r"""(?is)\bmethod\s*=\s*["']([^"']*)["']""")
_VERSION_RE = re.compile(r"[A-Za-z0-9_-]+/\d+\.\d+(?:\.\d+)?")

_SQL_ERROR_SIGS = (
    "sql syntax",
    "sqlite",
    "syntax error near",
    "unclosed quotation mark",
    "pg_query",
    "postgresql",
    "mysql_fetch",
    "ora-0",
    "odbc driver",
    "sqlstate[",
)

_COMMON_SUBS = ("www", "api", "app", "admin", "portal", "mail", "dev", "staging", "auth")


def normalize_target_spec(raw_target: str) -> Dict[str, Any]:
    """Parse bare domain, host:port, IP, or http/https URL into scan parameters."""
    trimmed = (raw_target or "").strip()
    if not trimmed:
        return {"raw": "", "domain": "", "host_port": "", "root_url": "", "seed_urls": [], "is_local_or_test": True}

    seed_urls: List[str] = []
    domain = ""
    host_port = ""
    root_url = ""

    if "://" in trimmed:
        parsed = urlparse(trimmed)
        if parsed.netloc:
            domain = (parsed.hostname or "").strip(".").lower()
            host_port = parsed.netloc.strip(".").lower()
            scheme = parsed.scheme.lower()
            root_url = f"{scheme}://{host_port}"
            if parsed.path not in ("", "/") or parsed.query:
                seed_urls.append(trimmed)
            seed_urls.append(root_url)

    if not domain:
        first_seg = trimmed.split("/", 1)[0].strip(".").lower()
        host_port = first_seg
        if first_seg.startswith("["):
            end = first_seg.find("]")
            domain = first_seg[1:end] if end != -1 else first_seg
            has_port = "]:" in first_seg
        elif ":" in first_seg and first_seg.count(":") == 1:
            h, p = first_seg.split(":", 1)
            domain = h
            has_port = p.isdigit()
        else:
            domain = first_seg
            has_port = False

        if has_port:
            root_url = f"http://{host_port}"
            seed_urls = [root_url, f"https://{host_port}"]
        else:
            root_url = f"https://{domain}"
            seed_urls = [root_url, f"http://{domain}"]

    is_ip = False
    try:
        ipaddress.ip_address(domain)
        is_ip = True
    except ValueError:
        pass

    is_synthetic = (
        domain in {"localhost", "localhost.localdomain"}
        or domain.endswith((".localhost", ".local", ".example", ".invalid", ".test"))
    )

    # Deduplicate seed URLs while keeping order
    dedup_seeds: List[str] = []
    for u in seed_urls:
        if u and u not in dedup_seeds:
            dedup_seeds.append(u)

    return {
        "raw": trimmed,
        "domain": domain,
        "host_port": host_port or domain,
        "root_url": root_url,
        "seed_urls": dedup_seeds,
        "is_ip": is_ip,
        "is_local_or_test": is_ip or is_synthetic,
    }


async def _resolve_host(hostname: str, timeout_s: float = 2.0) -> List[str]:
    if not hostname:
        return []
    try:
        ipaddress.ip_address(hostname)
        return [hostname]
    except ValueError:
        pass
    try:
        infos = await asyncio.wait_for(
            asyncio.to_thread(socket.getaddrinfo, hostname, None, proto=socket.IPPROTO_TCP),
            timeout=timeout_s,
        )
        ips: List[str] = []
        for item in infos:
            ip = item[4][0]
            if ip and ip not in ips:
                ips.append(ip)
        return ips
    except Exception:
        return []


def _detect_tech(headers: httpx.Headers, body: str) -> Tuple[List[str], str]:
    found: List[str] = []
    seen: Set[str] = set()

    def _add(name: str) -> None:
        if name and name not in seen:
            seen.add(name)
            found.append(name)

    server = (headers.get("server") or "").strip()
    s_low = server.lower()
    if "cloudflare" in s_low or headers.get("cf-ray"):
        _add("Cloudflare")
    if "nginx" in s_low:
        _add("Nginx")
    elif "apache" in s_low:
        _add("Apache")
    elif "iis" in s_low:
        _add("Microsoft IIS")
    elif server:
        _add(server.split(" ")[0])

    xpb = (headers.get("x-powered-by") or "").strip()
    if xpb:
        _add(xpb)

    b_low = body.lower()
    for needle, label in (
        ("__next_data__", "Next.js"),
        ("/_next/static", "Next.js"),
        ("wp-content", "WordPress"),
        ("react", "React"),
        ("ng-version", "Angular"),
        ("csrfmiddlewaretoken", "Django"),
        ("laravel", "Laravel"),
        ("swagger-ui", "Swagger UI"),
        ("bootstrap", "Bootstrap"),
        ("jquery", "jQuery"),
    ):
        if needle in b_low:
            _add(label)

    return found, server


def _extract_html_links_and_forms(base_url: str, body: str) -> Tuple[List[str], List[str]]:
    base_parsed = urlparse(base_url)
    base_host = (base_parsed.hostname or "").lower()
    endpoints: List[str] = []
    param_urls: List[str] = []
    seen_ep: Set[str] = set()
    seen_p: Set[str] = set()

    for m in _ATTR_LINK_RE.finditer(body):
        raw_ref = m.group(1).strip()
        if not raw_ref or raw_ref.startswith(("javascript:", "mailto:", "data:", "#")):
            continue
        joined = urljoin(base_url, raw_ref)
        p = urlparse(joined)
        if p.scheme not in {"http", "https"}:
            continue
        if (p.hostname or "").lower() != base_host:
            continue
        clean = urlunparse(p._replace(fragment=""))
        if clean not in seen_ep:
            seen_ep.add(clean)
            endpoints.append(clean)
        if p.query and clean not in seen_p:
            seen_p.add(clean)
            param_urls.append(clean)
        if len(endpoints) >= 30:
            break

    for fm in _FORM_RE.finditer(body):
        attrs, inner = fm.group(1), fm.group(2)
        act_m = _FORM_ACTION_RE.search(attrs)
        meth_m = _FORM_METHOD_RE.search(attrs)
        action = act_m.group(1).strip() if act_m else ""
        method = (meth_m.group(1).strip().upper() if meth_m else "GET")
        inputs = [im.group(1).strip() for im in _INPUT_NAME_RE.finditer(inner) if im.group(1).strip()]
        target_action = urljoin(base_url, action) if action else base_url
        p = urlparse(target_action)
        if p.scheme in {"http", "https"} and (p.hostname or "").lower() == base_host:
            clean_act = urlunparse(p._replace(fragment=""))
            if clean_act not in seen_ep:
                seen_ep.add(clean_act)
                endpoints.append(clean_act)
            if method == "GET" and inputs and "?" not in clean_act:
                q_str = urlencode({k: "test" for k in inputs[:4]})
                synthesized = f"{clean_act}?{q_str}"
                if synthesized not in seen_p:
                    seen_p.add(synthesized)
                    param_urls.append(synthesized)

    return endpoints, param_urls


def _make_asset_id(kind: str, value: str) -> str:
    digest = hashlib.sha1(f"{kind}:{value}".encode("utf-8", errors="ignore")).hexdigest()[:12]
    return f"hub_{kind.lower()}_{digest}"


def _make_finding(
    *,
    run_id: str,
    vuln_class: str,
    title: str,
    severity: str,
    endpoint: str,
    description: str,
    curl_cmd: str,
    confidence: float = 0.88,
    status: str = "TRIAGED",
) -> Dict[str, Any]:
    sev_up = severity.upper()
    cvss_map = {"CRITICAL": 9.8, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 3.1, "INFO": 0.0}
    fid = "hub_fd_" + hashlib.sha1(f"{vuln_class}:{endpoint}".encode("utf-8", errors="ignore")).hexdigest()[:12]
    evidence = description
    if curl_cmd:
        evidence = f"{description}\n\nReproduce:\n{curl_cmd}"
    return {
        "id": fid,
        "run_id": run_id,
        "title": title,
        "vuln_class": vuln_class,
        "severity": sev_up,
        "cvss_score": cvss_map.get(sev_up, 3.0),
        "confidence": confidence,
        "endpoint": endpoint,
        "evidence": evidence,
        "poc_details": {
            "description": description,
            "curl_command": curl_cmd,
            "template_id": vuln_class,
        },
        "status": status,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def _build_client_kwargs(*, proxy: Optional[str], follow_redirects: bool, timeout: float = 5.0) -> Dict[str, Any]:
    kwargs: Dict[str, Any] = {
        "timeout": httpx.Timeout(timeout, connect=3.5),
        "follow_redirects": follow_redirects,
        "verify": False,
        "headers": {
            "User-Agent": "Mozilla/5.0 (compatible; HunterAI/2.0)",
            "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
        },
    }
    clean_proxy = (proxy or "").strip()
    if clean_proxy:
        kwargs["proxy"] = clean_proxy
    else:
        kwargs["trust_env"] = False
    return kwargs


async def _inspect_tls(host: str, port: int = 443) -> Optional[Dict[str, Any]]:
    def _sync_tls() -> Optional[Dict[str, Any]]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=3.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()
                return {"protocol": proto or "", "has_cert": bool(cert)}

    try:
        return await asyncio.wait_for(asyncio.to_thread(_sync_tls), timeout=3.5)
    except Exception:
        return None


async def run_live_security_scan(
    *,
    target: str,
    run_id: str,
    mode: str = "full",
    proxy: Optional[str] = None,
    phase_cb: Optional[Callable[[str, float, Dict[str, Any]], Awaitable[bool]]] = None,
) -> Dict[str, Any]:
    """Execute a genuine multi-stage web recon & verification scan asynchronously."""
    spec = normalize_target_spec(target)
    domain = spec["domain"]
    assets: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    observations: List[Dict[str, Any]] = []
    seen_assets: Set[Tuple[str, str]] = set()
    seen_findings: Set[Tuple[str, str]] = set()

    def _add_asset(kind: str, value: str, attributes: Dict[str, Any]) -> None:
        key = (kind, value)
        if key in seen_assets:
            for existing in assets:
                if existing["kind"] == kind and existing["value"] == value:
                    existing["attributes"].update(attributes)
                    return
            return
        seen_assets.add(key)
        assets.append(
            {
                "id": _make_asset_id(kind, value),
                "kind": kind,
                "value": value,
                "attributes": attributes,
                "first_seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
        )

    def _add_finding(item: Dict[str, Any]) -> None:
        key = (item["vuln_class"], item["endpoint"])
        if key not in seen_findings:
            seen_findings.add(key)
            findings.append(item)

    if not domain:
        return {"assets": [], "findings": [], "observations": [], "live_count": 0}

    # Stage 1: DNS & Subdomain Enumeration
    if phase_cb and not await phase_cb("DNS_ENUM", 0.38, {"domain": domain}):
        return {"cancelled": True, "assets": assets, "findings": findings, "observations": observations, "live_count": 0}

    ips = await _resolve_host(domain, timeout_s=2.0)
    discovered_hosts: List[str] = [spec["host_port"]]
    if domain not in discovered_hosts:
        discovered_hosts.append(domain)

    _add_asset(
        "SUBDOMAIN",
        spec["host_port"],
        {"source": "target_seed", "resolved_ips": ips, "root_target": spec["raw"]},
    )
    for ip_addr in ips[:4]:
        _add_asset("IP", ip_addr, {"hostname": domain, "source": "dns_a"})

    if not ips and not spec["is_ip"]:
        observations.append(
            {
                "source_tool": "dns_resolver",
                "evidence_type": "observation",
                "confidence": 0.9,
                "target": spec["raw"],
                "title": f"DNS Lookup Returned No A/AAAA Records for {domain}",
                "content": f"Host {domain!r} did not resolve via system DNS (synthetic or offline domain).",
            }
        )

    # Passive CT logs + common subdomain resolution for resolvable public domains
    if ips and not spec["is_local_or_test"] and "." in domain:
        async def _probe_common_sub(sub_prefix: str) -> Optional[Tuple[str, List[str]]]:
            fqdn = f"{sub_prefix}.{domain}"
            sub_ips = await _resolve_host(fqdn, timeout_s=1.5)
            return (fqdn, sub_ips) if sub_ips else None

        sub_tasks = [_probe_common_sub(p) for p in _COMMON_SUBS]

        async def _query_crt() -> List[str]:
            ct_names: List[str] = []
            try:
                async with httpx.AsyncClient(**_build_client_kwargs(proxy=None, follow_redirects=True, timeout=3.5)) as c:
                    r = await c.get(f"https://crt.sh/?q=%25.{domain}&output=json")
                    if r.status_code == 200:
                        for row in r.json()[:80]:
                            for line in str(row.get("name_value", "")).splitlines():
                                clean = line.strip().lower().lstrip("*.")
                                if clean and (clean == domain or clean.endswith(f".{domain}")):
                                    if clean not in ct_names:
                                        ct_names.append(clean)
                                    if len(ct_names) >= 12:
                                        return ct_names
            except Exception:
                pass
            return ct_names

        sub_results, ct_hosts = await asyncio.gather(
            asyncio.gather(*sub_tasks),
            _query_crt(),
        )
        for res in sub_results:
            if res is not None:
                fqdn, sub_ips = res
                if fqdn not in discovered_hosts:
                    discovered_hosts.append(fqdn)
                _add_asset("SUBDOMAIN", fqdn, {"source": "dns_common", "resolved_ips": sub_ips})
        for fqdn in ct_hosts:
            if fqdn not in discovered_hosts and len(discovered_hosts) < 12:
                fqdn_ips = await _resolve_host(fqdn, timeout_s=1.2)
                if fqdn_ips:
                    discovered_hosts.append(fqdn)
                    _add_asset("SUBDOMAIN", fqdn, {"source": "crt.sh", "resolved_ips": fqdn_ips})

    # Stage 2: Live HTTP/HTTPS Probing & HTML Crawling
    if phase_cb and not await phase_cb("HTTP_PROBE", 0.56, {"hosts": len(discovered_hosts)}):
        return {"cancelled": True, "assets": assets, "findings": findings, "observations": observations, "live_count": 0}

    live_roots: List[Dict[str, Any]] = []
    discovered_param_urls: List[str] = []

    if ips or spec["is_local_or_test"] and (domain in {"localhost", "127.0.0.1", "::1"} or spec["is_ip"]):
        probe_candidates: List[Tuple[str, str]] = []
        for s_url in spec["seed_urls"]:
            probe_candidates.append((spec["host_port"], s_url))
        for h in discovered_hosts[1:6]:
            probe_candidates.append((h, f"https://{h}"))
            probe_candidates.append((h, f"http://{h}"))

        checked_origins: Set[str] = set()
        probed_hosts_ok: Set[str] = set()

        async with httpx.AsyncClient(**_build_client_kwargs(proxy=proxy, follow_redirects=True, timeout=5.0)) as client:
            for host_key, url_candidate in probe_candidates:
                if host_key in probed_hosts_ok and host_key != spec["host_port"]:
                    continue
                if url_candidate in checked_origins:
                    continue
                checked_origins.add(url_candidate)
                try:
                    resp = await client.get(url_candidate)
                    final_url = str(resp.url)
                    probed_hosts_ok.add(host_key)
                    body_text = resp.text[:200_000] if hasattr(resp, "text") else ""
                    title_m = _TITLE_RE.search(body_text)
                    title = " ".join(html.unescape(title_m.group(1)).split())[:120] if title_m else ""
                    tech, server = _detect_tech(resp.headers, body_text)
                    endpoints, param_urls = _extract_html_links_and_forms(final_url, body_text)
                    for pu in param_urls:
                        if pu not in discovered_param_urls:
                            discovered_param_urls.append(pu)

                    live_info = {
                        "live_url": final_url,
                        "status_code": resp.status_code,
                        "title": title,
                        "tech": tech,
                        "webserver": server,
                        "headers": dict(resp.headers),
                        "cookies": resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else [],
                        "body_sample": body_text[:8192],
                        "endpoints": endpoints,
                    }
                    live_roots.append(live_info)

                    _add_asset(
                        "SUBDOMAIN",
                        host_key,
                        {
                            "live_url": final_url,
                            "status_code": resp.status_code,
                            "title": title,
                            "tech": tech,
                            "webserver": server,
                        },
                    )
                    _add_asset(
                        "ENDPOINT",
                        final_url,
                        {
                            "live_url": final_url,
                            "status_code": resp.status_code,
                            "title": title,
                            "tech": tech,
                            "webserver": server,
                            "source": "http_probe",
                        },
                    )
                    for ep in endpoints[:20]:
                        _add_asset(
                            "ENDPOINT",
                            ep,
                            {"url": ep, "parent": final_url, "source": "html_crawl"},
                        )

                    observations.append(
                        {
                            "source_tool": "native_httpx",
                            "evidence_type": "observation",
                            "confidence": 0.95,
                            "target": final_url,
                            "title": f"HTTP {resp.status_code} {title or final_url}",
                            "content": (
                                f"GET {final_url} -> {resp.status_code} | "
                                f"Title: {title or '(none)'} | Server: {server or '(hidden)'} | "
                                f"Tech: {', '.join(tech) or '(none)'} | Links: {len(endpoints)}"
                            ),
                        }
                    )
                    if url_candidate.startswith("https://"):
                        parsed_live = urlparse(final_url)
                        if parsed_live.scheme == "https" and parsed_live.hostname:
                            tls_meta = await _inspect_tls(parsed_live.hostname, parsed_live.port or 443)
                            if tls_meta:
                                _add_asset("ENDPOINT", final_url, {"tls": tls_meta})
                    # Once root URL succeeded on HTTPS, don't duplicate on plain HTTP unless root lacked scheme
                    if host_key == spec["host_port"] and "://" not in spec["raw"] and final_url.startswith("https://"):
                        break
                except Exception as exc:
                    if proxy and len(live_roots) == 0:
                        observations.append(
                            {
                                "source_tool": "native_httpx",
                                "evidence_type": "observation",
                                "confidence": 0.7,
                                "target": url_candidate,
                                "title": f"HTTP Probe Failed via Proxy ({url_candidate})",
                                "content": f"Request to {url_candidate} failed (proxy={proxy}): {exc}",
                            }
                        )

    # Stage 3: Security Audit & Active Safe Checks
    if mode != "passive" and live_roots:
        if phase_cb and not await phase_cb("SECURITY_AUDIT", 0.78, {"live_roots": len(live_roots)}):
            return {"cancelled": True, "assets": assets, "findings": findings, "observations": observations, "live_count": len(live_roots)}

        primary_origins: List[Dict[str, Any]] = []
        seen_orig: Set[str] = set()
        for lr in live_roots:
            pu = urlparse(lr["live_url"])
            orig = f"{pu.scheme}://{pu.netloc}"
            if orig not in seen_orig:
                seen_orig.add(orig)
                primary_origins.append(lr)
            if len(primary_origins) >= 4:
                break

        async with httpx.AsyncClient(**_build_client_kwargs(proxy=proxy, follow_redirects=False, timeout=4.5)) as no_redir:
            for lr in primary_origins:
                target_url = lr["live_url"]
                pu = urlparse(target_url)
                orig = f"{pu.scheme}://{pu.netloc}"
                hdrs = {k.lower(): v for k, v in (lr.get("headers") or {}).items()}
                body_sample = lr.get("body_sample") or ""

                # 3a. Security headers audit
                missing_hdrs: List[str] = []
                if pu.scheme == "https" and "strict-transport-security" not in hdrs:
                    missing_hdrs.append("Strict-Transport-Security")
                if "content-security-policy" not in hdrs:
                    missing_hdrs.append("Content-Security-Policy")
                if "x-frame-options" not in hdrs and "frame-ancestors" not in hdrs.get("content-security-policy", "").lower():
                    missing_hdrs.append("X-Frame-Options")
                if "x-content-type-options" not in hdrs:
                    missing_hdrs.append("X-Content-Type-Options")
                if missing_hdrs:
                    _add_finding(
                        _make_finding(
                            run_id=run_id,
                            vuln_class="http-missing-security-headers",
                            title="Missing HTTP Security Hardening Headers",
                            severity="LOW",
                            endpoint=target_url,
                            description=f"HTTP {lr['status_code']} at {target_url} omits recommended headers: {', '.join(missing_hdrs)}.",
                            curl_cmd=f'curl -sI "{target_url}"',
                            confidence=0.92,
                        )
                    )

                # 3b. Plaintext HTTP active check
                if pu.scheme == "http" and lr["status_code"] == 200:
                    has_pw = 'type="password"' in body_sample.lower() or "type='password'" in body_sample.lower()
                    _add_finding(
                        _make_finding(
                            run_id=run_id,
                            vuln_class="plaintext-http-endpoint",
                            title="Cleartext HTTP Endpoint Active",
                            severity="MEDIUM" if has_pw else "INFO",
                            endpoint=target_url,
                            description=f"Unencrypted HTTP endpoint {target_url} served 200 OK without HTTPS redirect.",
                            curl_cmd=f'curl -iL "{target_url}"',
                            confidence=0.95,
                        )
                    )

                # 3c. Tech version disclosure
                leaks = []
                for hk in ("server", "x-powered-by", "x-aspnet-version"):
                    val = hdrs.get(hk, "")
                    if val and _VERSION_RE.search(val):
                        leaks.append(f"{hk}: {val}")
                if leaks:
                    _add_finding(
                        _make_finding(
                            run_id=run_id,
                            vuln_class="http-tech-version-disclosure",
                            title="Server / Framework Version Disclosure",
                            severity="INFO",
                            endpoint=target_url,
                            description=f"Response headers expose software version metadata: {'; '.join(leaks)}.",
                            curl_cmd=f'curl -sI "{target_url}"',
                            confidence=0.95,
                        )
                    )

                # 3d. Set-Cookie security flags
                for ck in lr.get("cookies") or []:
                    c_low = ck.lower()
                    issues = []
                    if "httponly" not in c_low:
                        issues.append("missing HttpOnly")
                    if pu.scheme == "https" and "secure" not in c_low:
                        issues.append("missing Secure")
                    if issues:
                        c_name = ck.split("=", 1)[0].strip()
                        _add_finding(
                            _make_finding(
                                run_id=run_id,
                                vuln_class="cookie-missing-security-flags",
                                title=f'Cookie "{c_name}" Missing Security Flags',
                                severity="LOW",
                                endpoint=target_url,
                                description=f"Set-Cookie header ({c_name}) lacks {', '.join(issues)}.",
                                curl_cmd=f'curl -sI "{target_url}"',
                                confidence=0.9,
                            )
                        )
                        break

                # 3e. Active CORS check
                try:
                    c_resp = await no_redir.get(target_url, headers={"Origin": "https://evil.example"})
                    acao = (c_resp.headers.get("access-control-allow-origin") or "").strip()
                    acac = (c_resp.headers.get("access-control-allow-credentials") or "").strip().lower() == "true"
                    if acao == "https://evil.example" or (acao == "*" and acac):
                        _add_finding(
                            _make_finding(
                                run_id=run_id,
                                vuln_class="cors-arbitrary-origin-reflection",
                                title="Permissive CORS Origin Reflection",
                                severity="HIGH" if acac else "MEDIUM",
                                endpoint=target_url,
                                description=f"Origin: https://evil.example received Access-Control-Allow-Origin: {acao} (Allow-Credentials: {acac}).",
                                curl_cmd=f'curl -i -H "Origin: https://evil.example" "{target_url}"',
                                confidence=0.95,
                                status="CONFIRMED",
                            )
                        )
                except Exception:
                    pass

                # 3f. Soft-404 baseline + exposed sensitive paths check
                nf_status, nf_len = 404, -1
                try:
                    nf_r = await no_redir.get(f"{orig}/__hunter_nonexistent_probe_918273__")
                    nf_status = nf_r.status_code
                    nf_len = len(nf_r.content)
                except Exception:
                    pass

                sensitive_checks = (
                    ("/.env", "exposed-dotenv-file", "Exposed Environment File (.env)", "CRITICAL",
                     lambda st, ct, b: st == 200 and "text/html" not in ct.lower() and any(k in b for k in ("APP_KEY=", "DB_PASSWORD=", "SECRET_KEY=", "DATABASE_URL="))),
                    ("/.git/HEAD", "exposed-git-head", "Exposed Git Repository Metadata (.git/HEAD)", "HIGH",
                     lambda st, ct, b: st == 200 and "ref: refs/" in b),
                    ("/phpinfo.php", "exposed-phpinfo", "Exposed PHPInfo Diagnostic Page", "MEDIUM",
                     lambda st, ct, b: st == 200 and "PHP Version" in b and "phpinfo()" in b),
                    ("/swagger.json", "exposed-swagger-spec", "Public Swagger/OpenAPI Specification", "INFO",
                     lambda st, ct, b: st == 200 and '"paths"' in b and ('"swagger"' in b or '"openapi"' in b)),
                    ("/openapi.json", "exposed-openapi-spec", "Public OpenAPI Specification", "INFO",
                     lambda st, ct, b: st == 200 and '"openapi"' in b and '"paths"' in b),
                )
                for path_suffix, v_cls, title, sev, validator in sensitive_checks:
                    probe_url = f"{orig}{path_suffix}"
                    try:
                        pr = await no_redir.get(probe_url)
                        if nf_status == pr.status_code and nf_len > 0 and len(pr.content) == nf_len:
                            continue
                        ct = pr.headers.get("content-type", "")
                        b = pr.text[:32_000]
                        if validator(pr.status_code, ct, b):
                            _add_asset("ENDPOINT", probe_url, {"live_url": probe_url, "status_code": pr.status_code, "source": "sensitive_probe"})
                            _add_finding(
                                _make_finding(
                                    run_id=run_id,
                                    vuln_class=v_cls,
                                    title=title,
                                    severity=sev,
                                    endpoint=probe_url,
                                    description=f"HTTP {pr.status_code} matched verification signature at {probe_url}.",
                                    curl_cmd=f'curl -sS "{probe_url}"',
                                    confidence=0.96,
                                    status="CONFIRMED",
                                )
                            )
                    except Exception:
                        pass

                # 3g. Safe active query parameter verification (when mode == full/web)
                if mode in {"full", "web", "autonomous"} and discovered_param_urls:
                    for p_url in discovered_param_urls[:6]:
                        parsed_p = urlparse(p_url)
                        qs = parse_qs(parsed_p.query, keep_blank_values=True)
                        for param_name in list(qs.keys())[:3]:
                            p_low = param_name.lower()
                            # Reflected XSS check using harmless marker
                            marker = "hunterXss7319<hx>"
                            test_qs = {k: (marker if k == param_name else v[0]) for k, v in qs.items()}
                            xss_url = urlunparse(parsed_p._replace(query=urlencode(test_qs)))
                            try:
                                xr = await no_redir.get(xss_url)
                                if xr.status_code == 200 and "text/html" in xr.headers.get("content-type", "").lower() and marker in xr.text:
                                    _add_finding(
                                        _make_finding(
                                            run_id=run_id,
                                            vuln_class="reflected-xss",
                                            title=f"Unescaped HTML Reflection (XSS Candidate) on `{param_name}`",
                                            severity="HIGH",
                                            endpoint=xss_url,
                                            description=f"Marker `{marker}` reflected verbatim unescaped in text/html response on parameter `{param_name}`.",
                                            curl_cmd=f'curl -sS "{xss_url}"',
                                            confidence=0.92,
                                            status="CONFIRMED",
                                        )
                                    )
                            except Exception:
                                pass

                            # Open redirect check on redirect-style params
                            if p_low in {"next", "redirect", "redirect_uri", "return", "return_to", "to", "url", "dest"}:
                                redir_qs = {k: ("https://evil.example" if k == param_name else v[0]) for k, v in qs.items()}
                                redir_url = urlunparse(parsed_p._replace(query=urlencode(redir_qs)))
                                try:
                                    rr = await no_redir.get(redir_url)
                                    loc = rr.headers.get("location", "")
                                    if rr.status_code in {301, 302, 303, 307, 308} and "evil.example" in loc.lower():
                                        _add_finding(
                                            _make_finding(
                                                run_id=run_id,
                                                vuln_class="open-redirect",
                                                title=f"Open Redirect via `{param_name}` Parameter",
                                                severity="MEDIUM",
                                                endpoint=redir_url,
                                                description=f"HTTP {rr.status_code} redirected Location to external origin ({loc}).",
                                                curl_cmd=f'curl -i "{redir_url}"',
                                                confidence=0.94,
                                                status="CONFIRMED",
                                            )
                                        )
                                except Exception:
                                    pass

                            # Safe SQL syntax error probe on ID/search params
                            if p_low in {"id", "uid", "user_id", "item", "cat", "q", "query", "search"}:
                                sqli_qs = {k: ("1' OR '1'='1" if k == param_name else v[0]) for k, v in qs.items()}
                                sqli_url = urlunparse(parsed_p._replace(query=urlencode(sqli_qs)))
                                try:
                                    sr = await no_redir.get(sqli_url)
                                    low_b = sr.text[:8000].lower()
                                    if sr.status_code >= 500 or any(sig in low_b for sig in _SQL_ERROR_SIGS):
                                        if any(sig in low_b for sig in _SQL_ERROR_SIGS):
                                            _add_finding(
                                                _make_finding(
                                                    run_id=run_id,
                                                    vuln_class="sql-injection-error",
                                                    title=f"SQL Syntax Error Disclosure / SQLi on `{param_name}`",
                                                    severity="CRITICAL",
                                                    endpoint=sqli_url,
                                                    description=f"SQL engine error signature returned (HTTP {sr.status_code}) when testing parameter `{param_name}`.",
                                                    curl_cmd=f'curl -i "{sqli_url}"',
                                                    confidence=0.93,
                                                    status="CONFIRMED",
                                                )
                                            )
                                except Exception:
                                    pass

    return {
        "cancelled": False,
        "assets": assets,
        "findings": findings,
        "observations": observations,
        "live_count": len(live_roots),
        "endpoints_count": sum(1 for a in assets if a["kind"] == "ENDPOINT"),
    }
