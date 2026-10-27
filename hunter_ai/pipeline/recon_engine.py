"""
HunterAI Recon Engine — Attack Surface Mapping
===============================================
Passive/Active subdomain discovery, live host probing, URL crawl, nuclei sweep.

مبدأ صارم: **لا بيانات وهمية إطلاقاً**.
كل نتيجة تُسجَّل مع الأداة التي أنتجتها (provenance)، والأدوات غير المتاحة
تُعلَن صراحةً في ``tools_missing`` بدل أن تُخترع لها قيم.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

# نمط اسم مضيف صالح (.labels + TLD)
_HOST_RE = re.compile(r"^(?:[a-z0-9_-]+\.)+[a-z]{2,}$", re.I)

# عدد المضيفات التي نُسقط عليها HTTPX في التشغيل الواحد (حماية من الانفجار)
MAX_PROBE_HOSTS = int(os.getenv("RECON_MAX_PROBE_HOSTS", "5000"))
# عدد الروابط التي نجمعها لكل مصدر
MAX_URLS_PER_SOURCE = 2000


def _domain_of(target: str) -> str:
    """يستخرج اسم النطاق الجذري من أي صيغة إدخال (URL / host / host:port)."""
    t = (target or "").strip().lower()
    if "://" in t:
        t = urlparse(t).netloc
    t = t.split("/")[0].split("@")[-1].split(":")[0]
    return t.strip(".")


def _host_of(value: str) -> str:
    """يستخرج اسم المضيف من سطر ناتج أداة (URL أو host أو host:port)."""
    v = (value or "").strip()
    if not v:
        return ""
    if "://" in v:
        v = urlparse(v).netloc
    v = v.split("/")[0].split("@")[-1]
    v = v.split(":")[0]
    return v.strip().lower().strip(".")


def _in_scope(host: str, domain: str) -> bool:
    """هل المضيف داخل نطاق الجذر؟ (يمنع التسرّب إلى نطاقات أخرى)"""
    if not host or not domain:
        return False
    return host == domain or host.endswith("." + domain)


def _clean_lines(values: List[Any]) -> List[str]:
    out: List[str] = []
    for v in values or []:
        if isinstance(v, str):
            s = v.strip()
            if s:
                out.append(s)
    return out


def _hostnames(values: List[Any]) -> List[str]:
    """يرشّح القيم إلى أسماء مضيفين صالحة داخل النطاق."""
    seen: Set[str] = set()
    out: List[str] = []
    for raw in _clean_lines(values):
        # some tools print "sub.example.com [200] [title]" -> take first token
        token = raw.split()[0] if raw.split() else raw
        host = _host_of(token)
        if not host or not _HOST_RE.match(host):
            continue
        if host in seen:
            continue
        seen.add(host)
        out.append(host)
    return out


def _probe_priority(host: str) -> Tuple[int, str]:
    """
    ترتيب أولوية الفحص: الجذر وwww والأسماء الشائعة أولاً.
    بدون هذا،探测 أول N أبجدياً من قائمة crt.sh قد كلها noise
    (0.0.1.example.com, 000.example.com, ...) والهدف الحقيقي لا يُفحص أبداً.
    """
    if host.count(".") <= 1:
        return (0, host)                       # النطاق الجذري
    label = host.split(".")[0].lower()
    if label in _HIGH_VALUE_LABELS:
        return (1, host)
    if label.isdigit() or (label and label[0].isdigit()):
        return (3, host)                       # أرقام فقط — غالباً ضجيج
    return (2, host)


# أسماء فرعية عالية القيمة تُفحص أولاً
_HIGH_VALUE_LABELS = {
    "www", "api", "app", "admin", "portal", "dev", "staging", "test", "uat",
    "auth", "login", "sso", "id", "account", "accounts", "user", "users",
    "git", "gitlab", "jenkins", "ci", "cd", "deploy", "internal", "intranet",
    "vpn", "remote", "mail", "smtp", "imap", "ftp", "s3", "cdn", "static",
    "assets", "media", "blog", "shop", "store", "checkout", "pay", "payment",
    "graphql", "ws", "websocket", "gateway", "proxy", "lb", "edge", "cdn2",
}


def _urls(values: List[Any]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for raw in _clean_lines(values):
        if not raw.lower().startswith("http"):
            continue
        u = raw.strip()
        if u in seen:
            continue
        seen.add(u)
        out.append(u)
        if len(out) >= MAX_URLS_PER_SOURCE:
            break
    return out


async def _run_tool(
    master: Any,
    tool: str,
    context: Dict[str, Any],
) -> Tuple[List[Any], Optional[str], bool]:
    """
    ينفّذ أداة عبر السجل الرئيسي.
    يعيد: (النتائج, ملف الخرج, هل نُفِّذت الأداة الأصلية؟)
    """
    spec = master.specs.get(tool)
    if spec is None:
        return [], None, False
    try:
        parsed, log_file = await master.execute(tool, context)
    except Exception:
        return [], None, False
    used_primary = master.is_available(tool) and bool(spec.command_template)
    return list(parsed or []), log_file, used_primary


async def run_recon(
    target: str,
    scope: str = "",
    nuclei: bool = False,
    profile: str = "safe",
) -> Dict[str, Any]:
    """Run full recon pipeline against target — real tools only."""
    domain = _domain_of(target)
    if not domain:
        return {
            "target": target,
            "domain": "",
            "error": f"Could not parse a domain from {target!r}",
            "subdomains": [], "live_hosts": [], "urls": [], "nuclei_findings": [],
            "provenance": {}, "tools_used": [], "tools_missing": [], "artifacts": {},
        }

    print(f"[+] Starting recon for {target} (domain={domain})")
    started = time.time()

    from hunter_ai.pipeline.tool_specs import MasterToolRegistry
    master = MasterToolRegistry()

    provenance: Dict[str, Dict[str, List[str]]] = {
        "subdomains": {}, "live_hosts": {}, "urls": {}, "nuclei_findings": {},
    }
    tools_used: Set[str] = set()
    tools_missing: Set[str] = set()
    artifacts: Dict[str, str] = {}

    subdomain_pool: Dict[str, Set[str]] = {}   # host -> {sources}
    url_pool: Dict[str, Set[str]] = {}         # url  -> {sources}

    def _record(bucket: str, key: str, source: str) -> None:
        provenance[bucket].setdefault(source, [])
        if key not in provenance[bucket][source]:
            provenance[bucket][source].append(key)

    def _add_host(bucket: Dict[str, Set[str]], host: str, source: str) -> None:
        host = _host_of(host)
        if not _HOST_RE.match(host) or not _in_scope(host, domain):
            return
        bucket.setdefault(host, set()).add(source)
        _record("subdomains" if bucket is subdomain_pool else "live_hosts", host, source)

    # ── 1) Certificate Transparency (crt.sh) — HTTP مباشر، بلا binary ─────────
    try:
        from core.playbooks.bug_bounty_methodology import BugBountyMethodology
        bb = BugBountyMethodology(master.tm)
        crt_subs = await bb.fetch_crtsh_subdomains(domain)
        for h in _hostnames(crt_subs):
            _add_host(subdomain_pool, h, "crtsh")
        tools_used.add("crtsh")
    except Exception as exc:
        tools_missing.add("crtsh")
        print(f"    [warn] crtsh unavailable: {exc}")

    # ── 2) Passive subdomain enumeration ─────────────────────────────────────
    passive_specs = [
        ("subfinder", {"domain": domain}),
        ("assetfinder", {"domain": domain}),
    ]
    if profile in ("full", "hunter", "deep", "active"):
        passive_specs.append(("amass", {"domain": domain}))

    for tool, ctx in passive_specs:
        if not master.is_available(tool):
            tools_missing.add(tool)
            print(f"    [skip] {tool} not in PATH")
            continue
        items, log_file, primary = await _run_tool(master, tool, ctx)
        if log_file:
            artifacts[tool] = log_file
        if not primary:
            tools_missing.add(tool)
            continue
        tools_used.add(tool)
        for h in _hostnames(items):
            _add_host(subdomain_pool, h, tool)

    # ── 3) theHarvester — OSINT for hosts/emails ────────────────────────────
    if master.is_available("theharvester") or master.is_available("theHarvester"):
        items, log_file, primary = await _run_tool(master, "theharvester", {"domain": domain})
        if log_file:
            artifacts["theharvester"] = log_file
        if primary:
            tools_used.add("theharvester")
            for h in _hostnames(items):
                _add_host(subdomain_pool, h, "theharvester")
        else:
            tools_missing.add("theharvester")

    subdomains = sorted(subdomain_pool.keys())
    # النطاق الجذري نفسه دائماً ضمن النطاقات المكتشفة
    if domain and domain not in subdomain_pool:
        subdomain_pool[domain] = {"root"}
        _record("subdomains", domain, "root")
        subdomains = sorted(subdomain_pool.keys())

    print(f"    [+] {len(subdomains)} subdomains discovered")

    # ── 4) Live host discovery via httpx (batch mode: httpx -l <file>) ────────
    live_hosts: Dict[str, Set[str]] = {}
    live_meta: Dict[str, Dict[str, Any]] = {}
    # ترتيب بالأولوية: الجذر وwww/api/admin أولاً ثم الباقي
    ordered = sorted(subdomains, key=_probe_priority)
    probe_targets = ordered[:MAX_PROBE_HOSTS]
    if len(ordered) > MAX_PROBE_HOSTS:
        print(f"    [warn] probing {MAX_PROBE_HOSTS} of {len(ordered)} hosts "
              f"(raise RECON_MAX_PROBE_HOSTS to cover all)")

    if master.is_available("httpx"):
        # وضع الدفعة: ملف مدخلات — أسرع بكثير من -u لكل مضيف على حدة
        # وhttpx يتعامل مع DNS failures والتوازي بنفسه.
        import tempfile
        tmp_path = ""
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False, encoding="utf-8", newline="\n"
            ) as tf:
                tf.write("\n".join(probe_targets))
                tmp_path = tf.name
            cmd = (
                f"httpx -l {tmp_path} -silent -json "
                f"-status-code -title -tech-detect -content-length"
            )
            res = await master.tm.execute(cmd, timeout=600)
            if res.output_file:
                artifacts["httpx"] = res.output_file
            if not res.success:
                tools_missing.add("httpx")
                print(f"    [warn] httpx batch probe failed: {res.error or res.stderr[:120]}")
            else:
                tools_used.add("httpx")
                for line in (res.stdout or "").splitlines():
                    line = line.strip()
                    if not line.startswith("{"):
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    host = _host_of(rec.get("host") or rec.get("input") or rec.get("url") or "")
                    if not host or not _in_scope(host, domain):
                        continue
                    live_hosts.setdefault(host, set()).add("httpx")
                    _record("live_hosts", host, "httpx")
                    live_meta[host] = {
                        "url": rec.get("url"),
                        "status_code": rec.get("status_code"),
                        "title": rec.get("title"),
                        "webserver": rec.get("webserver"),
                        "tech": rec.get("tech") or [],
                        "content_length": rec.get("content_length"),
                        "host_ip": rec.get("host_ip"),
                    }
        except Exception as exc:
            tools_missing.add("httpx")
            print(f"    [warn] httpx batch probe error: {exc}")
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
    else:
        tools_missing.add("httpx")
        print("    [skip] httpx not in PATH — live-host detection skipped")

    # ── 5) URL collection (katana / gau / waybackurls) ───────────────────────
    crawl_roots = [f"https://{h}" for h in sorted(live_hosts)[:10]] or [f"https://{domain}"]
    for tool, ctx in (("katana", {"url": crawl_roots[0]}), ("gau", {"domain": domain}),
                      ("waybackurls", {"domain": domain})):
        if not master.is_available(tool):
            tools_missing.add(tool)
            continue
        items, log_file, primary = await _run_tool(master, tool, ctx)
        if log_file:
            artifacts[tool] = log_file
        if not primary:
            tools_missing.add(tool)
            continue
        tools_used.add(tool)
        for u in _urls(items):
            h = _host_of(u)
            if h and not _in_scope(h, domain):
                continue
            url_pool.setdefault(u, set()).add(tool)
            _record("urls", u, tool)

    # ── 6) Nuclei triage (opt-in) ────────────────────────────────────────────
    nuclei_findings: List[str] = []
    if nuclei:
        scan_urls = [f"https://{h}" for h in sorted(live_hosts)[:20]] or [f"https://{domain}"]
        if master.is_available("nuclei"):
            for u in scan_urls:
                items, log_file, primary = await _run_tool(master, "nuclei", {"url": u})
                if log_file:
                    artifacts.setdefault("nuclei", log_file)
                if not primary:
                    continue
                tools_used.add("nuclei")
                for line in _clean_lines(items):
                    nuclei_findings.append(line)
                    _record("nuclei_findings", line, "nuclei")
        else:
            tools_missing.add("nuclei")

    results: Dict[str, Any] = {
        "target": target,
        "domain": domain,
        "scope": scope or domain,
        "subdomains": subdomains,
        "live_hosts": sorted(live_hosts.keys()),
        "live_hosts_meta": live_meta,
        "urls": sorted(url_pool.keys()),
        "nuclei_findings": nuclei_findings,
        "provenance": provenance,
        "tools_used": sorted(tools_used),
        "tools_missing": sorted(tools_missing),
        "artifacts": artifacts,
        "duration_s": round(time.time() - started, 2),
        "generated_at": time.time(),
    }

    out_dir = Path("data/engagements") / domain
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "recon.json").write_text(
        json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    results["artifact_path"] = str(out_dir / "recon.json")

    print(f"[+] Recon complete: {len(subdomains)} subdomains, "
          f"{len(results['live_hosts'])} live hosts, {len(results['urls'])} urls")
    if tools_missing:
        print(f"    [i] tools missing (no data for them): {', '.join(sorted(tools_missing))}")
    print(f"[+] Results saved to {out_dir / 'recon.json'}")
    return results


def load_recon(target: str) -> Optional[Dict[str, Any]]:
    """يحمّل نتيجة recon محفوظة سابقاً للهدف (بدل توليد بيانات)."""
    domain = _domain_of(target)
    path = Path("data/engagements") / domain / "recon.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def surface_summary(target: str) -> str:
    """Ranked attack surface summary — من نتيجة recon الحقيقية فقط."""
    recon = load_recon(target)
    if not recon:
        return (
            f"Attack Surface Summary for {target}\n"
            "===================================\n"
            "No recon data found.\n"
            f"Run first:  pentest recon {target}\n"
            "(summary is built only from real tool output — nothing is simulated)"
        )

    domain = recon.get("domain") or _domain_of(target)
    subdomains = recon.get("subdomains") or []
    live = recon.get("live_hosts") or []
    meta = recon.get("live_hosts_meta") or {}
    urls = recon.get("urls") or []
    findings = recon.get("nuclei_findings") or []
    used = recon.get("tools_used") or []
    missing = recon.get("tools_missing") or []

    # ترتيب: المضيفات الحيّة أولاً، ثم الأكثر روابط، ثم الباقي
    url_count = {}
    for u in urls:
        h = _host_of(u)
        url_count[h] = url_count.get(h, 0) + 1
    ranked = sorted(subdomains, key=lambda h: (h not in live, -url_count.get(h, 0), h))

    lines = [
        f"Attack Surface Summary for {target}",
        "=" * 43,
        f"Subdomains: {len(subdomains)}",
        f"Live Hosts: {len(live)}",
        f"URLs:       {len(urls)}",
        f"Nuclei hits: {len(findings)}",
        "",
        "Ranked hosts:",
    ]
    for h in ranked[:25]:
        if h in live:
            m = meta.get(h) or {}
            tech = ",".join(m.get("tech") or [])[:28]
            status = m.get("status_code")
            title = (m.get("title") or "")[:32]
            lines.append(
                f"  [LIVE] {h}  [{status}] {title} {('<' + tech + '>') if tech else ''}"
                f"  ({url_count.get(h, 0)} urls)"
            )
        else:
            lines.append(f"  [----] {h}  ({url_count.get(h, 0)} urls)")
    if len(ranked) > 25:
        lines.append(f"  ... and {len(ranked) - 25} more")

    if findings:
        lines += ["", "Nuclei findings:"]
        for f in findings[:10]:
            lines.append(f"  - {f[:110]}")

    lines += ["", f"Tools used:    {', '.join(used) if used else '(none)'}"]
    if missing:
        lines.append(f"Tools missing: {', '.join(missing)}")
    lines.append(f"Generated at:  {recon.get('generated_at', 'n/a')}")
    return "\n".join(lines)
