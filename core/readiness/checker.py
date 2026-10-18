"""
Unified Readiness Checker (Phase 1 — تثبيت الأساس)
==================================================
مصدر حقيقة واحد لجاهزية البيئة قبل بدء أي مهمة:

  - أدوات Kali المطلوبة  (probe محلي --version/--help — من scripts.verify_kali_toolchain)
  - Ollama والنماذج      (/tcp + /api/tags)
  - Burp Proxy            (TCP connect)
  - Burp Gateway          (TCP connect)
  - Playwright وChromium  (استيراد + مسار التنفيذي موجود فعلاً)
  - SecLists / wordlists  (resolve فعلي للملف و existence)

القانون:
  1. لا يوجد "READY" بدون إثبات محلي (probe/مسار/اتصال/tcp ناجح) — لا ادعاءات.
  2. فشل مكون واحد لا يُسقط بقية التقرير؛ كل فحص معزول try/except.
  3. strict gate: عنصر required ليس READY → المهمة محظورة (ReadinessGateError).
  4. التقرير نفسه Artifact يُحفظ لكل جلسة ويمكن تدقيقه لاحقًا.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import subprocess
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

log = logging.getLogger("hunter_ai.readiness")


class ComponentStatus(str, Enum):
    READY = "READY"
    MISSING = "MISSING"
    UNHEALTHY = "UNHEALTHY"
    SKIPPED = "SKIPPED"


class ReadinessGateError(RuntimeError):
    """تُرفع عندما يمنع الـ strict gate بدء المهمة بسبب عنصر أساسي غير جاهز."""

    def __init__(self, report: "ReadinessReport", blocked: List["ComponentResult"]):
        names = ", ".join(f"{r.name}({r.status})" for r in blocked)
        super().__init__(
            f"Readiness gate failed — عناصر أساسية غير جاهزة: {names}. "
            f"لم تبدأ المهمة (strict mode)."
        )
        self.report = report
        self.blocked = blocked


@dataclass
class ComponentResult:
    """نتيجة فحص عنصر واحد — كل نتيجة تحمل إثباتها المحلي."""
    component: str            # kali_tool | ollama | ollama_model | burp_proxy | burp_gateway | playwright | wordlists
    name: str
    status: ComponentStatus
    required: bool = True
    detail: str = ""
    probe: str = ""           # الأمر/الprobe الذي أنتج الإثبات
    evidence: Dict[str, Any] = field(default_factory=dict)
    checked_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


@dataclass
class ReadinessReport:
    target: str
    session_id: str
    results: List[ComponentResult] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    duration_sec: float = 0.0
    strict: bool = True
    safe_check: str = "Local probes only (--version/--help, TCP connect, file existence). لامس أي هدف."

    # ─── aggregate ──────────────────────────────────────────────────────
    @property
    def blocked(self) -> List[ComponentResult]:
        return [r for r in self.results if r.required and r.status is not ComponentStatus.READY]

    @property
    def strict_ready(self) -> bool:
        return not self.blocked

    def counts(self) -> Dict[str, int]:
        return {
            s.value: sum(1 for r in self.results if r.status is s)
            for s in ComponentStatus
        }

    def for_component(self, component: str) -> List[ComponentResult]:
        return [r for r in self.results if r.component == component]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "session_id": self.session_id,
            "started_at": self.started_at,
            "duration_sec": round(self.duration_sec, 2),
            "strict": self.strict,
            "strict_ready": self.strict_ready,
            "safe_check": self.safe_check,
            "counts": self.counts(),
            "blocked": [r.to_dict() for r in self.blocked],
            "results": [r.to_dict() for r in self.results],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


class ReadinessChecker:
    """
    فاحص جاهزية موحّد. كل فحص منفصل وقابل للحقن (injection points للتحكيم
    في الاختبارات: _tcp_ready / _ollama_tags / _playwright_state).
    """

    def __init__(
        self,
        kali_timeout: float = 6.0,
        tls_timeout: float = 0.8,
        burp_proxy: str = "127.0.0.1",
        burp_proxy_port: int = 8080,
        gateway_host: str = "127.0.0.1",
        gateway_port: int = 8085,
        ollama_host: Optional[str] = None,
        config_path: Path = Path("config/tools.yaml"),
        manifest_path: Path = Path("environment/manifest.json"),
        env_path: Path = Path(".env"),
        wordlist_categories: tuple = ("directories", "subdomains", "parameters"),
    ):
        self.kali_timeout = kali_timeout
        self.tcp_timeout = tls_timeout
        self.burp_proxy = (burp_proxy, burp_proxy_port)
        self.gateway = (gateway_host, gateway_port)
        self.config_path = Path(config_path)
        self.manifest_path = Path(manifest_path)
        self.env_path = Path(env_path)
        self.wordlist_categories = wordlist_categories
        self.ollama_host = ollama_host or self._load_env_host()

    # ─── إعدادات ────────────────────────────────────────────────────────
    def _load_env_host(self) -> str:
        if self.env_path.exists():
            for line in self.env_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line.startswith("OLLAMA_HOST="):
                    return line.split("=", 1)[1].strip().strip('"')
        return os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")

    # ─── 1) أدوات Kali ──────────────────────────────────────────────────
    async def check_kali_tools(
        self,
        configured: Optional[Dict[str, Any]] = None,
        required: Optional[List[str]] = None,
    ) -> List[ComponentResult]:
        """probe محلي لكل أداة مُعدّة في config/tools.yaml (أو configured المُمررة)."""
        from scripts.verify_kali_toolchain import probe, ROOT  # إعادة استخدام الدالة المُختبرة

        if configured is None:
            import yaml
            configured = {}
            if self.config_path.exists():
                configured = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}
        if required is None:
            required = []
            if self.manifest_path.exists():
                try:
                    required = json.loads(
                        self.manifest_path.read_text(encoding="utf-8")
                    ).get("required_kali_tools", [])
                except Exception:
                    required = []

        results: List[ComponentResult] = []
        for category, entries in configured.items():
            if not isinstance(entries, dict):
                continue
            for name, spec in entries.items():
                if not isinstance(spec, dict) or "cmd" not in spec:
                    continue
                cmd = str(spec["cmd"])
                is_required = name in required
                # البروب محلي فقط — لا اتصال بأي هدف
                probe_result = await asyncio.to_thread(probe, cmd, self.kali_timeout)
                ev = {"binary": probe_result.get("path"), "platform_root": str(ROOT)}
                status = ComponentStatus(probe_result["status"])
                results.append(ComponentResult(
                    component="kali_tool", name=name, status=status,
                    required=is_required, detail=probe_result.get("detail", ""),
                    probe=f"{cmd} --version/--help", evidence=ev,
                ))
        return results

    # ─── 2) Ollama + النماذج ───────────────────────────────────────────
    @staticmethod
    def _connectable_host(host: str) -> str:
        """
        OLLAMA_HOST كثيرًا ما يُضبط بـ 0.0.0.0 (عنوان ربط/Listen) —
        كعنوان اتصال على Windows يفشل دائمًا. نحوّله لـ 127.0.0.1 للـ probe
        مع الحفاظ على القيمة الأصلية في التقرير.
        """
        from urllib.parse import urlparse, urlunparse
        try:
            parts = urlparse(host if "://" in host else f"http://{host}")
            if parts.hostname in ("0.0.0.0", "::", "[::]"):
                netloc = f"127.0.0.1:{parts.port}" if parts.port else "127.0.0.1"
                fixed = urlunparse(parts._replace(netloc=netloc))
                return fixed
        except Exception:
            pass
        return host

    async def _ollama_tags(self, host: str) -> Optional[List[str]]:
        """يجلب أسماء النماذج من /api/tags — None = الخادم لا يستجيب."""
        probe_host = self._connectable_host(host)
        try:
            import httpx
            async with httpx.AsyncClient(timeout=2.5, trust_env=False) as client:
                r = await client.get(f"{probe_host}/api/tags")
                if r.status_code != 200:
                    return None
                data = r.json()
                return [m.get("name", "") for m in data.get("models", [])]
        except Exception:
            return None

    async def check_ollama(
        self,
        expected_models: Optional[List[str]] = None,
        host: Optional[str] = None,
    ) -> List[ComponentResult]:
        host = host or self.ollama_host
        probe_host = self._connectable_host(host)
        if expected_models is None:
            expected_models = []
            if self.manifest_path.exists():
                try:
                    expected_models = (json.loads(
                        self.manifest_path.read_text(encoding="utf-8")
                    ).get("components", {}).get("ollama", {}).get("expected_models", []))
                except Exception:
                    expected_models = []

        results: List[ComponentResult] = []
        available = await self._ollama_tags(host)
        if available is None:
            results.append(ComponentResult(
                component="ollama", name="ollama_server",
                status=ComponentStatus.UNHEALTHY, required=True,
                detail=f"Ollama server not reachable at {probe_host} (/api/tags)" +
                       ("" if probe_host == host else f" (configured: {host})"),
                probe=f"GET {probe_host}/api/tags",
                evidence={"configured_host": host, "probed_host": probe_host},
            ))
            # العناصر المتوقعة تُسجّل MISSING لأجل الشفافية
            for model in expected_models:
                results.append(ComponentResult(
                    component="ollama_model", name=model,
                    status=ComponentStatus.MISSING, required=True,
                    detail="server offline — cannot confirm model", probe=f"GET {probe_host}/api/tags",
                ))
            return results

        results.append(ComponentResult(
            component="ollama", name="ollama_server",
            status=ComponentStatus.READY, required=True,
            detail=f"Ollama reachable at {probe_host}, {len(available)} model(s) present",
            probe=f"GET {probe_host}/api/tags",
            evidence={"configured_host": host, "probed_host": probe_host, "models_seen": len(available)},
        ))
        for model in expected_models:
            ok = any(model in a or a.split(":")[0] == model.split(":")[0] for a in available)
            results.append(ComponentResult(
                component="ollama_model", name=model,
                status=ComponentStatus.READY if ok else ComponentStatus.MISSING,
                required=True,
                detail=f"model {'available' if ok else 'NOT PULLED'}",
                probe=f"GET {probe_host}/api/tags",
                evidence={"configured_host": host, "probed_host": probe_host},
            ))
        return results

    # ─── TCP مشترك ──────────────────────────────────────────────────────
    async def _tcp_ready(self, host: str, port: int) -> bool:
        def _connect() -> bool:
            try:
                with socket.create_connection((host, port), timeout=self.tcp_timeout):
                    return True
            except OSError:
                return False
        return await asyncio.to_thread(_connect)

    # ─── 3) Burp Proxy ──────────────────────────────────────────────────
    async def check_burp_proxy(self, host: Optional[str] = None, port: Optional[int] = None) -> ComponentResult:
        host = host or self.burp_proxy[0]
        port = port or self.burp_proxy[1]
        live = await self._tcp_ready(host, port)
        return ComponentResult(
            component="burp_proxy", name=f"burp_proxy@{host}:{port}",
            status=ComponentStatus.READY if live else ComponentStatus.MISSING,
            required=False,   # اختياري — يُفرض فقط في وضع --require-burp-browser
            detail=f"TCP {'accepted' if live else 'refused'} on {host}:{port}",
            probe=f"TCP connect {host}:{port}",
        )

    # ─── 4) Burp Gateway ────────────────────────────────────────────────
    async def check_burp_gateway(self, host: Optional[str] = None, port: Optional[int] = None) -> ComponentResult:
        host = host or self.gateway[0]
        port = port or self.gateway[1]
        live = await self._tcp_ready(host, port)
        return ComponentResult(
            component="burp_gateway", name=f"gateway@{host}:{port}",
            status=ComponentStatus.READY if live else ComponentStatus.SKIPPED,
            required=False,   # غالبًا اختياري؛ يُفرض عند --require-burp-browser
            detail=f"TCP {'accepted' if live else 'not listening'} on {host}:{port}",
            probe=f"TCP connect {host}:{port}",
        )

    # ─── 5) Playwright ──────────────────────────────────────────────────
    async def _playwright_state(self) -> Dict[str, Any]:
        """حالة Playwright الفعلية — إثبات مسار Chromium وليس مجرد استيراد."""
        try:
            from core.browser.playwright_controller import PLAYWRIGHT_AVAILABLE
            state = {"available": bool(PLAYWRIGHT_AVAILABLE), "executable": None}
            if state["available"]:
                try:
                    from playwright.async_api import async_playwright
                    pw = await async_playwright().start()
                    try:
                        state["executable"] = pw.chromium.executable_path
                    finally:
                        await pw.stop()
                except Exception as exc:  # الاستيراد نجح لكن المتصفح تعطّل
                    state["available"] = False
                    state["error"] = str(exc)
            return state
        except Exception as exc:
            return {"available": False, "error": str(exc)}

    async def check_playwright(self) -> ComponentResult:
        state = await self._playwright_state()
        executable = state.get("executable")
        # الإثبات المطلوب: مسار Chromium الحقيقي + وجوده على القرص
        exe_ok = (not executable) or Path(str(executable)).is_file()
        chromium_ok = bool(state.get("available")) and exe_ok
        status = ComponentStatus.READY if chromium_ok else ComponentStatus.MISSING
        detail = ("Playwright Chromium ready"
                  + (f" at {executable}" if executable else "")
                  ) if chromium_ok else f"Playwright/Chromium unavailable: {state.get('error', 'not installed')}"
        return ComponentResult(
            component="playwright", name="playwright_chromium",
            status=status, required=False,
            detail=detail,
            probe="import playwright_controller + playwright.chromium.executable_path",
            evidence={"executable": executable, "executable_exists": exe_ok, "state": state},
        )

    # ─── 6) SecLists / wordlists ─────────────────────────────────────────
    async def check_wordlists(self) -> List[ComponentResult]:
        results: List[ComponentResult] = []
        for category in self.wordlist_categories:
            resolved = None
            try:
                from core.wordlist_manager import resolve_wordlist
                resolved = await asyncio.to_thread(resolve_wordlist, category, "standard")
            except Exception as exc:
                results.append(ComponentResult(
                    component="wordlists", name=f"wordlist:{category}",
                    status=ComponentStatus.UNHEALTHY, required=False,
                    detail=f"resolver error: {exc}", probe=f"resolve_wordlist({category},'standard')",
                ))
                continue
            exists = bool(resolved) and os.path.isfile(str(resolved))
            results.append(ComponentResult(
                component="wordlists", name=f"wordlist:{category}",
                status=ComponentStatus.READY if exists else ComponentStatus.MISSING,
                required=False,
                detail=f"resolved to {resolved}" + (" (exists)" if exists else " (file missing)"),
                probe=f"resolve_wordlist({category},'standard')",
                evidence={"path": str(resolved)},
            ))
        return results

    # ─── run all ────────────────────────────────────────────────────────
    async def run_all(
        self,
        target: str = "",
        session_id: str = "",
        strict: bool = True,
        components: Optional[List[str]] = None,
    ) -> ReadinessReport:
        """
        يُجري كل الفحوص (أو المطلوبة فقط عبر components) بمعزل تام
        — فشل أي فحص لا يمنع البقية.
        components: subset من {"kali_tools","ollama","burp_proxy","burp_gateway","playwright","wordlists"}
        """
        started = time.time()
        report = ReadinessReport(target=target, session_id=session_id, strict=strict)
        want = set(components) if components else {
            "kali_tools", "ollama", "burp_proxy", "burp_gateway", "playwright", "wordlists",
        }

        pairs: List[tuple] = []
        if "kali_tools" in want:
            pairs.append(("kali_tools", self.check_kali_tools))
        if "ollama" in want:
            pairs.append(("ollama", self.check_ollama))
        if "burp_proxy" in want:
            pairs.append(("burp_proxy", self.check_burp_proxy))
        if "burp_gateway" in want:
            pairs.append(("burp_gateway", self.check_burp_gateway))
        if "playwright" in want:
            pairs.append(("playwright", self.check_playwright))
        if "wordlists" in want:
            pairs.append(("wordlists", self.check_wordlists))

        for comp_name, check in pairs:
            try:
                out = await check()
                if isinstance(out, ComponentResult):
                    report.results.append(out)
                elif isinstance(out, list):
                    report.results.extend(out)
            except Exception as exc:
                log.exception("[Readiness] فشل فحص %s", comp_name)
                report.results.append(ComponentResult(
                    component=comp_name, name=f"{comp_name}_check_crash",
                    status=ComponentStatus.UNHEALTHY, required=True,
                    detail=f"check crashed: {exc}", probe="isolated",
                ))

        report.duration_sec = time.time() - started
        return report


def enforce_strict(report: ReadinessReport) -> ReadinessReport:
    """بوابة صارمة: عنصر required غير READY → رفع ReadinessGateError."""
    if report.strict_ready:
        return report
    raise ReadinessGateError(report, report.blocked)
