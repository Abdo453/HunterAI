"""
Unified Skill Registry & Auto-Router
====================================
مركز تسجيل موحد لكل مهارات الثغرات مع توجيه تلقائي ذكي:

- Auto-Discovery: أي Skill ترث BaseSkill وتُسجَّل عبر @register تُضاف تلقائياً
- Auto-Routing: يوجّه كل بارامتر للمهارة الأعلى ملاءمة عبر can_handle()
- Evidence Contract: كل نتيجة تمر عبر SkillResult موحد (متوافق مع Evidence Court)

Usage:
    registry = SkillRegistry.instance()
    registry.register_class(CORSSkill)
    ranked = registry.rank_params_for_skill("sqli", param_records)
    results = await registry.run_skill_for_param("xss", url, param)
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Type, TYPE_CHECKING

if TYPE_CHECKING:
    from agents.skills.base_skill import BaseSkill, SkillResult

logger = logging.getLogger(__name__)


@dataclass
class SkillMeta:
    """بيانات وصفية لمهارة مسجّلة"""
    cls: Type["BaseSkill"]
    name: str
    vuln_type: str
    cwe: str
    owasp_top10: str
    default_severity: str
    # كلمات مفتاحية للبارامترات المحققة — تُستخدم كـ fallback لو can_handle ضعيفة
    param_keywords: List[str] = field(default_factory=list)

    def create(self, proxy: Optional[str] = None, **kwargs) -> "BaseSkill":
        """إنشاء instance دفاعياً — يدعم مهارات قديمة بأنماط بناء مختلفة"""
        try:
            return self.cls(proxy=proxy, **kwargs)  # type: ignore[call-arg]
        except (TypeError, AttributeError):
            try:
                return self.cls(timeout=kwargs.get("timeout", 12.0))  # type: ignore[call-arg]
            except Exception:
                return self.cls()  # type: ignore[call-arg]


class LegacyResultAdapter:
    """
    محوّل شكلي — يلفّ التُنديس الرجعي للمهارات القديمة التي تُرجع dict
    بحيث تحترم عقد SkillResult الموحد (verified / logs / to_dict)
    """
    def __init__(self, raw: Dict[str, Any]) -> None:
        self.raw = raw if isinstance(raw, dict) else {}

    @property
    def verified(self) -> bool:
        return bool(self.raw.get("verified", False))

    @property
    def logs(self) -> List[str]:
        v = self.raw.get("logs", [])
        return v if isinstance(v, list) else [str(v)]

    @property
    def title(self) -> str:
        return str(self.raw.get("title", ""))

    @property
    def evidence(self) -> str:
        return str(self.raw.get("evidence", ""))

    def to_dict(self) -> Dict[str, Any]:
        return self.raw


class SkillRegistry:
    """
    Registry موحد لكل مهارات الثغرات.
    - instance(): Singleton
    - register_class(cls): تسجيل مهارة (تُستخدم كديكوريتر أيضاً)
    - best_for(param_name, ...): أفضل مهارة لبارامتر معين
    - rank(rankable): قائمة مرتبة بالملاءمة
    - run_best(url, param): تشغيل أفضل مهارة وإرجاع SkillResult
    """
    _instance: Optional["SkillRegistry"] = None

    def __init__(self) -> None:
        self._skills: Dict[str, SkillMeta] = {}

    # ─── Singleton ────────────────────────────────────────────────────────
    @classmethod
    def instance(cls) -> "SkillRegistry":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """للاختبارات فقط — يعيد ضبط الـ Singleton"""
        cls._instance = None

    # ─── Registration ─────────────────────────────────────────────────────
    def register_class(self, cls: Type["BaseSkill"], param_keywords: Optional[List[str]] = None,
                       meta_overrides: Optional[Dict[str, str]] = None) -> Optional[SkillMeta]:
        """تسجيل دفاعي — يدعم مهارات قديمة لا ترث BaseSkill ولا تعرف can_handle"""
        if cls is None or not hasattr(cls, "run"):
            logger.warning(f"Skipping {getattr(cls, '__name__', cls)} — no run() method")
            return None

        name = getattr(cls, "name", None) or cls.__name__
        if name in self._skills:
            return self._skills[name]

        overrides = meta_overrides or {}
        meta = SkillMeta(
            cls=cls,
            name=name,
            vuln_type=overrides.get("vuln_type", getattr(cls, "vuln_type", "unknown")),
            cwe=overrides.get("cwe", getattr(cls, "cwe", "CWE-000")),
            owasp_top10=overrides.get("owasp_top10", getattr(cls, "owasp_top10", "A00:2021")),
            default_severity=overrides.get("default_severity", getattr(cls, "default_severity", "Medium")),
            param_keywords=param_keywords or [],
        )
        self._skills[name] = meta
        return meta

    def register(self, param_keywords: Optional[List[str]] = None):
        """ديكوريتر: @SkillRegistry.instance().register(param_keywords=[...])"""
        def decorator(cls: Type["BaseSkill"]) -> Type["BaseSkill"]:
            self.register_class(cls, param_keywords=param_keywords)
            return cls
        return decorator

    # ─── Lookup ───────────────────────────────────────────────────────────
    def get(self, name: str) -> Optional[SkillMeta]:
        return self._skills.get(name)

    def by_vuln_type(self, vuln_type: str) -> List[SkillMeta]:
        return [m for m in self._skills.values() if m.vuln_type == vuln_type]

    def all_skills(self) -> List[SkillMeta]:
        return list(self._skills.values())

    def __len__(self) -> int:
        return len(self._skills)

    def __contains__(self, name: str) -> bool:
        return name in self._skills

    # ─── Auto-Routing ─────────────────────────────────────────────────────
    def score_skill(self, meta: SkillMeta, param_name: str, url: str = "", sample_value: str = "") -> float:
        """
        درجة ملاءمة موحدة:
        - can_handle + تعزيز مسجّل إذا ضربت الكلمات المفتاحية
        - تخميد 30% عند غياب دليل الكلمات المفتاحية (يمنع المهارات الفضفاضة من اصطيادكل بارامتر)
        """
        probe = meta.cls()
        base = 0.0
        try:
            base = float(probe.can_handle(param_name, url=url, sample_value=sample_value) or 0.0)
        except Exception:
            logger.debug(f"can_handle failed for {meta.name}", exc_info=True)

        if meta.param_keywords:
            p = param_name.lower()
            # تجاهل الكلمات القصيرة جداً (حرف واحد) — substring match لها يلتقط أي بارامتر
            meaningful = [kw for kw in meta.param_keywords if len(kw) >= 2]
            if meaningful and any(kw in p for kw in meaningful):
                return min(max(base, 0.85), 1.0)
        # لا دليل كلمات — خفّض للتصنيف المحافظ
        return min(base * 0.7, 1.0)

    def best_for(self, param_name: str, url: str = "", sample_value: str = "",
                 min_score: float = 0.5) -> Optional[SkillMeta]:
        """أفضل مهارة لبارامتر — None لو لا توجد مهارة فوق الحد الأدنى"""
        ranked = self.rank(param_name, url=url, sample_value=sample_value)
        if ranked and ranked[0][1] >= min_score:
            return ranked[0][0]
        return None

    def rank(self, param_name: str, url: str = "", sample_value: str = "") -> List[tuple]:
        """قائمة (SkillMeta, score) مرتبة تنازلياً"""
        scored = [
            (meta, self.score_skill(meta, param_name, url=url, sample_value=sample_value))
            for meta in self._skills.values()
        ]
        scored.sort(key=lambda t: t[1], reverse=True)
        return [t for t in scored if t[1] > 0.0]

    # ─── Execution ────────────────────────────────────────────────────────
    async def run_skill(self, meta: SkillMeta, target_url: str, param_name: str,
                        proxy: Optional[str] = None, **kwargs) -> Optional["SkillResult"]:
        """تشغيل مهارة واحدة مع عزل الأخطاء — يدعم SkillResult و legacy dict outputs"""
        try:
            skill = meta.create(proxy=proxy)
            result = skill.run(target_url, param_name, **kwargs)
            if asyncio.iscoroutine(result):
                result = await result
            # توحيد النتائج القديمة (dict) داخل عقد SkillResult
            if isinstance(result, dict):
                return LegacyResultAdapter(result)
            return result
        except Exception:
            logger.exception(f"Skill {meta.name} failed on {param_name}")
            return None

    async def run_best(self, target_url: str, param_name: str,
                       proxy: Optional[str] = None, min_score: float = 0.5,
                       try_fallbacks: bool = True, **kwargs) -> Optional["SkillResult"]:
        """تشغيل أفضل مهارة — ولو فشلت بدون verified نجرب التالية حسب الترتيب"""
        ranked = self.rank(param_name, url=target_url)
        best_result: Optional["SkillResult"] = None
        for meta, score in ranked[:3 if try_fallbacks else 1]:
            if score < min_score:
                break
            result = await self.run_skill(meta, target_url, param_name, proxy=proxy, **kwargs)
            if result is None:
                continue
            if result.verified:
                return result
            if best_result is None:
                best_result = result
        return best_result

    async def run_all_for_param(self, target_url: str, param_name: str,
                                proxy: Optional[str] = None, min_score: float = 0.5,
                                concurrency: int = 3) -> List["SkillResult"]:
        """تشغيل كل المهارات الملائمة لبارامتر (للـ deep scan)"""
        ranked = [m for m, s in self.rank(param_name, url=target_url) if s >= min_score]
        sem = asyncio.Semaphore(max(1, concurrency))

        async def guarded(m: SkillMeta) -> Optional["SkillResult"]:
            async with sem:
                return await self.run_skill(m, target_url, param_name, proxy=proxy)

        results = await asyncio.gather(*(guarded(m) for m in ranked))
        return [r for r in results if r is not None]

    # ─── Reporting ────────────────────────────────────────────────────────
    def matrix(self) -> Dict[str, Dict[str, Any]]:
        """خريطة كل المهارات المسجلة (للـ dashboard والتقارير)"""
        return {
            m.name: {
                "vuln_type": m.vuln_type,
                "cwe": m.cwe,
                "owasp_top10": m.owasp_top10,
                "default_severity": m.default_severity,
                "param_keywords": m.param_keywords,
            }
            for m in self._skills.values()
        }


# ─── Bootstrap: تسجيل كل المهارات المدمجة ────────────────────────────────────
def bootstrap_builtin_skills() -> SkillRegistry:
    """يسجل كل مهارات النظام المدمجة في الـ Registry ويعيده"""
    from agents.skills.sqli_skill import SQLiSkill
    from agents.skills.ssrf_skill import SSRFSkill
    from agents.skills.idor_skill import IDORSkill, IDORMatrixSkill
    from agents.skills.xss_skill import XSSSkill
    from agents.skills.ssti_skill import SSTISkill
    from agents.skills.xxe_skill import XXESkill
    from agents.skills.cors_skill import CORSSkill
    from agents.skills.file_upload_skill import FileUploadSkill
    from agents.skills.jwt_oauth_skill import JWTOAuthSkill
    from agents.skills.race_condition_skill import RaceConditionSkill
    from agents.skills.graphql_skill import GraphQLSkill
    from agents.skills.websocket_skill import WebSocketSkill
    from agents.skills.lfi_skill import LFISkill
    from agents.skills.cmd_injection_skill import CmdInjectionSkill
    from agents.skills.csrf_skill import CSRFSkill

    # مهارات جديدة
    from agents.skills.open_redirect_skill import OpenRedirectSkill
    from agents.skills.host_header_injection_skill import HostHeaderInjectionSkill
    from agents.skills.nosql_injection_skill import NoSQLInjectionSkill
    from agents.skills.crlf_injection_skill import CRLFSkill
    from agents.skills.hpp_skill import HTTPParameterPollutionSkill
    from agents.skills.ldap_injection_skill import LDAPInjectionSkill

    reg = SkillRegistry.instance()
    # — المهارات القديمة (كلاسات عادية) تحصل على metadata صريح عبر overrides —
    reg.register_class(SQLiSkill,   param_keywords=["id", "q", "search", "query", "user", "sort", "order", "filter"],
                       meta_overrides={"vuln_type": "sqli", "cwe": "CWE-89", "owasp_top10": "A03:2021", "default_severity": "Critical"})
    reg.register_class(XSSSkill,    param_keywords=["q", "search", "msg", "comment", "name", "content", "text"],
                       meta_overrides={"vuln_type": "xss", "cwe": "CWE-79", "owasp_top10": "A03:2021", "default_severity": "High"})
    reg.register_class(IDORSkill,   param_keywords=["id", "user_id", "account_id", "doc_id", "order_id", "uid"],
                       meta_overrides={"vuln_type": "idor", "cwe": "CWE-639", "owasp_top10": "A01:2021", "default_severity": "High"})
    reg.register_class(SSRFSkill,       param_keywords=["url", "uri", "redirect", "dest", "target", "fetch", "proxy", "src"])
    reg.register_class(IDORMatrixSkill, param_keywords=["id", "user_id", "account_id"])
    reg.register_class(SSTISkill,       param_keywords=["template", "name", "preview", "render", "view", "tpl"])
    reg.register_class(XXESkill,        param_keywords=["xml", "xmlrpc", "soap", "data"])
    reg.register_class(CORSSkill,       param_keywords=["origin"])
    reg.register_class(FileUploadSkill, param_keywords=["file", "upload", "attachment", "image", "doc"])
    reg.register_class(JWTOAuthSkill,   param_keywords=["token", "jwt", "access_token", "refresh_token"])
    reg.register_class(RaceConditionSkill, param_keywords=["coupon", "voucher", "balance", "withdraw"])
    reg.register_class(GraphQLSkill,    param_keywords=["query", "operation", "variables"])
    reg.register_class(WebSocketSkill,  param_keywords=[])
    reg.register_class(LFISkill,        param_keywords=["file", "path", "page", "doc", "include", "view", "lang"])
    reg.register_class(CmdInjectionSkill, param_keywords=["cmd", "exec", "ping", "host", "ip", "command", "dir"])
    reg.register_class(CSRFSkill,       param_keywords=[])

    reg.register_class(OpenRedirectSkill,       param_keywords=["redirect", "url", "next", "dest", "goto", "return", "returnTo", "r", "u"])
    reg.register_class(HostHeaderInjectionSkill, param_keywords=["host", "x-forwarded", "site", "domain"])
    reg.register_class(NoSQLInjectionSkill,     param_keywords=["user", "email", "login", "username", "pass", "q"])
    reg.register_class(CRLFSkill,               param_keywords=["url", "next", "redirect", "path", "lang", "page"])
    reg.register_class(HTTPParameterPollutionSkill, param_keywords=["id", "price", "amount", "qty", "user_id"])
    reg.register_class(LDAPInjectionSkill,      param_keywords=["user", "search", "filter", "dn", "cn", "uid", "mail"])

    # مهارات المتصفح (Browser Skills) — محوّلات لواجهة `execute(ctx)` من skills/ pipeline
    from agents.skills.browser_adapter_skills import (
        BrowserReconAdapterSkill,
        FormIntelligenceAdapterSkill,
        NetworkIntelligenceAdapterSkill,
        BehaviorAnalysisAdapterSkill,
        BrowserSensorAdapterSkill,
    )
    reg.register_class(BrowserReconAdapterSkill,       param_keywords=[],
                       meta_overrides={"program_level": True})
    reg.register_class(FormIntelligenceAdapterSkill,   param_keywords=[],
                       meta_overrides={"program_level": True})
    reg.register_class(NetworkIntelligenceAdapterSkill,param_keywords=[],
                       meta_overrides={"program_level": True})
    reg.register_class(BehaviorAnalysisAdapterSkill,   param_keywords=[],
                       meta_overrides={"program_level": True})
    reg.register_class(BrowserSensorAdapterSkill,      param_keywords=[],
                       meta_overrides={"program_level": True})

    # مهارة مستوى البرنامج (bug bounty كاملة) — خارج التوجيه التلقائي (can_handle=0)
    from agents.skills.bug_bounty_master_skill import BugBountyMasterSkill
    reg.register_class(BugBountyMasterSkill, param_keywords=[],
                       meta_overrides={"vuln_type": "bug_bounty_pipeline", "cwe": "CWE-000",
                                       "owasp_top10": "A00:2021", "default_severity": "Info",
                                       "program_level": True})

    # مهارة ثغرات الجلسات (Session Flaws — CWE-613)
    from agents.skills.session_flaws_skill import SessionFlawsSkill
    reg.register_class(SessionFlawsSkill, param_keywords=["session", "sess", "sessionid", "jsessionid",
                                                          "phpsessid", "auth", "token", "cfid", "cftoken"])

    return reg


if __name__ == "__main__":
    import sys
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    reg = bootstrap_builtin_skills()
    print(f"[OK] Registered {len(reg)} skills:")
    for meta in sorted(reg.all_skills(), key=lambda m: m.vuln_type):
        print(f"  * {meta.name:34s} {meta.vuln_type:24s} {meta.cwe}")
