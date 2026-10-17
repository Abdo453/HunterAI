"""WhatWeb Technology Fingerprinting — L3 Context Intelligence + L4 Adaptive Advisor"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.whatweb.schemas import WhatWebAssetRecord

log = logging.getLogger("whatweb.context")

# خرائط teknik → اقتراحات فحص مكملة (بدون تأكيد تلقائي)
TECH_ADVICE: Dict[str, List[str]] = {
    "wordpress": [
        "wpscan --url {url} --enumerate vp,vt,tt,u",
        "nuclei -u {url} -t wordpress/",
    ],
    "drupal": ["nuclei -u {url} -t drupal/"],
    "joomla": ["nuclei -u {url} -t joomla/"],
    "apache": ["nuclei -u {url} -t http/"],
    "nginx": ["nuclei -u {url} -t http/"],
    "iis": ["nuclei -u {url} -t http/iis/"],
    "php": ["nuclei -u {url} -t exposed-panels/"],
    "python": ["nuclei -u {url} -t exposed-panels/"],
    "node.js": ["nuclei -u {url} -t exposed-panels/"],
    "jquery": ["nuclei -u {url} -t vulnerabilities/"],
    "bootstrap": ["nuclei -u {url} -t vulnerabilities/"],
}


class ContextEnricher:
    """L3: يضيف سياقًا لكل بصمة تقنية مكتشفة."""

    def enrich(self, record: WhatWebAssetRecord) -> Dict[str, Any]:
        techs = [t.lower() for t in record.technologies]
        context: Dict[str, Any] = {
            "cms": None,
            "web_server": None,
            "javascript_libraries": [],
            "is_cms": False,
            "is_ecommerce": False,
            "attack_surface": [],
            "notes": [],
        }

        # CMS Detection
        for cms in ("wordpress", "drupal", "joomla", "magento", "prestashop"):
            if any(cms in t for t in techs):
                context["cms"] = cms
                context["is_cms"] = True
                context["notes"].append(f"نظام إدارة محتوى مكتشف: {cms}")
                break

        # خادم الويب
        if record.server:
            server_l = record.server.lower()
            for ws in ("apache", "nginx", "iis", "litespeed", "openresty"):
                if ws in server_l:
                    context["web_server"] = ws
                    break
            if not context["web_server"]:
                context["web_server"] = record.server

        # مكتبات جافاسكريبت
        for lib in ("jquery", "bootstrap", "react", "angular", "vue.js", "vue", "lodash"):
            if any(lib in t for t in techs):
                context["javascript_libraries"].append(lib)

        if context["javascript_libraries"]:
            context["notes"].append(
                "مكتبات واجهة أمامية: " + ", ".join(context["javascript_libraries"])
            )

        # سطح الهجوم التقريبي
        if record.http_status == 200:
            context["attack_surface"].append("http_endpoint")
        if context["is_cms"]:
            context["attack_surface"].append("cms_admin")
            context["is_ecommerce"] = context["cms"] in ("magento", "prestashop")
        if record.plugins:
            context["attack_surface"].append("technology_fingerprint")

        return context


class AdaptiveTestAdvisor:
    """L4: يقترح خطوات الفحص التالية بناءً على التقنيات المكتشفة."""

    def advise(
        self,
        record: WhatWebAssetRecord,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        context = context or {}
        url = record.url
        suggestions: List[str] = []

        # nuclei على الهدف دائمًا
        suggestions.append(f"nuclei -u {url}")

        cms = context.get("cms")
        if cms and cms in TECH_ADVICE:
            for tmpl in TECH_ADVICE[cms]:
                suggestions.append(tmpl.format(url=url))

        # الإضافات الخاصة بالخادم
        ws = context.get("web_server")
        if ws and ws in TECH_ADVICE:
            for tmpl in TECH_ADVICE[ws]:
                suggestions.append(tmpl.format(url=url))

        # تقنيات عامة
        techs = [t.lower() for t in record.technologies]
        for tech, tmpls in TECH_ADVICE.items():
            if any(tech in t for t in techs) and tech not in (cms, ws):
                suggestions.append(tmpls[0].format(url=url))

        seen: set = set()
        unique: List[str] = []
        for s in suggestions:
            if s not in seen:
                seen.add(s)
                unique.append(s)
        return unique[:8]
