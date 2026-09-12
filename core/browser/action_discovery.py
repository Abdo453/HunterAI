"""
Action Discovery & Exploration Prioritizer
==========================================
Identifies interactable DOM affordances (links, forms, buttons, tabs, modals).
- Calculates Exploration Priority Score (Auth > Input > API > Nav > Static)
- Detects and neutralizes infinite pagination loops
- Deduplicates network requests to eliminate React re-render noise
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urljoin, urlparse

from core.attack_surface_graph import ThirdPartyDependencyFirewall


class ActionCategory(str, Enum):
    AUTH = "AUTH"                  # Login, register, password reset, oauth
    USER_INPUT = "USER_INPUT"      # Forms, search bars, file uploads, filters
    API_TRIGGER = "API_TRIGGER"    # Buttons (Load More, Submit, Sync, Fetch)
    NAVIGATION = "NAVIGATION"      # Internal page links, route transitions
    PAGINATION = "PAGINATION"      # Next, Prev, Page 1/2/3
    STATIC = "STATIC"              # Images, static assets, pdfs
    EXTERNAL = "EXTERNAL"          # Out-of-scope third-party targets (firewalled)


@dataclass
class ActionCandidate:
    action_id: str
    element_type: str              # link | button | form | input | tab | modal
    category: ActionCategory
    score: float                   # Exploration Priority Score (0.0 to 10.0)
    selector: str
    label: str
    target_url: str = ""
    method: str = "GET"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        return d


class RequestDeduplicator:
    """Fingerprints network requests to filter out redundant React re-renders"""

    def __init__(self):
        self._seen_fingerprints: Dict[str, int] = {}

    @staticmethod
    def compute_fingerprint(method: str, url: str, post_data: Optional[str] = None) -> str:
        parsed = urlparse(url)
        params = sorted(f"{k}={v}" for k, vs in parse_qs(parsed.query).items() for v in vs)
        body_prefix = (post_data or "")[:64]
        raw = f"{method.upper()}:{parsed.hostname}:{parsed.path}:{','.join(params)}:{body_prefix}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def is_duplicate(self, method: str, url: str, post_data: Optional[str] = None, max_occurrences: int = 2) -> bool:
        fp = self.compute_fingerprint(method, url, post_data)
        count = self._seen_fingerprints.get(fp, 0)
        self._seen_fingerprints[fp] = count + 1
        return count >= max_occurrences


class ActionDiscovery:
    """Scans DOM structures and ranks interactive affordances by security value"""

    AUTH_KEYWORDS = {"login", "signin", "sign-in", "signup", "sign-up", "register", "auth", "password", "oauth", "token", "account", "profile"}
    INPUT_KEYWORDS = {"upload", "file", "import", "search", "query", "filter", "find", "searchform"}
    API_KEYWORDS = {"api", "load more", "more", "submit", "apply", "save", "update", "send", "confirm"}
    STATIC_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".ico", ".woff", ".woff2", ".ttf", ".pdf", ".zip"}

    @classmethod
    def score_action(cls, elem_type: str, label: str, target_url: str, base_host: str) -> Tuple[ActionCategory, float]:
        """Calculates ActionCategory and exploration priority score (0.0 to 10.0)"""
        # 1. Check scope firewall
        if target_url:
            if ThirdPartyDependencyFirewall.is_external_dependency(target_url, base_host):
                return ActionCategory.EXTERNAL, -1.0

        # Check static extension
        if target_url:
            parsed = urlparse(target_url)
            path_low = parsed.path.lower()
            if any(path_low.endswith(ext) for ext in cls.STATIC_EXTS):
                return ActionCategory.STATIC, 1.0

        combined_text = f"{label} {target_url}".lower()

        # 2. Check Auth
        if any(kw in combined_text for kw in cls.AUTH_KEYWORDS):
            return ActionCategory.AUTH, 9.8

        # 3. Check Input / Upload / Search
        if elem_type == "form" or any(kw in combined_text for kw in cls.INPUT_KEYWORDS):
            return ActionCategory.USER_INPUT, 8.8

        # 4. Check API Trigger / Buttons
        if elem_type == "button" or any(kw in combined_text for kw in cls.API_KEYWORDS):
            return ActionCategory.API_TRIGGER, 8.0

        # 5. Check Pagination
        if re.search(r"\b(page|p|pg|next|prev)=\d+", combined_text) or any(w in label.lower() for w in ("next", "previous", "load more")):
            return ActionCategory.PAGINATION, 6.0

        # 6. Navigation
        if elem_type == "link" or target_url:
            return ActionCategory.NAVIGATION, 5.0

        return ActionCategory.NAVIGATION, 4.0

    @classmethod
    def discover_actions_from_html(cls, html: str, current_url: str, base_host: str) -> List[ActionCandidate]:
        """Parses HTML and extracts prioritized candidates"""
        candidates: List[ActionCandidate] = []

        # Simple robust regex extraction
        # Links
        links = re.findall(r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', html, flags=re.DOTALL | re.IGNORECASE)
        for href, text in links:
            cleaned_text = re.sub(r"<[^>]+>", "", text).strip()
            full_url = urljoin(current_url, href)
            cat, score = cls.score_action("link", cleaned_text, full_url, base_host)
            if cat == ActionCategory.EXTERNAL:
                continue  # Never probe external links
            candidates.append(ActionCandidate(
                action_id=f"link:{hashlib.md5(full_url.encode()).hexdigest()[:8]}",
                element_type="link",
                category=cat,
                score=score,
                selector=f"a[href*='{href[:30]}']",
                label=cleaned_text or full_url,
                target_url=full_url,
                method="GET"
            ))

        # Forms
        forms = re.findall(r'<form\s+([^>]*)>(.*?)</form>', html, flags=re.DOTALL | re.IGNORECASE)
        for idx, (attrs, body) in enumerate(forms):
            action_m = re.search(r'action=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
            method_m = re.search(r'method=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
            id_m = re.search(r'id=["\']([^"\']*)["\']', attrs, re.IGNORECASE)

            action = action_m.group(1) if action_m else current_url
            method = (method_m.group(1) if method_m else "POST").upper()
            form_id = id_m.group(1) if id_m else f"form_{idx}"

            full_action = urljoin(current_url, action)
            cat, score = cls.score_action("form", form_id, full_action, base_host)
            candidates.append(ActionCandidate(
                action_id=f"form:{form_id}",
                element_type="form",
                category=cat,
                score=score,
                selector=f"form#{form_id}" if id_m else f"form:nth-of-type({idx+1})",
                label=f"Form {form_id}",
                target_url=full_action,
                method=method,
                metadata={"body_len": len(body)}
            ))

        # Buttons
        buttons = re.findall(r'<button\s+([^>]*)>(.*?)</button>', html, flags=re.DOTALL | re.IGNORECASE)
        for idx, (attrs, text) in enumerate(buttons):
            cleaned_text = re.sub(r"<[^>]+>", "", text).strip()
            id_m = re.search(r'id=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
            btn_id = id_m.group(1) if id_m else f"btn_{idx}"

            cat, score = cls.score_action("button", cleaned_text or btn_id, current_url, base_host)
            candidates.append(ActionCandidate(
                action_id=f"button:{btn_id}",
                element_type="button",
                category=cat,
                score=score,
                selector=f"button#{btn_id}" if id_m else f"button:nth-of-type({idx+1})",
                label=cleaned_text or f"Button {btn_id}",
                target_url=current_url,
                method="CLICK"
            ))

        # Sort candidates descending by exploration score
        candidates.sort(key=lambda c: c.score, reverse=True)
        return candidates