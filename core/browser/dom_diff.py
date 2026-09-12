"""
DOM Diff Engine
================
Computes structural and semantic differences between DOM states:
- Added/Removed forms, inputs, buttons, links, modals, scripts
- Structural hashing for fast state comparison
- Ignores dynamic ephemeral noise (CSRF tokens, dynamic timestamps)
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Set, Tuple
from html.parser import HTMLParser


@dataclass
class DOMElementSummary:
    tag: str
    element_id: str = ""
    name: str = ""
    element_type: str = ""
    classes: str = ""
    text_snippet: str = ""
    action_url: str = ""

    @property
    def identity_key(self) -> str:
        ident = self.element_id or self.name or self.action_url or self.text_snippet[:30]
        return f"{self.tag}:{self.element_type}:{ident}".strip(":")


@dataclass
class DOMDiffResult:
    has_changes: bool
    added_elements: List[DOMElementSummary] = field(default_factory=list)
    removed_elements: List[DOMElementSummary] = field(default_factory=list)
    new_forms: List[str] = field(default_factory=list)
    new_inputs: List[str] = field(default_factory=list)
    new_buttons: List[str] = field(default_factory=list)
    new_links: List[str] = field(default_factory=list)
    new_modals: List[str] = field(default_factory=list)
    structural_change_ratio: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "has_changes": self.has_changes,
            "added_count": len(self.added_elements),
            "removed_count": len(self.removed_elements),
            "new_forms": self.new_forms,
            "new_inputs": self.new_inputs,
            "new_buttons": self.new_buttons,
            "new_links": self.new_links[:20],
            "new_modals": self.new_modals,
            "structural_change_ratio": round(self.structural_change_ratio, 3),
        }


class _MiniDOMParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.elements: List[DOMElementSummary] = []
        self._current_tag = ""
        self._current_elem: DOMElementSummary | None = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, str | None]]):
        attr_dict = {k.lower(): (v or "") for k, v in attrs}
        tag_lower = tag.lower()

        is_modal = tag_lower in ("dialog", "modal") or any(
            w in (attr_dict.get("id", "") + " " + attr_dict.get("class", "")).lower()
            for w in ("modal", "dialog", "drawer", "popup")
        )
        if tag_lower in ("button", "a", "form", "input", "select", "textarea") or is_modal:
            elem = DOMElementSummary(
                tag="modal" if is_modal and tag_lower not in ("button", "a", "form", "input") else tag_lower,
                element_id=attr_dict.get("id", ""),
                name=attr_dict.get("name", ""),
                element_type=attr_dict.get("type", ""),
                classes=attr_dict.get("class", ""),
                action_url=attr_dict.get("href", "") or attr_dict.get("action", "")
            )
            self.elements.append(elem)
            self._current_elem = elem

    def handle_data(self, data: str):
        cleaned = data.strip()
        if self._current_elem and cleaned and not self._current_elem.text_snippet:
            self._current_elem.text_snippet = cleaned[:50]

    def handle_endtag(self, tag: str):
        self._current_elem = None


class DOMDiffEngine:
    """Computes structural differences between two HTML snapshots"""

    @staticmethod
    def compute_structural_hash(html: str) -> str:
        if not html:
            return ""
        # Strip comments, scripts, timestamps, csrf noise
        cleaned = re.sub(r"<!--.*?-->", "", html, flags=re.DOTALL)
        cleaned = re.sub(r"<script.*?>.*?</script>", "", cleaned, flags=re.DOTALL | re.IGNORECASE)
        cleaned = re.sub(r"<style.*?>.*?</style>", "", cleaned, flags=re.DOTALL | re.IGNORECASE)
        # Normalize tags
        tags = re.findall(r"<([a-zA-Z0-9]+)[^>]*>", cleaned)
        skeleton = "-".join(t.lower() for t in tags[:1000])
        return hashlib.sha256(skeleton.encode("utf-8")).hexdigest()[:16]

    @classmethod
    def extract_elements(cls, html: str) -> List[DOMElementSummary]:
        if not html:
            return []
        parser = _MiniDOMParser()
        try:
            parser.feed(html)
        except Exception:
            pass
        return parser.elements

    @classmethod
    def diff(cls, before_html: str, after_html: str) -> DOMDiffResult:
        before_elems = cls.extract_elements(before_html)
        after_elems = cls.extract_elements(after_html)

        before_map = {e.identity_key: e for e in before_elems}
        after_map = {e.identity_key: e for e in after_elems}

        added = [e for k, e in after_map.items() if k not in before_map]
        removed = [e for k, e in before_map.items() if k not in after_map]

        new_forms = [e.identity_key for e in added if e.tag == "form"]
        new_inputs = [e.name or e.element_id or e.element_type for e in added if e.tag in ("input", "select", "textarea")]
        new_buttons = [e.text_snippet or e.element_id or e.name for e in added if e.tag == "button"]
        new_links = [e.action_url for e in added if e.tag == "a" and e.action_url]
        new_modals = [e.element_id or e.classes for e in added if e.tag in ("dialog", "modal") or "modal" in e.classes.lower()]

        total = max(len(before_map) + len(after_map), 1)
        ratio = (len(added) + len(removed)) / total

        has_changes = bool(added or removed or (cls.compute_structural_hash(before_html) != cls.compute_structural_hash(after_html)))

        return DOMDiffResult(
            has_changes=has_changes,
            added_elements=added,
            removed_elements=removed,
            new_forms=new_forms,
            new_inputs=new_inputs,
            new_buttons=new_buttons,
            new_links=new_links,
            new_modals=new_modals,
            structural_change_ratio=ratio
        )