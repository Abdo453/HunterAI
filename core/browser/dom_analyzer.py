"""
DOM Analyzer
============
Extracts structured elements (forms, inputs, buttons, links, modals) and
calculates structural DOM hashes to detect mutations without false positives.
"""
from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

logger = logging.getLogger("hunter_ai.dom_analyzer")


@dataclass
class FormField:
    name: str
    field_type: str = "text"
    value: str = ""
    required: bool = False


@dataclass
class ExtractedForm:
    action: str
    method: str = "GET"
    fields: List[FormField] = field(default_factory=list)
    has_file_upload: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "method": self.method.upper(),
            "has_file_upload": self.has_file_upload,
            "fields": [{"name": f.name, "type": f.field_type, "value": f.value} for f in self.fields],
        }


class _DOMStructureParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tag_sequence: List[str] = []
        self.forms: List[ExtractedForm] = []
        self._current_form: Optional[ExtractedForm] = None
        self.buttons: List[Dict[str, str]] = []
        self.links: List[Dict[str, str]] = []
        self._current_tag: Optional[str] = None

    def handle_starttag(self, tag: str, attrs: List[tuple[str, Optional[str]]]):
        tag_lower = tag.lower()
        self._current_tag = tag_lower
        attr_dict = {k.lower(): (v or "") for k, v in attrs}

        # Track structural layout
        if tag_lower in ("div", "form", "input", "button", "table", "ul", "dialog", "section", "main", "nav"):
            class_val = attr_dict.get("class", "")
            id_val = attr_dict.get("id", "")
            self.tag_sequence.append(f"{tag_lower}#{id_val}.{class_val[:20]}")

        # Form tracking
        if tag_lower == "form":
            action = attr_dict.get("action", "")
            method = attr_dict.get("method", "GET").upper()
            enctype = attr_dict.get("enctype", "").lower()
            self._current_form = ExtractedForm(
                action=action,
                method=method,
                has_file_upload="multipart" in enctype,
            )
        elif tag_lower in ("input", "textarea", "select"):
            name = attr_dict.get("name", "")
            ftype = attr_dict.get("type", "text").lower()
            if self._current_form and name:
                self._current_form.fields.append(
                    FormField(name=name, field_type=ftype, value=attr_dict.get("value", ""))
                )
                if ftype == "file":
                    self._current_form.has_file_upload = True

        # Button tracking
        elif tag_lower == "button" or (tag_lower == "input" and attr_dict.get("type") in ("submit", "button")):
            self.buttons.append({
                "id": attr_dict.get("id", ""),
                "class": attr_dict.get("class", ""),
                "type": attr_dict.get("type", "button"),
                "name": attr_dict.get("name", ""),
            })

        # Link tracking
        elif tag_lower == "a" and "href" in attr_dict:
            href = attr_dict.get("href", "").strip()
            if href and not href.startswith(("javascript:", "#", "mailto:", "tel:")):
                self.links.append({
                    "href": href,
                    "id": attr_dict.get("id", ""),
                    "class": attr_dict.get("class", ""),
                })

    def handle_endtag(self, tag: str):
        if tag.lower() == "form" and self._current_form:
            self.forms.append(self._current_form)
            self._current_form = None
        self._current_tag = None


class DOMAnalyzer:
    """Provides structured inspection and structural hashing for HTML pages"""

    @classmethod
    def compute_structural_hash(cls, html: str) -> str:
        """Calculates a deterministic hash representing the structural skeleton of the DOM"""
        if not html:
            return "empty"
        parser = _DOMStructureParser()
        try:
            parser.feed(html)
            skeleton = "|".join(parser.tag_sequence)
            return hashlib.sha256(skeleton.encode("utf-8")).hexdigest()[:16]
        except Exception:
            return hashlib.sha256(html[:500].encode("utf-8")).hexdigest()[:16]

    @classmethod
    def analyze(cls, html: str, base_url: str) -> Dict[str, Any]:
        """Parses HTML into forms, buttons, links, and structural metrics"""
        if not html:
            return {"forms": [], "buttons": [], "links": [], "structural_hash": "empty"}

        parser = _DOMStructureParser()
        try:
            parser.feed(html)
        except Exception as e:
            logger.debug(f"DOM parsing error: {e}")

        # Resolve relative URLs
        resolved_links = []
        for l in parser.links:
            resolved = urljoin(base_url, l["href"])
            resolved_links.append({"href": resolved, "id": l.get("id", ""), "class": l.get("class", "")})

        resolved_forms = []
        for f in parser.forms:
            f.action = urljoin(base_url, f.action) if f.action else base_url
            resolved_forms.append(f.to_dict())

        return {
            "forms": resolved_forms,
            "buttons": parser.buttons,
            "links": resolved_links,
            "structural_hash": cls.compute_structural_hash(html),
        }
