"""
HunterAI Browser 2.0 — Live Browser Control & DOM Annotation (Phase 8)
======================================================================
Provides:
  1. DOMAnnotator: Tags DOM elements with security risk metadata & semantics
  2. HistoryManager: Full chronological audit trail of navigation & interactions
  3. BrowserAgent: Autonomous browser automation orchestrator
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("hunter_ai.browser_v2")

try:
    from core.browser.playwright_controller import PlaywrightBrowserController, PLAYWRIGHT_AVAILABLE
except Exception:
    PLAYWRIGHT_AVAILABLE = False
    PlaywrightBrowserController = None


@dataclass
class DOMAnnotation:
    element_id: str
    tag: str
    element_type: str
    risk: str  # "high", "medium", "low", "info"
    security_role: str  # "login_form", "file_upload", "csrf_token", "admin_action", "navigation"
    attributes: Dict[str, str] = field(default_factory=dict)
    text_content: str = ""
    xpath_or_selector: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SimpleHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.elements: List[Dict[str, Any]] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        attr_dict = {k.lower(): (v or "") for k, v in attrs}
        self.elements.append({
            "tag": tag.lower(),
            "attrs": attr_dict,
            "text": "",
        })

    def handle_data(self, data: str):
        if self.elements and data.strip():
            self.elements[-1]["text"] = data.strip()


class DOMAnnotator:
    """
    Parses and tags DOM structures with security risk levels and semantic categorization.
    """
    def __init__(self):
        self.sensitive_keywords = ["password", "token", "secret", "auth", "session", "admin", "key", "credential"]
        self.upload_keywords = ["file", "upload", "attachment"]

    def annotate_html(self, html_content: str, current_url: str = "") -> List[DOMAnnotation]:
        parser = SimpleHTMLParser()
        try:
            parser.feed(html_content or "")
        except Exception:
            pass

        annotations: List[DOMAnnotation] = []
        for idx, el in enumerate(parser.elements):
            tag = el["tag"]
            attrs = el["attrs"]
            text = el.get("text", "")
            elem_id = attrs.get("id") or attrs.get("name") or f"elem_{tag}_{idx}"

            # 1. Forms & Inputs
            if tag == "form":
                action = attrs.get("action", "")
                method = attrs.get("method", "get").upper()
                is_auth = any(kw in action.lower() or kw in elem_id.lower() for kw in ["login", "signin", "auth"])
                annotations.append(DOMAnnotation(
                    element_id=elem_id,
                    tag=tag,
                    element_type="form",
                    risk="high" if is_auth else "medium",
                    security_role="login_form" if is_auth else "data_submission_form",
                    attributes=attrs,
                    text_content=text,
                    xpath_or_selector=f"form#{attrs.get('id')}" if attrs.get("id") else f"form[action='{action}']",
                ))

            elif tag == "input":
                itype = attrs.get("type", "text").lower()
                name = attrs.get("name", "").lower()
                
                if itype == "password" or any(k in name for k in self.sensitive_keywords):
                    annotations.append(DOMAnnotation(
                        element_id=elem_id,
                        tag=tag,
                        element_type=itype,
                        risk="high",
                        security_role="sensitive_credential_input",
                        attributes=attrs,
                        text_content="",
                        xpath_or_selector=f"input[name='{name}']",
                    ))
                elif itype == "file" or any(k in name for k in self.upload_keywords):
                    annotations.append(DOMAnnotation(
                        element_id=elem_id,
                        tag=tag,
                        element_type="file",
                        risk="high",
                        security_role="file_upload",
                        attributes=attrs,
                        text_content="",
                        xpath_or_selector=f"input[name='{name}']",
                    ))
                elif itype == "hidden" and any(k in name for k in ["csrf", "token", "xsrf", "_csrf"]):
                    annotations.append(DOMAnnotation(
                        element_id=elem_id,
                        tag=tag,
                        element_type="hidden",
                        risk="low",
                        security_role="csrf_token",
                        attributes=attrs,
                        text_content="",
                        xpath_or_selector=f"input[name='{name}']",
                    ))

            elif tag in ["button", "a"]:
                href = attrs.get("href", "")
                is_admin = any(k in href.lower() or k in text.lower() for k in ["admin", "delete", "destroy", "manage"])
                if is_admin:
                    annotations.append(DOMAnnotation(
                        element_id=elem_id,
                        tag=tag,
                        element_type="action_trigger",
                        risk="medium",
                        security_role="admin_action",
                        attributes=attrs,
                        text_content=text,
                        xpath_or_selector=f"{tag}#{elem_id}",
                    ))

        return annotations


class HistoryManager:
    """
    Chronological session history tracker for user/agent interactions.
    """
    def __init__(self):
        self._history: List[Dict[str, Any]] = []

    def record_navigation(self, url: str, status_code: int = 200, title: str = "") -> Dict[str, Any]:
        entry = {
            "type": "navigation",
            "url": url,
            "status_code": status_code,
            "title": title,
            "timestamp": time.time(),
        }
        self._history.append(entry)
        return entry

    def record_action(self, action_type: str, selector: str, value: str = "", metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        entry = {
            "type": "action",
            "action": action_type,
            "selector": selector,
            "value": value,
            "metadata": metadata or {},
            "timestamp": time.time(),
        }
        self._history.append(entry)
        return entry

    def get_history(self) -> List[Dict[str, Any]]:
        return list(self._history)

    def clear(self) -> None:
        self._history.clear()


class BrowserAgent:
    """
    Autonomous Browser Automation Agent coordinating navigation,
    DOM analysis, and interaction tracing.
    """
    def __init__(self, headless: bool = True):
        self.headless = headless
        self.annotator = DOMAnnotator()
        self.history_manager = HistoryManager()
        self.current_url: str = ""
        self.current_html: str = ""
        self.last_annotations: List[DOMAnnotation] = []

    def inspect_dom(self, html_content: str, url: str = "") -> List[DOMAnnotation]:
        """Annotates DOM elements with risk and security role tags"""
        self.current_url = url or self.current_url
        self.current_html = html_content
        self.last_annotations = self.annotator.annotate_html(html_content, self.current_url)
        return self.last_annotations

    def navigate(self, url: str, title: str = "Web Page", simulated_html: Optional[str] = None) -> Dict[str, Any]:
        """Simulates or executes page navigation, recording in history"""
        self.current_url = url
        self.history_manager.record_navigation(url=url, status_code=200, title=title)
        
        if simulated_html:
            self.inspect_dom(simulated_html, url)
            
        return {
            "url": url,
            "title": title,
            "annotations_count": len(self.last_annotations),
        }

    def click(self, selector: str) -> Dict[str, Any]:
        entry = self.history_manager.record_action("click", selector=selector)
        logger.info("BrowserAgent clicked: %s", selector)
        return entry

    def fill(self, selector: str, value: str) -> Dict[str, Any]:
        # Redact value if password
        is_pw = "password" in selector.lower()
        entry = self.history_manager.record_action(
            "fill",
            selector=selector,
            value="[REDACTED]" if is_pw else value,
        )
        logger.info("BrowserAgent filled: %s", selector)
        return entry

    def get_annotated_surface(self) -> Dict[str, Any]:
        high_risk = [a.to_dict() for a in self.last_annotations if a.risk == "high"]
        medium_risk = [a.to_dict() for a in self.last_annotations if a.risk == "medium"]
        return {
            "current_url": self.current_url,
            "total_annotations": len(self.last_annotations),
            "high_risk_elements": high_risk,
            "medium_risk_elements": medium_risk,
            "history_length": len(self.history_manager.get_history()),
        }
