"""
Crawl4AI-Inspired Clean Markdown & Structured Content Extractor
Transforms raw HTML / DOM pages into clean, LLM-friendly structured Markdown, tables, and form definitions for AI reasoning.
"""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from bs4 import BeautifulSoup, Comment, NavigableString, Tag


@dataclass
class ExtractedContent:
    title: str
    clean_markdown: str
    raw_text: str
    metadata: Dict[str, str] = field(default_factory=dict)
    links: List[str] = field(default_factory=list)
    headings: List[str] = field(default_factory=list)
    code_blocks: List[str] = field(default_factory=list)
    forms_markdown: str = ""


class MarkdownExtractor:
    """
    مستخرج المحتوى النظيف للـ LLM (LLM-Friendly Markdown Extractor):
    - ينظف الـ DOM من السكربتات المزعجة والـ CSS والإعلانات.
    - يحول الجداول والقوائم والنصوص إلى Markdown منظم وسهل القراءة للذكاء الاصطناعي.
    - يستخرج النماذج ومسارات الإدخال في جداول ملخصة.
    """

    @staticmethod
    def extract_from_html(html_text: str, base_url: str = "") -> ExtractedContent:
        soup = BeautifulSoup(html_text, "html.parser")

        # 1. Extract metadata & title
        title = soup.title.string.strip() if soup.title and soup.title.string else "Untitled Page"
        metadata = {}
        for meta in soup.find_all("meta"):
            name = meta.get("name") or meta.get("property")
            content = meta.get("content")
            if name and content:
                metadata[name] = content

        # 2. Extract Headings & Links
        headings = [h.get_text(strip=True) for h in soup.find_all(["h1", "h2", "h3", "h4"]) if h.get_text(strip=True)]
        links = []
        for a in soup.find_all("a", href=True):
            href = a.get("href")
            if href and not href.startswith(("javascript:", "#", "mailto:", "tel:")):
                if base_url and not href.startswith("http"):
                    href = urllib.parse.urljoin(base_url, href)
                links.append(href)
        links = sorted(list(set(links)))

        # 3. Extract Forms into Structured Markdown
        forms_lines = []
        for f_idx, form in enumerate(soup.find_all("form"), 1):
            action = form.get("action") or base_url or "/"
            method = (form.get("method") or "GET").upper()
            form_id = form.get("id") or form.get("name") or f"form_{f_idx}"
            forms_lines.append(f"### Form #{f_idx}: `{form_id}` [{method} -> {action}]")
            forms_lines.append("| Field Name | Type | Required | Placeholder / Default |")
            forms_lines.append("|---|---|---|---|")
            for inp in form.find_all(["input", "textarea", "select"]):
                f_name = inp.get("name") or inp.get("id") or "-"
                f_type = inp.get("type") or inp.name
                f_req = "Yes" if inp.has_attr("required") else "No"
                f_val = inp.get("placeholder") or inp.get("value") or "-"
                forms_lines.append(f"| `{f_name}` | `{f_type}` | {f_req} | {f_val} |")
            forms_lines.append("")
        forms_markdown = "\n".join(forms_lines)

        # 4. Remove clutter elements (scripts, styles, noscript, svg, iframes, comments)
        for element in soup(["script", "style", "noscript", "svg", "header", "footer", "nav", "aside"]):
            element.decompose()
        for comment in soup.find_all(string=lambda s: isinstance(s, Comment)):
            comment.extract()

        # 5. Extract Code blocks
        code_blocks = []
        for pre in soup.find_all("pre"):
            code = pre.get_text().strip()
            if code:
                code_blocks.append(code)

        # 6. Build Clean Markdown
        body = soup.body or soup
        lines = []
        lines.append(f"# {title}\n")

        for elem in body.find_all(["h1", "h2", "h3", "h4", "p", "ul", "ol", "table", "pre"]):
            if elem.name == "h1":
                lines.append(f"# {elem.get_text(strip=True)}\n")
            elif elem.name == "h2":
                lines.append(f"## {elem.get_text(strip=True)}\n")
            elif elem.name == "h3":
                lines.append(f"### {elem.get_text(strip=True)}\n")
            elif elem.name == "h4":
                lines.append(f"#### {elem.get_text(strip=True)}\n")
            elif elem.name == "p":
                txt = elem.get_text(strip=True)
                if txt:
                    lines.append(f"{txt}\n")
            elif elem.name in ("ul", "ol"):
                for li in elem.find_all("li", recursive=False):
                    li_txt = li.get_text(strip=True)
                    if li_txt:
                        lines.append(f"- {li_txt}")
                lines.append("")
            elif elem.name == "pre":
                lines.append(f"```\n{elem.get_text().strip()}\n```\n")

        clean_md = "\n".join(lines).strip()
        raw_text = re.sub(r"\s+", " ", body.get_text()).strip()

        return ExtractedContent(
            title=title,
            clean_markdown=clean_md,
            raw_text=raw_text,
            metadata=metadata,
            links=links,
            headings=headings,
            code_blocks=code_blocks,
            forms_markdown=forms_markdown
        )
