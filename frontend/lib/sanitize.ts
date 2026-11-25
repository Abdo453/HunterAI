import DOMPurify from "dompurify";

/**
 * Escape raw text so it cannot be interpreted as HTML markup.
 */
export function escapeHtml(value: unknown): string {
  if (value === null || value === undefined) {
    return "";
  }
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Validate external/relative URLs, blocking javascript:, data:, vbscript:, and protocol-relative bypasses.
 */
export function safeHref(url: unknown, fallback = "#"): string {
  if (typeof url !== "string") {
    return fallback;
  }
  const trimmed = url.trim();
  if (!trimmed || /[\u0000-\u001F\u007F]/.test(trimmed)) {
    return fallback;
  }
  if (trimmed.startsWith("/")) {
    if (trimmed.length > 1 && (trimmed[1] === "/" || trimmed[1] === "\\")) {
      return fallback;
    }
    return trimmed;
  }
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol === "http:" || parsed.protocol === "https:") {
      return parsed.href;
    }
  } catch {
    return fallback;
  }
  return fallback;
}

function renderInlineMarkdown(text: string): string {
  let out = escapeHtml(text);
  out = out.replace(/`([^`\n]+)`/g, '<code class="ltr-isolate">$1</code>');
  out = out.replace(/\*\*([^*\n]+)\*\*/g, "<strong>$1</strong>");
  out = out.replace(/(^|[^*])\*([^*\n]+)\*/g, "$1<em>$2</em>");
  out = out.replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, (_m, label: string, href: string) => {
    const safeUrl = safeHref(href, "#");
    if (safeUrl === "#") {
      return escapeHtml(label);
    }
    return `<a href="${escapeHtml(safeUrl)}" target="_blank" rel="noopener noreferrer">${label}</a>`;
  });
  return out;
}

/**
 * Convert plain/Markdown text into sanitized HTML via DOMPurify.
 * Safe for SSR (returns escaped HTML when window is unavailable).
 */
export function sanitizeHtml(html: string): string {
  if (!html) {
    return "";
  }
  if (typeof window === "undefined") {
    return escapeHtml(html);
  }
  return DOMPurify.sanitize(html, {
    ALLOWED_TAGS: [
      "a",
      "b",
      "blockquote",
      "br",
      "code",
      "div",
      "em",
      "h1",
      "h2",
      "h3",
      "h4",
      "hr",
      "i",
      "li",
      "ol",
      "p",
      "pre",
      "span",
      "strong",
      "ul",
    ],
    ALLOWED_ATTR: ["class", "dir", "href", "rel", "target"],
    FORBID_TAGS: ["script", "style", "iframe", "object", "embed", "form"],
    FORBID_ATTR: ["onerror", "onload", "onclick", "onmouseover", "onfocus", "onblur", "style"],
    ALLOW_DATA_ATTR: false,
  });
}

/**
 * Render Markdown text cleanly into DOMPurify-sanitized HTML with isolated LTR code fences.
 */
export function renderSafeMarkdown(markdown: string): string {
  const normalized = String(markdown ?? "").replace(/\r\n/g, "\n");
  if (!normalized.trim()) {
    return "";
  }
  const lines = normalized.split("\n");
  const blocks: string[] = [];
  let inCode = false;
  let codeBuf: string[] = [];
  let listType: "ul" | "ol" | null = null;

  const flushCode = () => {
    blocks.push(`<pre class="ltr-isolate" dir="ltr"><code>${codeBuf.join("\n")}</code></pre>`);
    codeBuf = [];
    inCode = false;
  };

  const flushList = () => {
    if (listType) {
      blocks.push(`</${listType}>`);
      listType = null;
    }
  };

  for (const raw of lines) {
    if (/^```/.test(raw.trim())) {
      if (inCode) {
        flushCode();
      } else {
        flushList();
        inCode = true;
      }
      continue;
    }
    if (inCode) {
      codeBuf.push(escapeHtml(raw));
      continue;
    }

    const ulMatch = raw.match(/^\s*[-*]\s+(.*)$/);
    if (ulMatch) {
      if (listType === "ol") flushList();
      if (!listType) {
        blocks.push("<ul>");
        listType = "ul";
      }
      blocks.push(`<li>${renderInlineMarkdown(ulMatch[1])}</li>`);
      continue;
    }

    const olMatch = raw.match(/^\s*\d+\.\s+(.*)$/);
    if (olMatch) {
      if (listType === "ul") flushList();
      if (!listType) {
        blocks.push("<ol>");
        listType = "ol";
      }
      blocks.push(`<li>${renderInlineMarkdown(olMatch[1])}</li>`);
      continue;
    }

    flushList();
    if (!raw.trim()) {
      continue;
    }

    const heading = raw.match(/^(#{1,4})\s+(.*)$/);
    if (heading) {
      const level = Math.min(4, Math.max(2, heading[1].length));
      blocks.push(`<h${level}>${renderInlineMarkdown(heading[2])}</h${level}>`);
      continue;
    }

    if (raw.trim() === "---") {
      blocks.push("<hr />");
      continue;
    }

    blocks.push(`<p>${renderInlineMarkdown(raw)}</p>`);
  }

  if (inCode) flushCode();
  flushList();

  return sanitizeHtml(blocks.join(""));
}
