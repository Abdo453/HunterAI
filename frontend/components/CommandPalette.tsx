"use client";

import React, { useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { Search, X, ArrowRight, Loader2, Sparkles, Moon, Sun, Languages, Bot } from "lucide-react";
import { CopilotRef, usePlatform } from "@/lib/platform-context";
import { NAV_ROUTES } from "@/components/AppShell";
import { useI18n } from "@/lib/i18n";
import { useTheme } from "@/lib/theme";

interface SearchHit {
  kind: string;
  id: string;
  title: string;
  subtitle?: string;
  ref?: CopilotRef;
}

type PaletteEntry =
  | { kind: "route"; id: string; title: string; subtitle: string; href: string }
  | { kind: "action"; id: string; title: string; subtitle: string; run: () => void }
  | { kind: "hit"; id: string; title: string; subtitle: string; hit: SearchHit };

export default function CommandPalette() {
  const router = useRouter();
  const {
    commandPaletteOpen,
    setCommandPaletteOpen,
    setCopilotOpen,
    navigateToRef,
    apiJson,
  } = usePlatform();
  const { t, lang, toggleLang } = useI18n();
  const { theme, toggleTheme } = useTheme();

  const [query, setQuery] = useState<string>("");
  const [hits, setHits] = useState<SearchHit[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [selectedIndex, setSelectedIndex] = useState<number>(0);

  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    const onGlobalKey = (ev: KeyboardEvent) => {
      if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "k") {
        ev.preventDefault();
        setCommandPaletteOpen((prev) => !prev);
      } else if (ev.key === "Escape" && commandPaletteOpen) {
        ev.preventDefault();
        setCommandPaletteOpen(false);
      }
    };
    window.addEventListener("keydown", onGlobalKey);
    return () => window.removeEventListener("keydown", onGlobalKey);
  }, [commandPaletteOpen, setCommandPaletteOpen]);

  useEffect(() => {
    if (commandPaletteOpen) {
      setQuery("");
      setHits([]);
      setSelectedIndex(0);
      window.setTimeout(() => inputRef.current?.focus(), 20);
    }
  }, [commandPaletteOpen]);

  useEffect(() => {
    if (!commandPaletteOpen) return;
    const trimmed = query.trim();
    if (!trimmed) {
      setHits([]);
      setLoading(false);
      return;
    }

    const controller = new AbortController();
    const timer = window.setTimeout(async () => {
      setLoading(true);
      const res = await apiJson<{ results?: SearchHit[] }>(
        `/api/platform/search?q=${encodeURIComponent(trimmed)}&limit=25`,
        { signal: controller.signal }
      );
      if (!controller.signal.aborted) {
        setHits(res.ok && Array.isArray(res.data?.results) ? res.data.results : []);
        setLoading(false);
      }
    }, 180);

    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [query, commandPaletteOpen, apiJson]);

  const entries = useMemo<PaletteEntry[]>(() => {
    const q = query.trim().toLowerCase();
    const list: PaletteEntry[] = [];

    for (const r of NAV_ROUTES) {
      const label = t(r.labelKey);
      if (!q || label.toLowerCase().includes(q) || r.href.toLowerCase().includes(q)) {
        list.push({
          kind: "route",
          id: `route:${r.href}`,
          title: label,
          subtitle: r.href,
          href: r.href,
        });
      }
    }

    const quickActions: Array<{ id: string; title: string; subtitle: string; run: () => void }> = [
      {
        id: "act:copilot",
        title: t("nav.copilotBtn"),
        subtitle: "Ctrl+J",
        run: () => setCopilotOpen((prev) => !prev),
      },
      {
        id: "act:theme",
        title: theme === "dark" ? t("common.lightTheme") : t("common.darkTheme"),
        subtitle: t("common.theme"),
        run: toggleTheme,
      },
      {
        id: "act:lang",
        title: lang === "ar" ? "Switch to English (LTR)" : "التبديل إلى العربية (RTL)",
        subtitle: t("common.language"),
        run: toggleLang,
      },
    ];

    for (const act of quickActions) {
      if (!q || act.title.toLowerCase().includes(q)) {
        list.push({ kind: "action", ...act });
      }
    }

    for (const h of hits) {
      list.push({
        kind: "hit",
        id: `hit:${h.kind}:${h.id}`,
        title: h.title || h.id,
        subtitle: `${h.kind.toUpperCase()}${h.subtitle ? ` · ${h.subtitle}` : ""}`,
        hit: h,
      });
    }

    return list;
  }, [query, hits, lang, theme, toggleLang, toggleTheme, setCopilotOpen, t]);

  useEffect(() => {
    setSelectedIndex(0);
  }, [entries.length]);

  const executeEntry = (entry: PaletteEntry | undefined) => {
    if (!entry) return;
    setCommandPaletteOpen(false);
    if (entry.kind === "route") {
      router.push(entry.href);
    } else if (entry.kind === "action") {
      entry.run();
    } else {
      const ref: CopilotRef = entry.hit.ref || {
        kind: entry.hit.kind,
        id: entry.hit.id,
        label: entry.hit.title,
      };
      navigateToRef(ref);
    }
  };

  const handleInputKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setSelectedIndex((idx) => (entries.length ? (idx + 1) % entries.length : 0));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSelectedIndex((idx) => (entries.length ? (idx - 1 + entries.length) % entries.length : 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      executeEntry(entries[selectedIndex]);
    }
  };

  if (!commandPaletteOpen) {
    return null;
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-[10vh] px-4 bg-black/60 backdrop-blur-[2px]"
      onClick={() => setCommandPaletteOpen(false)}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label={t("nav.commandPalette")}
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-2xl rounded-xl border border-border-strong bg-surface shadow-sentinelMd overflow-hidden flex flex-col max-h-[75vh]"
      >
        <div className="px-4 py-3 border-b border-border-subtle flex items-center gap-2.5 bg-inset">
          {loading ? (
            <Loader2 className="w-4 h-4 animate-spin text-sentinel-primary shrink-0" />
          ) : (
            <Search className="w-4 h-4 text-sentinel-primary shrink-0" />
          )}
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleInputKeyDown}
            placeholder={t("palette.placeholder")}
            aria-label={t("palette.placeholder")}
            className="flex-1 bg-transparent text-sm text-ink-primary placeholder:text-ink-muted focus:outline-none"
          />
          <button
            type="button"
            onClick={() => setCommandPaletteOpen(false)}
            aria-label={t("common.close")}
            className="min-h-[36px] min-w-[36px] rounded border border-border-subtle bg-elevated text-ink-muted hover:text-ink-primary flex items-center justify-center"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-2 space-y-1">
          {entries.length === 0 ? (
            <div className="py-8 text-center text-xs text-ink-muted">
              {loading ? t("palette.searching") : query.trim() ? t("palette.noResults") : t("palette.emptyQuery")}
            </div>
          ) : (
            entries.map((item, idx) => {
              const selected = idx === selectedIndex;
              return (
                <button
                  key={`${item.id}-${idx}`}
                  type="button"
                  onMouseEnter={() => setSelectedIndex(idx)}
                  onClick={() => executeEntry(item)}
                  className={`w-full min-h-[44px] px-3 py-2 rounded-md text-start flex items-center justify-between gap-3 transition-colors ${
                    selected
                      ? "bg-[var(--accent-primary-bg)] border border-[var(--accent-primary)]/40 text-ink-primary"
                      : "hover:bg-elevated border border-transparent text-ink-secondary"
                  }`}
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    {item.kind === "action" && item.id === "act:theme" ? (
                      theme === "dark" ? <Sun className="w-4 h-4 text-sentinel-warning shrink-0" /> : <Moon className="w-4 h-4 text-sentinel-primary shrink-0" />
                    ) : item.kind === "action" && item.id === "act:lang" ? (
                      <Languages className="w-4 h-4 text-sentinel-primary shrink-0" />
                    ) : item.kind === "action" && item.id === "act:copilot" ? (
                      <Bot className="w-4 h-4 text-sentinel-ai shrink-0" />
                    ) : item.kind === "hit" ? (
                      <Sparkles className="w-4 h-4 text-sentinel-success shrink-0" />
                    ) : (
                      <ArrowRight className="w-4 h-4 text-sentinel-primary shrink-0" />
                    )}
                    <div className="min-w-0">
                      <div className="text-xs font-semibold text-ink-primary truncate">
                        {item.title}
                      </div>
                      <div className="text-[11px] font-mono text-ink-muted truncate ltr-isolate">
                        {item.subtitle}
                      </div>
                    </div>
                  </div>

                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-inset border border-border-subtle text-ink-muted shrink-0 uppercase">
                    {item.kind}
                  </span>
                </button>
              );
            })
          )}
        </div>

        <div className="px-4 py-2 border-t border-border-subtle bg-elevated/60 text-[11px] font-mono text-ink-muted flex items-center justify-between">
          <span>{t("palette.shortcutHint")}</span>
          {query.trim() && (
            <span className="tabular-nums">{hits.length} hits</span>
          )}
        </div>
      </div>
    </div>
  );
}
