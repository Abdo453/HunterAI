"use client";

import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import catalogData from "./catalog.json";

export type Lang = "ar" | "en";

export const LANG_STORAGE_KEY = "hunterai_lang";

type NestedDict = { [key: string]: string | NestedDict };

function lookupNested(obj: unknown, path: string): string | undefined {
  if (!obj || typeof obj !== "object") return undefined;
  const parts = path.split(".");
  let cur: unknown = obj;
  for (const part of parts) {
    if (!cur || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[part];
  }
  return typeof cur === "string" ? cur : undefined;
}

function interpolate(template: string, vars?: Record<string, string | number>): string {
  if (!vars) return template;
  return template.replace(/\{([a-zA-Z0-9_]+)\}/g, (match, key: string) =>
    Object.prototype.hasOwnProperty.call(vars, key) ? String(vars[key]) : match
  );
}

export function translate(
  lang: Lang,
  key: string,
  fallbackOrVars?: string | Record<string, string | number>,
  maybeVars?: Record<string, string | number>
): string {
  const fallback = typeof fallbackOrVars === "string" ? fallbackOrVars : key;
  const vars = typeof fallbackOrVars === "object" && fallbackOrVars !== null ? fallbackOrVars : maybeVars;

  const catalog = catalogData as Record<Lang, NestedDict>;
  const resolved =
    lookupNested(catalog[lang], key) ??
    lookupNested(catalog.en, key) ??
    fallback;

  return interpolate(resolved, vars);
}

export function normalizeLang(value: string | null | undefined): Lang | null {
  if (!value) return null;
  const norm = value.trim().toLowerCase();
  if (norm === "ar" || norm === "en") return norm;
  return null;
}

interface I18nContextValue {
  lang: Lang;
  dir: "rtl" | "ltr";
  setLang: (next: Lang) => void;
  toggleLang: () => void;
  t: (
    key: string,
    fallbackOrVars?: string | Record<string, string | number>,
    maybeVars?: Record<string, string | number>
  ) => string;
}

const I18nContext = createContext<I18nContextValue | null>(null);

export function I18nProvider({ children }: { children: React.ReactNode }) {
  const [lang, setLangState] = useState<Lang>("en");

  const applyDomLang = useCallback((next: Lang) => {
    if (typeof document !== "undefined") {
      document.documentElement.setAttribute("lang", next);
      document.documentElement.setAttribute("dir", next === "ar" ? "rtl" : "ltr");
    }
  }, []);

  useEffect(() => {
    let resolved: Lang = "en";
    try {
      const params = new URLSearchParams(window.location.search);
      const qLang = normalizeLang(params.get("lang"));
      const stored =
        normalizeLang(window.localStorage.getItem(LANG_STORAGE_KEY)) ||
        normalizeLang(window.localStorage.getItem("lang"));
      if (qLang) {
        resolved = qLang;
        window.localStorage.setItem(LANG_STORAGE_KEY, qLang);
      } else if (stored) {
        resolved = stored;
      }
    } catch {
      resolved = "en";
    }
    setLangState(resolved);
    applyDomLang(resolved);

    const onStorage = (ev: StorageEvent) => {
      if (ev.key === LANG_STORAGE_KEY || ev.key === "lang") {
        const next = normalizeLang(ev.newValue);
        if (next) {
          setLangState(next);
          applyDomLang(next);
        }
      }
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, [applyDomLang]);

  const setLang = useCallback(
    (next: Lang) => {
      setLangState(next);
      applyDomLang(next);
      try {
        window.localStorage.setItem(LANG_STORAGE_KEY, next);
      } catch {
        // Ignore storage errors in restricted contexts
      }
    },
    [applyDomLang]
  );

  const toggleLang = useCallback(() => {
    setLang(lang === "ar" ? "en" : "ar");
  }, [lang, setLang]);

  const t = useCallback(
    (
      key: string,
      fallbackOrVars?: string | Record<string, string | number>,
      maybeVars?: Record<string, string | number>
    ) => translate(lang, key, fallbackOrVars, maybeVars),
    [lang]
  );

  const value = useMemo<I18nContextValue>(
    () => ({
      lang,
      dir: lang === "ar" ? "rtl" : "ltr",
      setLang,
      toggleLang,
      t,
    }),
    [lang, setLang, toggleLang, t]
  );

  return React.createElement(I18nContext.Provider, { value }, children);
}

export function useI18n(): I18nContextValue {
  const ctx = useContext(I18nContext);
  if (!ctx) {
    throw new Error("useI18n must be used within I18nProvider");
  }
  return ctx;
}
