"use client";

import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";

export type Theme = "dark" | "light";

export const THEME_STORAGE_KEY = "hunterai_theme";

export function normalizeTheme(value: string | null | undefined): Theme | null {
  if (!value) return null;
  const norm = value.trim().toLowerCase();
  if (norm === "dark" || norm === "light") return norm;
  return null;
}

interface ThemeContextValue {
  theme: Theme;
  setTheme: (next: Theme) => void;
  toggleTheme: () => void;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setThemeState] = useState<Theme>("dark");

  const applyDomTheme = useCallback((next: Theme) => {
    if (typeof document !== "undefined") {
      document.documentElement.setAttribute("data-theme", next);
    }
  }, []);

  useEffect(() => {
    let resolved: Theme = "dark";
    try {
      const params = new URLSearchParams(window.location.search);
      const qTheme = normalizeTheme(params.get("theme"));
      const stored = normalizeTheme(window.localStorage.getItem(THEME_STORAGE_KEY));
      if (qTheme) {
        resolved = qTheme;
        window.localStorage.setItem(THEME_STORAGE_KEY, qTheme);
      } else if (stored) {
        resolved = stored;
      }
    } catch {
      resolved = "dark";
    }
    setThemeState(resolved);
    applyDomTheme(resolved);

    const onStorage = (ev: StorageEvent) => {
      if (ev.key === THEME_STORAGE_KEY) {
        const next = normalizeTheme(ev.newValue);
        if (next) {
          setThemeState(next);
          applyDomTheme(next);
        }
      }
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, [applyDomTheme]);

  const setTheme = useCallback(
    (next: Theme) => {
      setThemeState(next);
      applyDomTheme(next);
      try {
        window.localStorage.setItem(THEME_STORAGE_KEY, next);
        const url = new URL(window.location.href);
        url.searchParams.set("theme", next);
        window.history.replaceState(null, "", url.toString());
      } catch {
        // Ignore storage or history errors in restricted contexts
      }
    },
    [applyDomTheme]
  );

  const toggleTheme = useCallback(() => {
    setTheme(theme === "dark" ? "light" : "dark");
  }, [theme, setTheme]);

  const value = useMemo<ThemeContextValue>(
    () => ({ theme, setTheme, toggleTheme }),
    [theme, setTheme, toggleTheme]
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) {
    throw new Error("useTheme must be used within ThemeProvider");
  }
  return ctx;
}
