"use client";

import React, { useEffect } from "react";
import { AlertTriangle, RotateCcw, RefreshCw } from "lucide-react";
import { useI18n } from "@/lib/i18n";

interface RouteErrorProps {
  error: Error & { digest?: string };
  reset: () => void;
}

export default function GlobalRouteError({ error, reset }: RouteErrorProps) {
  let lang: "ar" | "en" = "en";
  let t = (key: string, fallback: string) => fallback;

  try {
    const i18n = useI18n();
    lang = i18n.lang;
    t = (key: string, fallback: string) => i18n.t(key, fallback);
  } catch {
    // Fallback if error boundary catches above I18nProvider
  }

  useEffect(() => {
    if (error) {
      console.error("[ARTEX-Pro UI ErrorBoundary]", error);
    }
  }, [error]);

  const title =
    lang === "ar"
      ? t("errorBoundary.title", "حدث خطأ غير متوقع في الواجهة")
      : t("errorBoundary.title", "An unexpected interface error occurred");
  const subtitle =
    lang === "ar"
      ? t(
          "errorBoundary.subtitle",
          "تم احتواء العطل بأمان دون التأثير على المهام النشطة في الخلفية."
        )
      : t(
          "errorBoundary.subtitle",
          "The failure was safely isolated without interrupting active backend missions."
        );
  const retryLabel =
    lang === "ar" ? t("errorBoundary.retry", "إعادة المحاولة") : t("errorBoundary.retry", "Try Again");
  const reloadLabel =
    lang === "ar"
      ? t("errorBoundary.reload", "إعادة تحميل الصفحة")
      : t("errorBoundary.reload", "Reload Page");

  return (
    <div
      role="alert"
      className="min-h-[60vh] flex items-center justify-center p-6"
    >
      <div className="sentinel-surface max-w-lg w-full p-6 space-y-4 border-sentinel-danger/40">
        <div className="flex items-start gap-3">
          <div className="w-10 h-10 rounded-lg bg-sentinel-danger/15 border border-sentinel-danger/35 flex items-center justify-center shrink-0">
            <AlertTriangle className="w-5 h-5 text-sentinel-danger" />
          </div>
          <div className="space-y-1 min-w-0">
            <h1 className="text-base font-semibold text-ink-primary">{title}</h1>
            <p className="text-xs text-ink-muted leading-relaxed">{subtitle}</p>
          </div>
        </div>

        {(error?.message || error?.digest) && (
          <div
            dir="ltr"
            className="ltr-isolate p-3 rounded-md bg-inset border border-border-subtle font-mono text-xs text-ink-secondary space-y-1 break-words"
          >
            {error.message && <div>{error.message}</div>}
            {error.digest && (
              <div className="text-[11px] text-ink-muted">Digest: {error.digest}</div>
            )}
          </div>
        )}

        <div className="flex flex-wrap items-center gap-2 pt-1">
          <button
            type="button"
            onClick={() => reset()}
            className="min-h-[44px] px-4 rounded-md bg-sentinel-primary text-sentinel-onAccent text-xs font-semibold flex items-center gap-2 hover:opacity-90"
          >
            <RotateCcw className="w-4 h-4" />
            <span>{retryLabel}</span>
          </button>
          <button
            type="button"
            onClick={() => window.location.reload()}
            className="min-h-[44px] px-4 rounded-md border border-border-strong bg-elevated text-ink-primary text-xs font-semibold flex items-center gap-2 hover:border-sentinel-primary"
          >
            <RefreshCw className="w-4 h-4" />
            <span>{reloadLabel}</span>
          </button>
        </div>
      </div>
    </div>
  );
}
