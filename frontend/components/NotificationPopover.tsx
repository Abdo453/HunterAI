"use client";

import React, { useEffect, useRef, useState } from "react";
import { Bell, Check, CheckCheck, RefreshCw, X } from "lucide-react";
import { usePlatform } from "@/lib/platform-context";
import { useI18n } from "@/lib/i18n";

function formatNotifTime(ts?: number): string {
  if (!ts) return "";
  const ms = ts > 1e12 ? ts : ts * 1000;
  return new Date(ms).toLocaleTimeString("en-GB", { hour12: false });
}

export default function NotificationPopover() {
  const {
    notifications,
    unreadNotificationsCount,
    refreshNotifications,
    markNotificationRead,
    navigateToRef,
  } = usePlatform();
  const { t } = useI18n();

  const [open, setOpen] = useState<boolean>(false);
  const [busyId, setBusyId] = useState<string | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const triggerRef = useRef<HTMLButtonElement | null>(null);

  useEffect(() => {
    if (!open) return;
    void refreshNotifications();

    const onPointerDown = (ev: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(ev.target as Node)) {
        setOpen(false);
      }
    };
    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape") {
        setOpen(false);
        triggerRef.current?.focus();
      }
    };
    document.addEventListener("mousedown", onPointerDown);
    window.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("mousedown", onPointerDown);
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [open, refreshNotifications]);

  const handleMarkRead = async (id: string) => {
    setBusyId(id);
    await markNotificationRead(id);
    setBusyId(null);
  };

  const handleMarkAllRead = async () => {
    const unread = notifications.filter((n) => !n.read);
    for (const item of unread) {
      await markNotificationRead(item.notification_id);
    }
  };

  return (
    <div ref={containerRef} className="relative">
      <button
        ref={triggerRef}
        type="button"
        data-testid="notifications-trigger"
        onClick={() => setOpen((prev) => !prev)}
        aria-expanded={open}
        aria-controls="notifications-popover-panel"
        aria-label={t("notifications.title")}
        title={t("notifications.title")}
        className={`min-h-[44px] min-w-[44px] lg:min-h-0 lg:min-w-0 lg:h-9 px-2.5 rounded-md border text-xs flex items-center justify-center gap-1.5 transition-colors ${
          open
            ? "border-sentinel-primary bg-sentinel-primary/15 text-sentinel-primary"
            : "border-border-subtle bg-elevated hover:border-border-strong text-ink-primary"
        }`}
      >
        <Bell
          className={`w-4 h-4 ${
            unreadNotificationsCount > 0 ? "text-sentinel-primary" : "text-ink-muted"
          }`}
        />
        {unreadNotificationsCount > 0 && (
          <span
            data-testid="notifications-unread-badge"
            className="px-1.5 py-0.5 rounded-full text-[10px] font-mono tabular-nums bg-sentinel-primary/15 text-sentinel-primary border border-sentinel-primary/35"
          >
            {unreadNotificationsCount}
          </span>
        )}
      </button>

      {open && (
        <div
          id="notifications-popover-panel"
          role="dialog"
          aria-modal="false"
          aria-label={t("notifications.title")}
          className="absolute top-full end-0 mt-1.5 z-50 w-[340px] max-w-[calc(100vw-1.5rem)] rounded-lg border border-border-strong bg-surface shadow-sentinelMd flex flex-col overflow-hidden"
        >
          <div className="px-3.5 py-2.5 border-b border-border-subtle bg-elevated/60 flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 min-w-0">
              <Bell className="w-4 h-4 text-sentinel-primary shrink-0" />
              <span className="text-xs font-semibold text-ink-primary truncate">
                {t("notifications.title")}
              </span>
              {unreadNotificationsCount > 0 && (
                <span className="px-1.5 py-0.5 rounded-full text-[10px] font-mono tabular-nums bg-sentinel-primary/15 text-sentinel-primary border border-sentinel-primary/35">
                  {unreadNotificationsCount}
                </span>
              )}
            </div>
            <div className="flex items-center gap-1">
              {unreadNotificationsCount > 0 && (
                <button
                  type="button"
                  onClick={() => void handleMarkAllRead()}
                  aria-label={t("notifications.markAllRead")}
                  title={t("notifications.markAllRead")}
                  className="h-7 px-2 rounded border border-border-subtle bg-inset text-[11px] text-ink-secondary hover:text-ink-primary flex items-center gap-1"
                >
                  <CheckCheck className="w-3.5 h-3.5 text-sentinel-success" />
                </button>
              )}
              <button
                type="button"
                onClick={() => void refreshNotifications()}
                aria-label={t("common.refresh")}
                title={t("common.refresh")}
                className="h-7 w-7 rounded border border-border-subtle bg-inset text-ink-secondary hover:text-ink-primary flex items-center justify-center"
              >
                <RefreshCw className="w-3.5 h-3.5" />
              </button>
              <button
                type="button"
                onClick={() => setOpen(false)}
                aria-label={t("common.close")}
                className="h-7 w-7 rounded border border-border-subtle bg-inset text-ink-secondary hover:text-ink-primary flex items-center justify-center"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          <div className="max-h-80 overflow-y-auto divide-y divide-border-subtle">
            {notifications.length === 0 ? (
              <div className="py-8 px-4 text-center text-xs text-ink-muted">
                {t("notifications.empty")}
              </div>
            ) : (
              notifications.map((item) => {
                const lvl = (item.level || "info").toLowerCase();
                const accent =
                  lvl === "error" || lvl === "critical"
                    ? "text-sentinel-danger"
                    : lvl === "warn" || lvl === "warning"
                      ? "text-sentinel-warning"
                      : lvl === "success"
                        ? "text-sentinel-success"
                        : "text-sentinel-primary";

                return (
                  <div
                    key={item.notification_id}
                    className={`p-3 text-xs space-y-1.5 ${
                      item.read ? "bg-surface opacity-80" : "bg-elevated/50"
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <button
                        type="button"
                        onClick={() => {
                          if (!item.read) void handleMarkRead(item.notification_id);
                          if (item.run_id) {
                            navigateToRef({ kind: "run", id: item.run_id });
                          } else if (item.engagement_id) {
                            navigateToRef({ kind: "engagement", id: item.engagement_id });
                          }
                          setOpen(false);
                        }}
                        className="text-start flex-1 min-w-0 space-y-0.5 hover:underline"
                      >
                        <div className="flex items-center gap-1.5">
                          {!item.read && (
                            <span
                              className="w-1.5 h-1.5 rounded-full bg-sentinel-primary shrink-0"
                              aria-hidden="true"
                            />
                          )}
                          <span className={`font-semibold truncate ${accent}`}>
                            {item.title || item.source || t("notifications.systemNotice")}
                          </span>
                        </div>
                        <p className="text-ink-secondary leading-relaxed break-words">
                          {item.message}
                        </p>
                      </button>

                      {!item.read && (
                        <button
                          type="button"
                          disabled={busyId === item.notification_id}
                          onClick={() => void handleMarkRead(item.notification_id)}
                          aria-label={t("notifications.markRead")}
                          title={t("notifications.markRead")}
                          className="h-7 w-7 rounded border border-border-subtle bg-inset hover:border-sentinel-success text-ink-muted hover:text-sentinel-success flex items-center justify-center shrink-0"
                        >
                          <Check className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>
                    <div className="flex items-center justify-between text-[10px] font-mono text-ink-muted tabular-nums">
                      <span>{item.source || "platform"}</span>
                      <span>{formatNotifTime(item.created_at)}</span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}
    </div>
  );
}
