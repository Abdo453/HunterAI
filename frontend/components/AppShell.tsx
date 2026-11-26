"use client";

import React, { useEffect, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import {
  LayoutDashboard,
  Network,
  ShieldAlert,
  Crosshair,
  Code2,
  Radar,
  Boxes,
  SlidersHorizontal,
  Shield,
  PanelLeftClose,
  PanelLeftOpen,
  X,
  AlertTriangle,
  Database,
  Radio,
} from "lucide-react";
import Navbar from "@/components/Navbar";
import CommandPalette from "@/components/CommandPalette";
import CopilotDrawer from "@/components/CopilotDrawer";
import { usePlatform } from "@/lib/platform-context";
import { useI18n } from "@/lib/i18n";

const SIDEBAR_STORAGE_KEY = "hunterai_sidebar_collapsed";

export interface NavRouteItem {
  href: string;
  labelKey: string;
  icon: React.ComponentType<{ className?: string }>;
}

export const NAV_ROUTES: NavRouteItem[] = [
  { href: "/", labelKey: "routes.overview", icon: LayoutDashboard },
  { href: "/surface", labelKey: "routes.surface", icon: Network },
  { href: "/findings", labelKey: "routes.findings", icon: ShieldAlert },
  { href: "/operations", labelKey: "routes.operations", icon: Crosshair },
  { href: "/studio", labelKey: "routes.studio", icon: Code2 },
  { href: "/intercept", labelKey: "routes.intercept", icon: Radar },
  { href: "/arsenal", labelKey: "routes.arsenal", icon: Boxes },
  { href: "/system", labelKey: "routes.system", icon: SlidersHorizontal },
];

export default function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname() || "/";
  const router = useRouter();
  const { goCoreHealth, hunterHubHealth, pendingApprovalsCount } = usePlatform();
  const { t, dir } = useI18n();

  const [collapsed, setCollapsed] = useState<boolean>(false);
  const [mobileDrawerOpen, setMobileDrawerOpen] = useState<boolean>(false);

  useEffect(() => {
    try {
      const saved = window.localStorage.getItem(SIDEBAR_STORAGE_KEY);
      if (saved === "1") setCollapsed(true);
    } catch {
      // Ignore storage access errors
    }
  }, []);

  useEffect(() => {
    setMobileDrawerOpen(false);
  }, [pathname]);

  useEffect(() => {
    if (!mobileDrawerOpen) return;
    const onKey = (ev: KeyboardEvent) => {
      if (ev.key === "Escape") {
        setMobileDrawerOpen(false);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [mobileDrawerOpen]);

  const toggleCollapsed = () => {
    setCollapsed((prev) => {
      const next = !prev;
      try {
        window.localStorage.setItem(SIDEBAR_STORAGE_KEY, next ? "1" : "0");
      } catch {
        // Ignore storage error
      }
      return next;
    });
  };

  const isStudio = pathname.startsWith("/studio");

  const isActiveRoute = (href: string) =>
    href === "/" ? pathname === "/" : pathname === href || pathname.startsWith(`${href}/`);

  const handleNavClick = (href: string) => {
    setMobileDrawerOpen(false);
    router.push(href);
  };

  const showBanners =
    !isStudio &&
    (goCoreHealth.status === "offline" ||
      goCoreHealth.status === "degraded" ||
      hunterHubHealth.status === "offline");

  return (
    <div className="min-h-screen flex bg-canvas text-ink-primary">
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:start-2 focus:z-50 focus:px-3 focus:py-2 focus:rounded-md focus:bg-sentinel-primary focus:text-sentinel-onAccent focus:text-xs focus:font-semibold"
      >
        {t("common.skipToContent")}
      </a>

      {/* Desktop Collapsible Sidebar Rail */}
      <aside
        aria-label="Primary Navigation"
        className={`hidden lg:flex flex-col shrink-0 border-e border-border-subtle bg-surface sticky top-0 h-screen transition-[width] duration-150 ${
          collapsed ? "w-[72px]" : "w-60"
        }`}
      >
        <div className="h-14 px-3 border-b border-border-subtle flex items-center justify-between gap-2">
          <button
            type="button"
            onClick={() => handleNavClick("/")}
            className="flex items-center gap-2.5 min-w-0 text-start"
          >
            <div className="w-9 h-9 rounded-md bg-[var(--accent-primary-bg)] border border-[var(--accent-primary)]/35 flex items-center justify-center text-sentinel-primary shrink-0">
              <Shield className="w-5 h-5" />
            </div>
            {!collapsed && (
              <div className="min-w-0">
                <div className="font-bold text-sm tracking-tight text-ink-primary truncate">
                  {t("brand.name")}
                </div>
                <div className="text-[10px] font-mono text-ink-muted truncate">
                  {t("brand.engineTag")}
                </div>
              </div>
            )}
          </button>

          <button
            type="button"
            onClick={toggleCollapsed}
            aria-label={collapsed ? t("nav.expandSidebar") : t("nav.collapseSidebar")}
            title={collapsed ? t("nav.expandSidebar") : t("nav.collapseSidebar")}
            className="h-8 w-8 rounded border border-border-subtle bg-elevated hover:border-border-strong text-ink-muted hover:text-ink-primary flex items-center justify-center shrink-0"
          >
            {collapsed ? (
              dir === "rtl" ? <PanelLeftClose className="w-4 h-4" /> : <PanelLeftOpen className="w-4 h-4" />
            ) : (
              dir === "rtl" ? <PanelLeftOpen className="w-4 h-4" /> : <PanelLeftClose className="w-4 h-4" />
            )}
          </button>
        </div>

        <nav className="flex-1 overflow-y-auto p-2 space-y-1">
          {NAV_ROUTES.map((item) => {
            const Icon = item.icon;
            const active = isActiveRoute(item.href);
            return (
              <button
                key={item.href}
                type="button"
                onClick={() => handleNavClick(item.href)}
                title={collapsed ? t(item.labelKey) : undefined}
                aria-current={active ? "page" : undefined}
                className={`w-full min-h-[42px] px-2.5 py-2 rounded-md text-xs font-medium flex items-center gap-2.5 transition-colors ${
                  collapsed ? "justify-center" : "justify-start"
                } ${
                  active
                    ? "bg-[var(--accent-primary-bg)] text-sentinel-primary border border-[var(--accent-primary)]/35"
                    : "text-ink-secondary hover:bg-elevated hover:text-ink-primary border border-transparent"
                }`}
              >
                <Icon className="w-4 h-4 shrink-0" />
                {!collapsed && <span className="truncate">{t(item.labelKey)}</span>}
                {!collapsed && item.href === "/" && pendingApprovalsCount > 0 && (
                  <span className="ms-auto px-1.5 py-0.5 rounded-full text-[10px] font-mono tabular-nums bg-[var(--accent-warning-bg)] text-sentinel-warning border border-[var(--accent-warning)]/30">
                    {pendingApprovalsCount}
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        {!collapsed && (
          <div className="p-3 border-t border-border-subtle text-[11px] font-mono text-ink-muted space-y-1">
            <div className="flex items-center justify-between">
              <span>{t("nav.hunterHub")}</span>
              <span
                className={
                  hunterHubHealth.status === "connected"
                    ? "text-sentinel-success"
                    : "text-sentinel-danger"
                }
              >
                {hunterHubHealth.status === "connected" ? t("status.connected") : t("status.offline")}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span>{t("nav.goCore")}</span>
              <span
                className={
                  goCoreHealth.status === "connected"
                    ? "text-sentinel-success"
                    : goCoreHealth.status === "degraded"
                      ? "text-sentinel-warning"
                      : "text-ink-muted"
                }
              >
                {goCoreHealth.status === "connected"
                  ? t("status.connected")
                  : goCoreHealth.status === "degraded"
                    ? t("status.degraded")
                    : t("status.offline")}
              </span>
            </div>
          </div>
        )}
      </aside>

      {/* Mobile Slide-Over Navigation Drawer (<1024px) */}
      {mobileDrawerOpen && (
        <div
          className="fixed inset-0 z-50 lg:hidden flex bg-black/55 backdrop-blur-[1px]"
          onClick={() => setMobileDrawerOpen(false)}
        >
          <aside
            role="dialog"
            aria-modal="true"
            aria-label="Mobile Navigation"
            onClick={(e) => e.stopPropagation()}
            className="w-72 max-w-[85vw] h-full bg-surface border-e border-border-subtle shadow-sentinelMd flex flex-col"
          >
            <div className="px-4 py-3 border-b border-border-subtle flex items-center justify-between gap-2">
              <div className="flex items-center gap-2.5 min-w-0">
                <div className="w-9 h-9 rounded-md bg-[var(--accent-primary-bg)] border border-[var(--accent-primary)]/35 flex items-center justify-center text-sentinel-primary shrink-0">
                  <Shield className="w-5 h-5" />
                </div>
                <div className="min-w-0">
                  <div className="font-bold text-sm text-ink-primary truncate">{t("brand.name")}</div>
                  <div className="text-[11px] font-mono text-ink-muted truncate">{t("brand.engineTag")}</div>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setMobileDrawerOpen(false)}
                aria-label={t("common.close")}
                className="min-h-[44px] min-w-[44px] rounded-md border border-border-subtle bg-elevated text-ink-primary flex items-center justify-center"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <nav className="flex-1 overflow-y-auto p-3 space-y-1.5">
              {NAV_ROUTES.map((item) => {
                const Icon = item.icon;
                const active = isActiveRoute(item.href);
                return (
                  <button
                    key={item.href}
                    type="button"
                    onClick={() => handleNavClick(item.href)}
                    aria-current={active ? "page" : undefined}
                    className={`w-full min-h-[44px] px-3 py-2.5 rounded-md text-sm font-medium flex items-center gap-3 transition-colors ${
                      active
                        ? "bg-[var(--accent-primary-bg)] text-sentinel-primary border border-[var(--accent-primary)]/35"
                        : "text-ink-secondary hover:bg-elevated hover:text-ink-primary border border-transparent"
                    }`}
                  >
                    <Icon className="w-4 h-4 shrink-0" />
                    <span className="truncate">{t(item.labelKey)}</span>
                  </button>
                );
              })}
            </nav>
          </aside>
        </div>
      )}

      {/* Main Column */}
      <div className="flex-1 min-w-0 flex flex-col min-h-screen">
        <Navbar
          mobileNavOpen={mobileDrawerOpen}
          onToggleMobileNav={() => setMobileDrawerOpen((prev) => !prev)}
        />

        <main
          id="main-content"
          className={
            isStudio
              ? "flex-1 min-w-0 flex flex-col"
              : "flex-1 min-w-0 max-w-[1480px] w-full mx-auto px-4 sm:px-6 py-5 space-y-5"
          }
        >
          {showBanners && (
            <div className="space-y-2" role="status" aria-live="polite">
              {hunterHubHealth.status === "offline" && (
                <div className="px-4 py-2.5 rounded-md border border-[var(--accent-warning)]/35 bg-[var(--accent-warning-bg)] text-sentinel-warning text-xs flex items-center gap-2">
                  <Radio className="w-4 h-4 shrink-0" />
                  <span>{t("status.hubOfflineBanner")}</span>
                </div>
              )}
              {goCoreHealth.status === "degraded" && (
                <div className="px-4 py-2.5 rounded-md border border-[var(--accent-warning)]/35 bg-[var(--accent-warning-bg)] text-sentinel-warning text-xs flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>
                    {t("status.goDegradedBanner")}
                    {goCoreHealth.error ? ` (${goCoreHealth.error})` : ""}
                  </span>
                </div>
              )}
              {goCoreHealth.status === "offline" && hunterHubHealth.status === "connected" && (
                <div className="px-4 py-2 rounded-md border border-border-subtle bg-surface text-ink-muted text-xs flex items-center gap-2">
                  <Database className="w-3.5 h-3.5 shrink-0 text-sentinel-danger" />
                  <span>{t("status.goOfflineBanner")}</span>
                </div>
              )}
            </div>
          )}

          {children}
        </main>

        {!isStudio && (
          <footer className="border-t border-border-subtle bg-surface py-3 px-4 text-center text-xs text-ink-muted font-mono">
            {t("brand.footer")}
          </footer>
        )}
      </div>

      <CommandPalette />
      <CopilotDrawer />
    </div>
  );
}
