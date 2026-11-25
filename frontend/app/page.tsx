"use client";

import React from "react";
import { AlertTriangle, Database, Radio } from "lucide-react";
import Navbar from "@/components/Navbar";
import StatsCards from "@/components/StatsCards";
import AssetDualGraph from "@/components/AssetDualGraph";
import FindingsTable from "@/components/FindingsTable";
import ApprovalsPanel from "@/components/ApprovalsPanel";
import LiveConsole from "@/components/LiveConsole";
import CopilotDrawer from "@/components/CopilotDrawer";
import { PlatformProvider, usePlatform } from "@/lib/platform-context";
import { useI18n } from "@/lib/i18n";

function DashboardContent() {
  const { goCoreHealth, hunterHubHealth } = usePlatform();
  const { t } = useI18n();

  return (
    <div className="flex flex-col min-h-screen bg-canvas text-ink-primary">
      <Navbar />

      <main className="flex-1 max-w-[1440px] w-full mx-auto px-4 sm:px-6 py-5 space-y-5">
        {/* Graceful Truthful Offline / Degraded Banners */}
        {(goCoreHealth.status === "offline" ||
          goCoreHealth.status === "degraded" ||
          hunterHubHealth.status === "offline") && (
          <div className="space-y-2" role="status" aria-live="polite">
            {goCoreHealth.status === "offline" && (
              <div className="px-4 py-2.5 rounded-md border border-[var(--accent-danger)]/35 bg-[var(--accent-danger-bg)] text-sentinel-danger text-xs flex items-center gap-2">
                <Database className="w-4 h-4 shrink-0" />
                <span>{t("status.goOfflineBanner")}</span>
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
            {hunterHubHealth.status === "offline" && (
              <div className="px-4 py-2.5 rounded-md border border-[var(--accent-warning)]/35 bg-[var(--accent-warning-bg)] text-sentinel-warning text-xs flex items-center gap-2">
                <Radio className="w-4 h-4 shrink-0" />
                <span>{t("status.hubOfflineBanner")}</span>
              </div>
            )}
          </div>
        )}

        {/* Top Telemetry Cards */}
        <StatsCards />

        {/* Dual Workspace: Topology Graph / Table + Findings */}
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
          <div className="xl:col-span-7">
            <AssetDualGraph />
          </div>
          <div className="xl:col-span-5">
            <FindingsTable />
          </div>
        </div>

        {/* Policy Approvals & Live Console */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          <div className="lg:col-span-5">
            <ApprovalsPanel />
          </div>
          <div className="lg:col-span-7">
            <LiveConsole />
          </div>
        </div>
      </main>

      <footer className="border-t border-border-subtle bg-surface py-3.5 px-4 text-center text-xs text-ink-muted font-mono">
        {t("brand.footer")}
      </footer>

      <CopilotDrawer />
    </div>
  );
}

export default function Home() {
  return (
    <PlatformProvider>
      <DashboardContent />
    </PlatformProvider>
  );
}
