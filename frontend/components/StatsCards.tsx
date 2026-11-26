"use client";

import React from "react";
import { Globe, Server, ShieldAlert, Cpu } from "lucide-react";
import { usePlatform } from "@/lib/platform-context";
import { useI18n } from "@/lib/i18n";

export default function StatsCards() {
  const { stats, assets, findings, runs, tasks, goCoreHealth, hunterHubHealth, isLoading } =
    usePlatform();
  const { t } = useI18n();

  const liveEndpointsCount = assets.filter(
    (a) => Boolean(a.attributes?.status_code) || Boolean(a.attributes?.live_url)
  ).length;

  const activeRunsCount = runs.filter((r) =>
    ["running", "paused", "pending", "queued", "waiting"].includes((r.status || "").toLowerCase())
  ).length;
  const activeTasksCount = tasks.filter((tk) =>
    ["RUNNING", "PENDING", "QUEUED"].includes((tk.status || "").toUpperCase())
  ).length;
  const activeExecutionCount = activeRunsCount + activeTasksCount;

  const goOffline = goCoreHealth.status === "offline";
  const allOffline = goOffline && hunterHubHealth.status === "offline";

  const indexedAssetsValue =
    allOffline
      ? t("status.offline")
      : (stats.total_assets || assets.length).toLocaleString();

  const liveEndpointsValue =
    allOffline ? t("status.offline") : liveEndpointsCount.toLocaleString();

  const findingsValue =
    allOffline
      ? t("status.offline")
      : (stats.total_findings || findings.length).toLocaleString();

  const activeExecutionValue = allOffline
    ? t("status.offline")
    : activeExecutionCount.toLocaleString();

  const cards = [
    {
      label: t("stats.assetsLabel"),
      value: isLoading ? "…" : indexedAssetsValue,
      desc: t("stats.assetsDesc"),
      icon: Globe,
      iconColor: "text-sentinel-primary",
      accentBg: "bg-sentinel-primary/15",
      offline: allOffline,
    },
    {
      label: t("stats.endpointsLabel"),
      value: isLoading ? "…" : liveEndpointsValue,
      desc: t("stats.endpointsDesc"),
      icon: Server,
      iconColor: "text-sentinel-success",
      accentBg: "bg-sentinel-success/15",
      offline: allOffline,
    },
    {
      label: t("stats.findingsLabel"),
      value: isLoading ? "…" : findingsValue,
      desc: t("stats.findingsDesc"),
      icon: ShieldAlert,
      iconColor: "text-sentinel-warning",
      accentBg: "bg-sentinel-warning/15",
      offline: allOffline,
    },
    {
      label: t("stats.runsLabel"),
      value: isLoading ? "…" : activeExecutionValue,
      desc: t("stats.runsDesc"),
      icon: Cpu,
      iconColor: "text-sentinel-ai",
      accentBg: "bg-sentinel-ai/15",
      offline: allOffline,
    },
  ];

  return (
    <section
      aria-label={t("stats.sectionAriaLabel")}
      className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4"
    >
      {cards.map((card) => {
        const Icon = card.icon;
        return (
          <div
            key={card.label}
            className="sentinel-surface p-4 flex flex-col justify-between gap-2.5 transition-colors hover:border-border-strong"
          >
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-semibold uppercase tracking-wider text-ink-muted">
                {card.label}
              </span>
              <span
                className={`w-8 h-8 rounded-md ${card.accentBg} flex items-center justify-center shrink-0`}
              >
                <Icon className={`w-4 h-4 ${card.iconColor}`} />
              </span>
            </div>

            <div
              className={`text-2xl font-bold font-mono tabular-nums ${
                card.offline ? "text-ink-muted text-lg" : "text-ink-primary"
              }`}
            >
              {card.value}
            </div>

            <div className="text-xs text-ink-muted truncate">{card.desc}</div>
          </div>
        );
      })}
    </section>
  );
}
