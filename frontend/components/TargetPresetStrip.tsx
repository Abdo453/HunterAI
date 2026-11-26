"use client";

import React from "react";
import { Globe, Server, Sparkles } from "lucide-react";
import {
  TARGET_PRESETS,
  TargetPreset,
  getPresetCategoryBadgeClasses,
  getPresetDescription,
} from "@/lib/target-presets";
import { useI18n } from "@/lib/i18n";

interface TargetPresetStripProps {
  testId: string;
  heading: string;
  subtitle?: string;
  activeTarget?: string;
  onSelect: (preset: TargetPreset) => void;
}

/**
 * Reusable 1-click preset pill strip for public practice targets and local pentest labs.
 */
export default function TargetPresetStrip({
  testId,
  heading,
  subtitle,
  activeTarget = "",
  onSelect,
}: TargetPresetStripProps) {
  const { lang, t } = useI18n();
  const normalizedActive = activeTarget.trim();

  return (
    <div
      data-testid={testId}
      className="rounded-md border border-border-subtle bg-inset/70 p-2.5 space-y-2"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-1.5 min-w-0">
          <Sparkles className="w-3.5 h-3.5 text-sentinel-primary shrink-0" />
          <span className="text-xs font-semibold text-ink-primary truncate">{heading}</span>
        </div>
        {subtitle && <span className="text-[11px] text-ink-muted">{subtitle}</span>}
      </div>

      <div className="flex flex-wrap gap-1.5">
        {TARGET_PRESETS.map((preset) => {
          const isSelected = normalizedActive === preset.target;
          const isPublic = preset.category === "public_demo";
          const badgeLabel = isPublic
            ? t("targets.presetBadgePublic")
            : t("targets.presetBadgeLab");
          const desc = getPresetDescription(preset, lang);

          return (
            <button
              key={preset.id}
              type="button"
              onClick={() => onSelect(preset)}
              aria-pressed={isSelected}
              title={`${preset.label} — ${desc} (${preset.tags.join(", ")})`}
              className={`max-w-full min-h-[32px] px-2.5 py-1 rounded-md border text-xs transition-colors flex flex-wrap items-center gap-1.5 text-start ${
                isSelected
                  ? "border-sentinel-primary bg-[var(--accent-primary-bg)] text-ink-primary"
                  : "border-border-subtle bg-elevated/70 hover:bg-elevated hover:border-border-strong text-ink-secondary hover:text-ink-primary"
              }`}
            >
              <span
                className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono border shrink-0 ${getPresetCategoryBadgeClasses(
                  preset.category
                )}`}
              >
                {isPublic ? (
                  <Globe className="w-2.5 h-2.5 shrink-0" />
                ) : (
                  <Server className="w-2.5 h-2.5 shrink-0" />
                )}
                <span>{badgeLabel}</span>
              </span>
              <span className="font-medium text-ink-primary truncate max-w-[180px]">
                {preset.label}
              </span>
              <span className="ltr-isolate font-mono text-[11px] text-sentinel-primary truncate max-w-[220px]">
                {preset.target}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
