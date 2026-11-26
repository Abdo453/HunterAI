"use client";

import React from "react";
import { Filter } from "lucide-react";
import { usePlatform } from "@/lib/platform-context";
import { useI18n } from "@/lib/i18n";

export default function TaskFilterDropdown() {
  const { tasks, runs, activeTaskFilter, setActiveTaskFilter } = usePlatform();
  const { t } = useI18n();

  return (
    <label className="inline-flex items-center gap-1.5 text-xs">
      <Filter className="w-3.5 h-3.5 text-sentinel-primary shrink-0" />
      <span className="sr-only">{t("taskTree.filterByTask")}</span>
      <select
        data-testid="task-filter-dropdown"
        aria-label={t("taskTree.filterByTask")}
        value={activeTaskFilter}
        onChange={(e) => setActiveTaskFilter(e.target.value)}
        className="h-8 px-2 rounded bg-inset border border-border-subtle text-xs text-ink-primary max-w-[200px] truncate"
      >
        <option value="ALL">{t("taskTree.allTasks")}</option>
        {tasks.map((tk) => (
          <option key={tk.id} value={tk.id}>
            {tk.agent_role}: {tk.title || tk.id}
          </option>
        ))}
        {runs.slice(0, 10).map((r) => (
          <option key={`run:${r.run_id}`} value={r.run_id}>
            {r.kind}: {r.target || r.run_id}
          </option>
        ))}
      </select>
    </label>
  );
}
