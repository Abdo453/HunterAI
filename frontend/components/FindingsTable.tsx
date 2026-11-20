"use client";

import React from "react";
import { AlertCircle, ShieldAlert, CheckCircle2, Terminal } from "lucide-react";

interface Finding {
  id: string;
  title: string;
  vuln_class: string;
  severity: string;
  cvss_score: number;
  endpoint: string;
  status: string;
  created_at: string;
}

interface FindingsTableProps {
  findings: Finding[];
}

export default function FindingsTable({ findings }: FindingsTableProps) {
  const getSeverityBadge = (sev: string) => {
    switch (sev.toLowerCase()) {
      case "critical":
        return "bg-rose-950/80 text-rose-300 border-rose-800";
      case "high":
        return "bg-orange-950/80 text-orange-300 border-orange-800";
      case "medium":
        return "bg-amber-950/80 text-amber-300 border-amber-800";
      default:
        return "bg-cyan-950/80 text-cyan-300 border-cyan-800";
    }
  };

  return (
    <div className="bg-[#0f172a]/90 border border-gray-800 rounded-xl p-5 flex flex-col h-[460px]">
      <div className="flex items-center justify-between pb-3 border-b border-gray-800 mb-4">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-amber-400" />
          <h3 className="font-semibold text-sm text-gray-200">
            Validated Vulnerability Findings & 7-Question Gate Dossier
          </h3>
        </div>
        <span className="text-xs font-mono px-2 py-0.5 rounded bg-gray-800 text-gray-300">
          {findings.length} findings
        </span>
      </div>

      {findings.length === 0 ? (
        <div className="flex-1 flex flex-col items-center justify-center text-gray-500">
          <CheckCircle2 className="w-10 h-10 mb-2 opacity-30 text-emerald-400" />
          <p className="text-sm">No vulnerability findings recorded yet.</p>
          <p className="text-xs text-gray-600 mt-1">Autonomous workers will index verified leads here.</p>
        </div>
      ) : (
        <div className="flex-1 overflow-y-auto pr-1">
          <div className="space-y-2.5">
            {findings.map((f) => (
              <div
                key={f.id}
                className="p-3.5 rounded-lg bg-[#1e293b]/50 border border-gray-800 hover:border-gray-700 transition-colors"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-semibold ${getSeverityBadge(f.severity)}`}>
                        {f.severity} {f.cvss_score.toFixed(1)}
                      </span>
                      <h4 className="font-semibold text-xs text-white">{f.title}</h4>
                    </div>
                    <div className="font-mono text-xs text-gray-400 truncate max-w-lg mt-1">
                      {f.endpoint}
                    </div>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-gray-850 text-emerald-400 border border-emerald-900/60">
                    {f.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
