"use client";

import React, { useMemo } from "react";
import { Network, Database, Layers, ExternalLink } from "lucide-react";

interface Asset {
  id: string;
  kind: string;
  value: string;
  attributes: Record<string, any>;
  created_at: string;
}

interface AssetDualGraphProps {
  assets: Asset[];
  target: string;
}

export default function AssetDualGraph({ assets, target }: AssetDualGraphProps) {
  // Sample up to 15 subdomains to render an attack surface node topology
  const sampleNodes = useMemo(() => {
    return assets.slice(0, 16);
  }, [assets]);

  return (
    <div className="bg-[#0f172a]/90 border border-gray-800 rounded-xl p-5 flex flex-col h-[460px]">
      <div className="flex items-center justify-between pb-3 border-b border-gray-800 mb-4">
        <div className="flex items-center gap-2">
          <Network className="w-5 h-5 text-cyan-400" />
          <h3 className="font-semibold text-sm text-gray-200">
            Attack Surface Topology & Dual Graph (PostgreSQL `asset_nodes`)
          </h3>
        </div>
        <div className="flex items-center gap-2 text-xs font-mono text-gray-400">
          <span className="w-2 h-2 rounded-full bg-cyan-400" />
          <span>Root: {target || "Active Target"}</span>
          <span className="text-gray-600">|</span>
          <span>Sample: {sampleNodes.length} nodes</span>
        </div>
      </div>

      {sampleNodes.length === 0 ? (
        <div className="flex-1 flex flex-col items-center justify-center text-gray-500">
          <Database className="w-10 h-10 mb-2 opacity-40 text-cyan-500" />
          <p className="text-sm">No asset nodes indexed in PostgreSQL yet.</p>
          <p className="text-xs text-gray-600 mt-1">Run an autonomous mission to populate the attack graph.</p>
        </div>
      ) : (
        <div className="flex-1 overflow-y-auto pr-2 space-y-2">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
            {sampleNodes.map((asset, index) => {
              const liveUrl = asset.attributes?.live_url;
              const title = asset.attributes?.title;
              const statusCode = asset.attributes?.status_code;
              const tech = asset.attributes?.tech;

              return (
                <div
                  key={asset.id || index}
                  className="p-3 rounded-lg bg-[#1e293b]/50 border border-gray-800/80 hover:border-cyan-500/40 transition-all flex flex-col justify-between"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="font-mono text-xs text-cyan-300 truncate max-w-[240px]">
                      {asset.value}
                    </div>
                    {statusCode ? (
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                        {statusCode}
                      </span>
                    ) : (
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-gray-800 text-gray-400">
                        DNS
                      </span>
                    )}
                  </div>

                  {title && (
                    <div className="text-[11px] text-gray-400 truncate mt-1 italic">
                      "{title}"
                    </div>
                  )}

                  <div className="flex items-center justify-between mt-2 pt-1.5 border-t border-gray-800/60 text-[10px] text-gray-500">
                    <div className="flex items-center gap-1">
                      {tech && Array.isArray(tech) && tech.length > 0 ? (
                        <span className="text-cyan-400/80">{tech.slice(0, 2).join(", ")}</span>
                      ) : (
                        <span>Source: subfinder</span>
                      )}
                    </div>
                    {liveUrl && (
                      <a
                        href={liveUrl}
                        target="_blank"
                        rel="noreferrer"
                        className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300"
                      >
                        Visit <ExternalLink className="w-2.5 h-2.5" />
                      </a>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
