"use client";

import React from "react";
import { Globe, Server, AlertTriangle, Layers, Cpu } from "lucide-react";

interface StatsProps {
  totalAssets: number;
  liveEndpoints: number;
  totalFindings: number;
  activeAgents: number;
}

export default function StatsCards({ totalAssets, liveEndpoints, totalFindings, activeAgents }: StatsProps) {
  const cards = [
    {
      label: "Indexed Assets",
      value: totalAssets.toLocaleString(),
      desc: "PostgreSQL asset nodes",
      icon: Globe,
      color: "text-cyan-400",
      border: "border-cyan-500/20",
      bg: "bg-cyan-500/5",
    },
    {
      label: "Live HTTP Endpoints",
      value: liveEndpoints.toLocaleString(),
      desc: "Verified responsive hosts",
      icon: Server,
      color: "text-emerald-400",
      border: "border-emerald-500/20",
      bg: "bg-emerald-500/5",
    },
    {
      label: "Triaged Vulnerabilities",
      value: totalFindings.toLocaleString(),
      desc: "Validated bug bounty leads",
      icon: AlertTriangle,
      color: "text-amber-400",
      border: "border-amber-500/20",
      bg: "bg-amber-500/5",
    },
    {
      label: "Autonomous Agents",
      value: activeAgents.toString(),
      desc: "Norma-style Go Goroutines",
      icon: Cpu,
      color: "text-purple-400",
      border: "border-purple-500/20",
      bg: "bg-purple-500/5",
    },
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {cards.map((card, idx) => {
        const Icon = card.icon;
        return (
          <div
            key={idx}
            className={`p-5 rounded-xl border ${card.border} ${card.bg} backdrop-blur-sm transition-all hover:translate-y-[-2px]`}
          >
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs uppercase font-medium text-gray-400 tracking-wider">
                {card.label}
              </span>
              <Icon className={`w-5 h-5 ${card.color}`} />
            </div>
            <div className="text-3xl font-bold font-mono text-white mb-1">
              {card.value}
            </div>
            <div className="text-xs text-gray-400">{card.desc}</div>
          </div>
        );
      })}
    </div>
  );
}
