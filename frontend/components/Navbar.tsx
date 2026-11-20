"use client";

import React, { useState } from "react";
import { Shield, Play, Terminal, Database, Cpu, Activity } from "lucide-react";

interface NavbarProps {
  onScan: (target: string) => void;
  isScanning: boolean;
}

export default function Navbar({ onScan, isScanning }: NavbarProps) {
  const [targetInput, setTargetInput] = useState("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (targetInput.trim()) {
      onScan(targetInput.trim());
    }
  };

  return (
    <header className="border-b border-gray-800 bg-[#0f172a]/80 backdrop-blur-md sticky top-0 z-50 px-6 py-3.5">
      <div className="max-w-7xl mx-auto flex items-center justify-between gap-4">
        {/* Brand */}
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.25)]">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-lg text-white tracking-wider">ARTEX-Pro</span>
              <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-cyan-900/60 text-cyan-300 border border-cyan-700/50">
                Go Core v2.0
              </span>
            </div>
            <p className="text-xs text-gray-400">Autonomous Multi-Agent Offensive Control Center</p>
          </div>
        </div>

        {/* Target Launch Bar */}
        <form onSubmit={handleSubmit} className="flex-1 max-w-lg flex items-center gap-2">
          <div className="relative flex-1">
            <input
              type="text"
              placeholder="Target domain (e.g. wolt.com, example.com)..."
              value={targetInput}
              onChange={(e) => setTargetInput(e.target.value)}
              className="w-full bg-[#1e293b]/80 border border-gray-700 rounded-lg px-4 py-2 text-sm text-gray-100 placeholder-gray-500 focus:outline-none focus:border-cyan-500 transition-colors"
            />
          </div>
          <button
            type="submit"
            disabled={isScanning || !targetInput.trim()}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-semibold shadow-lg shadow-cyan-600/30 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
          >
            {isScanning ? (
              <>
                <Activity className="w-4 h-4 animate-spin" />
                <span>Running...</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4 fill-white" />
                <span>Launch Mission</span>
              </>
            )}
          </button>
        </form>

        {/* System Badges */}
        <div className="hidden lg:flex items-center gap-4 text-xs font-mono">
          <div className="flex items-center gap-1.5 text-emerald-400 bg-emerald-950/40 border border-emerald-800/60 px-2.5 py-1 rounded-full">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>Go Goroutines: Active</span>
          </div>
          <div className="flex items-center gap-1.5 text-cyan-300 bg-cyan-950/40 border border-cyan-800/60 px-2.5 py-1 rounded-full">
            <Database className="w-3.5 h-3.5" />
            <span>PostgreSQL: 127.0.0.1</span>
          </div>
        </div>
      </div>
    </header>
  );
}
