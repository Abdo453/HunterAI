"use client";

import React, { useState, useEffect } from "react";
import Navbar from "@/components/Navbar";
import StatsCards from "@/components/StatsCards";
import AssetDualGraph from "@/components/AssetDualGraph";
import FindingsTable from "@/components/FindingsTable";
import { Terminal, Shield, RefreshCw } from "lucide-react";

const API_BASE = "http://127.0.0.1:7071/api/v1";

export default function Home() {
  const [target, setTarget] = useState("example.com");
  const [isScanning, setIsScanning] = useState(false);
  const [stats, setStats] = useState({
    total_assets: 0,
    total_findings: 0,
    total_engagements: 0,
  });
  const [assets, setAssets] = useState<any[]>([]);
  const [findings, setFindings] = useState<any[]>([]);
  const [logs, setLogs] = useState<string[]>([
    "[*] ARTEX-Pro Go Orchestrator Core Initialized.",
    "[*] Connected to PostgreSQL 16+ relational datastore.",
    "[*] Ready for autonomous reconnaissance and penetration testing missions.",
  ]);

  const addLog = (msg: string) => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs((prev) => [...prev.slice(-40), `[${timestamp}] ${msg}`]);
  };

  const fetchData = async () => {
    try {
      // 1. Stats
      const statsRes = await fetch(`${API_BASE}/stats`);
      if (statsRes.ok) {
        const statsData = await statsRes.json();
        setStats(statsData);
      }

      // 2. Assets
      const assetsRes = await fetch(`${API_BASE}/assets`);
      if (assetsRes.ok) {
        const assetsData = await assetsRes.json();
        if (Array.isArray(assetsData)) {
          setAssets(assetsData);
        }
      }

      // 3. Findings
      const findingsRes = await fetch(`${API_BASE}/findings`);
      if (findingsRes.ok) {
        const findingsData = await findingsRes.json();
        if (Array.isArray(findingsData)) {
          setFindings(findingsData);
        }
      }
    } catch (err) {
      // API might be starting up
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 4000);
    return () => clearInterval(interval);
  }, []);

  const handleLaunchMission = async (targetDomain: string) => {
    setTarget(targetDomain);
    setIsScanning(true);
    addLog(`🚀 Dispatching autonomous ARTEX-Pro pipeline against target: ${targetDomain}`);

    try {
      const res = await fetch(`${API_BASE}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: targetDomain }),
      });

      if (res.ok) {
        addLog(`[✓] Mission accepted by Go Orchestrator. Goroutines active.`);
      } else {
        addLog(`[-] Mission dispatch error: ${res.statusText}`);
      }
    } catch (err: any) {
      addLog(`[-] Could not contact Go API daemon: ${err.message}`);
    } finally {
      setTimeout(() => setIsScanning(false), 8000);
    }
  };

  return (
    <div className="flex flex-col min-h-screen">
      <Navbar onScan={handleLaunchMission} isScanning={isScanning} />

      <main className="flex-1 max-w-7xl w-full mx-auto p-6 space-y-6">
        {/* Top Metric Cards */}
        <StatsCards
          totalAssets={stats.total_assets}
          liveEndpoints={assets.filter((a) => a.attributes?.status_code).length}
          totalFindings={stats.total_findings}
          activeAgents={isScanning ? 4 : 1}
        />

        {/* Dual Panels: Asset Graph & Findings */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <AssetDualGraph assets={assets} target={target} />
          <FindingsTable findings={findings} />
        </div>

        {/* Live Terminal / Activity Stream */}
        <div className="bg-[#0f172a]/90 border border-gray-800 rounded-xl p-5">
          <div className="flex items-center justify-between pb-3 border-b border-gray-800 mb-3">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyan-400" />
              <h3 className="font-semibold text-xs text-gray-200 uppercase tracking-wider font-mono">
                Autonomous Mission Activity Stream & Goroutine Feed
              </h3>
            </div>
            <button
              onClick={fetchData}
              className="text-xs text-gray-400 hover:text-cyan-300 flex items-center gap-1"
            >
              <RefreshCw className="w-3 h-3" /> Refresh
            </button>
          </div>

          <div className="bg-black/60 rounded-lg p-3 font-mono text-xs text-gray-300 h-36 overflow-y-auto space-y-1">
            {logs.map((log, idx) => (
              <div key={idx} className="leading-relaxed">
                {log.includes("[-]") ? (
                  <span className="text-rose-400">{log}</span>
                ) : log.includes("[✓]") || log.includes("🚀") ? (
                  <span className="text-emerald-400 font-semibold">{log}</span>
                ) : (
                  <span className="text-cyan-300/80">{log}</span>
                )}
              </div>
            ))}
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-gray-900 bg-[#070b14] py-4 text-center text-xs text-gray-500 font-mono">
        ARTEX-Pro Unified Architecture • Go High-Concurrency Engine + PostgreSQL 16+ + Next.js 15
      </footer>
    </div>
  );
}
