/* ==========================================================================
   HunterAI Control Center — Offline HTML5 Canvas System Health Charts
   Zero external libraries or CDNs — renders CPU, RAM, Disk I/O, Network
   ========================================================================== */
(function (global) {
  "use strict";

  const MAX_POINTS = 60;

  const SERIES_CONFIG = {
    cpu: {
      canvasId: "chart-cpu",
      valueId: "val-cpu",
      color: "#06b6d4",
      fillTop: "rgba(6, 182, 212, 0.30)",
      fillBot: "rgba(6, 182, 212, 0.02)",
      fixedMax: 100,
      threshold: 80,
      thresholdColor: "rgba(245, 158, 11, 0.65)",
      unit: "%",
      decimals: 1,
    },
    ram: {
      canvasId: "chart-ram",
      valueId: "val-ram",
      color: "#10b981",
      fillTop: "rgba(16, 185, 129, 0.28)",
      fillBot: "rgba(16, 185, 129, 0.02)",
      fixedMax: 100,
      threshold: 90,
      thresholdColor: "rgba(239, 68, 68, 0.72)",
      unit: "%",
      decimals: 1,
    },
    disk: {
      canvasId: "chart-disk",
      valueId: "val-disk",
      color: "#f59e0b",
      fillTop: "rgba(245, 158, 11, 0.28)",
      fillBot: "rgba(245, 158, 11, 0.02)",
      fixedMax: null,
      minScaleMax: 1.0,
      threshold: null,
      unit: " MB/s",
      decimals: 2,
    },
    net: {
      canvasId: "chart-net",
      valueId: "val-net",
      color: "#8b5cf6",
      fillTop: "rgba(139, 92, 246, 0.30)",
      fillBot: "rgba(139, 92, 246, 0.02)",
      fixedMax: null,
      minScaleMax: 1.0,
      threshold: null,
      unit: " MB/s",
      decimals: 2,
    },
  };

  const state = {
    series: {
      cpu: [],
      ram: [],
      disk: [],
      net: [],
    },
    cpuHighSinceTs: null,
    lastSampleTs: 0,
    initialized: false,
  };

  function toNumber(val, fallback) {
    const n = Number(val);
    return Number.isFinite(n) ? n : fallback;
  }

  function extractSnapshot(raw) {
    if (!raw || typeof raw !== "object") return null;

    const current = raw.current && typeof raw.current === "object" ? raw.current : raw;

    const cpu = toNumber(
      current.cpu_percent ?? current.cpu ?? current.cpu_pct,
      null
    );
    const ram = toNumber(
      current.ram_percent ?? current.memory_percent ?? current.mem_percent ?? current.ram,
      null
    );

    let disk = toNumber(
      current.disk_io_mb_s ?? current.disk_mb_s ?? current.disk_io_mbs ?? current.disk_io,
      null
    );
    if (disk === null) {
      const readMb = toNumber(current.disk_read_mb_s ?? current.disk_read_mbs, 0);
      const writeMb = toNumber(current.disk_write_mb_s ?? current.disk_write_mbs, 0);
      if (
        current.disk_read_mb_s !== undefined ||
        current.disk_write_mb_s !== undefined ||
        current.disk_read_mbs !== undefined ||
        current.disk_write_mbs !== undefined
      ) {
        disk = readMb + writeMb;
      } else if (current.disk_io_kbps !== undefined) {
        disk = toNumber(current.disk_io_kbps, 0) / 1024;
      }
    }

    let net = toNumber(
      current.net_mb_s ??
        current.network_mb_s ??
        current.net_throughput_mb_s ??
        current.network_mbs ??
        current.network,
      null
    );
    if (net === null) {
      const sentMb = toNumber(current.net_sent_mb_s ?? current.net_tx_mb_s, 0);
      const recvMb = toNumber(current.net_recv_mb_s ?? current.net_rx_mb_s, 0);
      if (
        current.net_sent_mb_s !== undefined ||
        current.net_recv_mb_s !== undefined ||
        current.net_tx_mb_s !== undefined ||
        current.net_rx_mb_s !== undefined
      ) {
        net = sentMb + recvMb;
      } else if (
        current.net_throughput_kb_s !== undefined ||
        current.net_kbps !== undefined ||
        current.network_kbps !== undefined
      ) {
        net = toNumber(
          current.net_throughput_kb_s ?? current.net_kbps ?? current.network_kbps,
          0
        ) / 1024;
      } else if (current.net_bytes_sec !== undefined) {
        net = toNumber(current.net_bytes_sec, 0) / (1024 * 1024);
      }
    }

    const diskFreeGb = toNumber(
      current.disk_free_gb ?? current.free_disk_gb ?? raw.disk_free_gb,
      null
    );

    const ts = toNumber(current.timestamp ?? raw.timestamp, Date.now() / 1000);

    return {
      cpu: cpu !== null ? Math.max(0, Math.min(100, cpu)) : 0,
      ram: ram !== null ? Math.max(0, Math.min(100, ram)) : 0,
      disk: disk !== null ? Math.max(0, disk) : 0,
      net: net !== null ? Math.max(0, net) : 0,
      diskFreeGb,
      ts,
      hasCpu: cpu !== null,
      hasRam: ram !== null,
    };
  }

  function pushPoint(key, value) {
    const arr = state.series[key];
    arr.push(value);
    if (arr.length > MAX_POINTS) {
      arr.splice(0, arr.length - MAX_POINTS);
    }
  }

  function hydrateFromHistory(raw) {
    const hist = raw.history || raw.samples || raw.series;
    if (!hist) return false;

    if (Array.isArray(hist) && hist.length > 0) {
      state.series.cpu = [];
      state.series.ram = [];
      state.series.disk = [];
      state.series.net = [];

      const slice = hist.slice(-MAX_POINTS);
      for (const item of slice) {
        const snap = extractSnapshot(item);
        if (snap) {
          pushPoint("cpu", snap.cpu);
          pushPoint("ram", snap.ram);
          pushPoint("disk", snap.disk);
          pushPoint("net", snap.net);
        }
      }
      const lastItem = slice[slice.length - 1];
      const lastSnap = extractSnapshot(lastItem);
      if (lastSnap) {
        state.lastSampleTs = lastSnap.ts;
      }
      return true;
    }

    if (typeof hist === "object" && !Array.isArray(hist)) {
      let hydrated = false;
      const mapKeys = {
        cpu: hist.cpu || hist.cpu_percent,
        ram: hist.ram || hist.ram_percent || hist.memory_percent,
        disk: hist.disk || hist.disk_io || hist.disk_io_mb_s,
        net: hist.net || hist.network || hist.net_mb_s || hist.network_mb_s,
      };
      for (const [k, arr] of Object.entries(mapKeys)) {
        if (Array.isArray(arr) && arr.length > 0) {
          state.series[k] = arr.slice(-MAX_POINTS).map((v) => Math.max(0, toNumber(v, 0)));
          hydrated = true;
        }
      }
      return hydrated;
    }

    return false;
  }

  function escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = String(text ?? "");
    return div.innerHTML;
  }

  function renderAlerts(raw, latestSnap) {
    const container = document.getElementById("system-health-alerts");
    if (!container) return;

    const alerts = [];
    const seenMsgs = new Set();

    function addAlert(level, message) {
      const msg = String(message || "").trim();
      if (!msg || seenMsgs.has(msg)) return;
      seenMsgs.add(msg);
      alerts.push({ level, message: msg });
    }

    if (raw && Array.isArray(raw.alerts)) {
      for (const a of raw.alerts) {
        if (typeof a === "string") {
          const lvl = a.includes("🔴") || a.toLowerCase().includes("ram") || a.toLowerCase().includes("critical")
            ? "critical"
            : "warning";
          addAlert(lvl, a);
        } else if (a && typeof a === "object") {
          const msg = a.message || a.text || a.label || a.title || JSON.stringify(a);
          const lvl = String(a.level || a.severity || "warning").toLowerCase();
          addAlert(lvl === "critical" || lvl === "error" ? "critical" : "warning", msg);
        }
      }
    }

    // Defensive client-side threshold evaluation
    if (latestSnap) {
      const nowMs = Date.now();
      if (latestSnap.cpu > 80) {
        if (state.cpuHighSinceTs === null) state.cpuHighSinceTs = nowMs;
        if (nowMs - state.cpuHighSinceTs >= 30000) {
          addAlert("warning", "🟡 CPU > 80% for 30s");
        }
      } else {
        state.cpuHighSinceTs = null;
      }

      if (latestSnap.ram > 90) {
        addAlert("critical", "🔴 RAM > 90%");
      }

      if (latestSnap.diskFreeGb !== null && latestSnap.diskFreeGb < 1.0) {
        addAlert("warning", `🟡 Disk < 1GB free (${latestSnap.diskFreeGb.toFixed(2)} GB)`);
      }
    }

    if (alerts.length === 0) {
      container.innerHTML =
        '<span class="health-alert-pill health-alert-ok">🟢 All system health thresholds nominal</span>';
      return;
    }

    container.innerHTML = alerts
      .map((a) => {
        const cls = a.level === "critical" ? "health-alert-critical" : "health-alert-warning";
        return `<span class="health-alert-pill ${cls}">${escapeHtml(a.message)}</span>`;
      })
      .join("");
  }

  function drawChart(key) {
    const cfg = SERIES_CONFIG[key];
    const canvas = document.getElementById(cfg.canvasId);
    if (!canvas) return;

    const parent = canvas.parentElement;
    const width = Math.max(180, (parent ? parent.clientWidth : canvas.clientWidth) || 300);
    const height = Math.max(100, (parent ? parent.clientHeight : canvas.clientHeight) || 130);
    const dpr = Math.min(global.devicePixelRatio || 1, 2);

    if (canvas.width !== Math.floor(width * dpr) || canvas.height !== Math.floor(height * dpr)) {
      canvas.width = Math.floor(width * dpr);
      canvas.height = Math.floor(height * dpr);
    }

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    ctx.save();
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, width, height);

    const pad = { top: 10, right: 10, bottom: 20, left: 36 };
    const plotW = Math.max(20, width - pad.left - pad.right);
    const plotH = Math.max(20, height - pad.top - pad.bottom);

    const rawData = state.series[key];
    const data = rawData.length > 0 ? rawData : [0];

    let maxVal = cfg.fixedMax;
    if (maxVal === null) {
      const peak = Math.max(...data, cfg.minScaleMax || 1.0);
      maxVal = peak <= 1 ? 1 : peak <= 5 ? Math.ceil(peak) : Math.ceil(peak * 1.15);
    }

    // Background grid
    ctx.strokeStyle = "rgba(31, 41, 55, 0.75)";
    ctx.lineWidth = 1;
    const rows = 4;
    ctx.font = '10px "JetBrains Mono", ui-monospace, monospace';
    ctx.fillStyle = "#6b7280";
    ctx.textAlign = "right";
    ctx.textBaseline = "middle";

    for (let i = 0; i <= rows; i++) {
      const y = pad.top + (plotH * i) / rows;
      ctx.beginPath();
      ctx.moveTo(pad.left, y);
      ctx.lineTo(pad.left + plotW, y);
      ctx.stroke();

      const labelVal = maxVal * (1 - i / rows);
      const labelTxt = cfg.fixedMax === 100
        ? `${Math.round(labelVal)}`
        : labelVal >= 10
        ? `${labelVal.toFixed(0)}`
        : `${labelVal.toFixed(1)}`;
      ctx.fillText(labelTxt, pad.left - 5, y);
    }

    // X-axis labels
    ctx.textAlign = "left";
    ctx.textBaseline = "top";
    ctx.fillText("-60s", pad.left, pad.top + plotH + 5);
    ctx.textAlign = "center";
    ctx.fillText("-30s", pad.left + plotW / 2, pad.top + plotH + 5);
    ctx.textAlign = "right";
    ctx.fillText("now", pad.left + plotW, pad.top + plotH + 5);

    // Optional threshold line
    if (cfg.threshold !== null && cfg.threshold <= maxVal) {
      const ty = pad.top + plotH * (1 - cfg.threshold / maxVal);
      ctx.save();
      ctx.setLineDash([4, 4]);
      ctx.strokeStyle = cfg.thresholdColor;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(pad.left, ty);
      ctx.lineTo(pad.left + plotW, ty);
      ctx.stroke();
      ctx.restore();
    }

    // Map points right-aligned over MAX_POINTS window
    const count = data.length;
    const stepX = plotW / Math.max(MAX_POINTS - 1, 1);
    const startIdx = MAX_POINTS - count;
    const points = data.map((val, idx) => {
      const clamped = Math.max(0, Math.min(maxVal, val));
      const x = pad.left + (startIdx + idx) * stepX;
      const y = pad.top + plotH * (1 - clamped / maxVal);
      return { x, y };
    });

    if (points.length === 1) {
      points.unshift({ x: pad.left, y: points[0].y });
    }

    // Area gradient fill
    const grad = ctx.createLinearGradient(0, pad.top, 0, pad.top + plotH);
    grad.addColorStop(0, cfg.fillTop);
    grad.addColorStop(1, cfg.fillBot);

    ctx.beginPath();
    ctx.moveTo(points[0].x, pad.top + plotH);
    for (const pt of points) {
      ctx.lineTo(pt.x, pt.y);
    }
    ctx.lineTo(points[points.length - 1].x, pad.top + plotH);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();

    // Line stroke
    ctx.beginPath();
    ctx.moveTo(points[0].x, points[0].y);
    for (let i = 1; i < points.length; i++) {
      ctx.lineTo(points[i].x, points[i].y);
    }
    ctx.strokeStyle = cfg.color;
    ctx.lineWidth = 2;
    ctx.lineJoin = "round";
    ctx.lineCap = "round";
    ctx.stroke();

    // Latest point beacon
    const last = points[points.length - 1];
    ctx.beginPath();
    ctx.arc(last.x, last.y, 3.5, 0, Math.PI * 2);
    ctx.fillStyle = "#ffffff";
    ctx.fill();
    ctx.lineWidth = 2;
    ctx.strokeStyle = cfg.color;
    ctx.stroke();

    ctx.restore();
  }

  function updateValueLabels(snap) {
    if (!snap) return;
    const vals = {
      cpu: snap.cpu,
      ram: snap.ram,
      disk: snap.disk,
      net: snap.net,
    };
    for (const [k, cfg] of Object.entries(SERIES_CONFIG)) {
      const el = document.getElementById(cfg.valueId);
      if (el) {
        el.textContent = `${vals[k].toFixed(cfg.decimals)}${cfg.unit}`;
      }
    }
    const diskEl = document.getElementById("health-disk-free");
    if (diskEl && snap.diskFreeGb !== null) {
      diskEl.textContent = `Disk Free: ${snap.diskFreeGb.toFixed(2)} GB`;
    }
  }

  function renderAll() {
    drawChart("cpu");
    drawChart("ram");
    drawChart("disk");
    drawChart("net");
  }

  function update(raw) {
    if (!raw || typeof raw !== "object") return;

    const didHydrate = hydrateFromHistory(raw);
    const snap = extractSnapshot(raw);

    if (!didHydrate && snap) {
      pushPoint("cpu", snap.cpu);
      pushPoint("ram", snap.ram);
      pushPoint("disk", snap.disk);
      pushPoint("net", snap.net);
    } else if (didHydrate && snap && snap.hasCpu && snap.ts > state.lastSampleTs + 0.25) {
      // Ensure latest sample is reflected if history didn't include current snapshot
      const lastCpu = state.series.cpu[state.series.cpu.length - 1];
      if (state.series.cpu.length === 0 || Math.abs(lastCpu - snap.cpu) > 0.001) {
        pushPoint("cpu", snap.cpu);
        pushPoint("ram", snap.ram);
        pushPoint("disk", snap.disk);
        pushPoint("net", snap.net);
      }
      state.lastSampleTs = snap.ts;
    }

    updateValueLabels(snap);
    renderAlerts(raw, snap);
    renderAll();
  }

  function reset() {
    state.series.cpu = [];
    state.series.ram = [];
    state.series.disk = [];
    state.series.net = [];
    state.cpuHighSinceTs = null;
    updateValueLabels({ cpu: 0, ram: 0, disk: 0, net: 0, diskFreeGb: null });
    renderAlerts({}, null);
    renderAll();
  }

  function init() {
    if (state.initialized) return;
    state.initialized = true;
    renderAll();

    if (typeof ResizeObserver !== "undefined") {
      const ro = new ResizeObserver(() => renderAll());
      for (const cfg of Object.values(SERIES_CONFIG)) {
        const el = document.getElementById(cfg.canvasId);
        if (el && el.parentElement) {
          ro.observe(el.parentElement);
        }
      }
    } else {
      global.addEventListener("resize", renderAll);
    }
  }

  global.HunterCharts = {
    init,
    update,
    renderAll,
    reset,
  };
})(window);
