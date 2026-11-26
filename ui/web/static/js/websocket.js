/* ==========================================================================
   HunterAI Control Center — WebSocket Streams, REST Fallback & UI Controller
   Connects to /ws/agents, /ws/findings, /ws/metrics, /ws/court, /ws/terminal
   ========================================================================== */
(function (global) {
  "use strict";

  const state = {
    agents: null,
    findings: [],
    findingsMap: new Map(),
    seenFindingIds: new Set(),
    findingsInitialized: false,
    severityFilter: "ALL",
    activeModalFindingId: null,
    court: null,
    scope: {
      targets: [],
      active_target: "",
      excluded_domains: [],
      firewall_rules: [],
      locked: false,
    },
    scopeDirty: false,
    mcp: {
      configured: 0,
      connected: 0,
      failed: 0,
      disabled: 0,
      servers: [],
    },
    expandedMcpIds: new Set(),
    confirmCallback: null,
    sockets: {},
    wsConnected: {
      agents: false,
      findings: false,
      metrics: false,
      court: false,
      terminal: false,
    },
  };

  // ── Utilities ─────────────────────────────────────────────────────────────

  function escapeHtml(value) {
    const div = document.createElement("div");
    div.textContent = String(value ?? "");
    return div.innerHTML;
  }

  function formatTime(isoOrTs) {
    if (!isoOrTs) return "--:--:--";
    try {
      const d =
        typeof isoOrTs === "number"
          ? new Date(isoOrTs * 1000)
          : new Date(String(isoOrTs));
      if (Number.isNaN(d.getTime())) return String(isoOrTs);
      return d.toLocaleTimeString([], { hour12: false });
    } catch {
      return "--:--:--";
    }
  }

  async function apiJson(url, options) {
    const opts = Object.assign({ headers: {} }, options || {});
    if (opts.body && typeof opts.body !== "string") {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(opts.body);
    }
    const resp = await fetch(url, opts);
    let data = null;
    try {
      data = await resp.json();
    } catch {
      data = null;
    }
    if (!resp.ok) {
      const msg =
        (data && (data.detail || data.error || data.message)) ||
        `HTTP ${resp.status}`;
      const err = new Error(msg);
      err.status = resp.status;
      err.data = data;
      throw err;
    }
    return data;
  }

  // ── Toasts & Modals ───────────────────────────────────────────────────────

  function showToast(title, message, variant = "info", durationMs = 5000) {
    const container = document.getElementById("toast-container");
    if (!container) return;

    const toast = document.createElement("div");
    toast.className = `toast toast-${variant}`;
    toast.innerHTML = `
      <div>
        <div class="toast-title">${escapeHtml(title)}</div>
        <div class="toast-body">${escapeHtml(message)}</div>
      </div>
      <button type="button" class="toast-close" aria-label="Dismiss notification">✕</button>
    `;

    const closeBtn = toast.querySelector(".toast-close");
    if (closeBtn) {
      closeBtn.addEventListener("click", () => toast.remove());
    }

    container.prepend(toast);
    while (container.children.length > 6) {
      container.lastElementChild.remove();
    }

    if (durationMs > 0) {
      setTimeout(() => {
        if (toast.parentElement) toast.remove();
      }, durationMs);
    }
  }

  function openModal(id) {
    const el = document.getElementById(id);
    if (el) el.classList.remove("hidden");
  }

  function closeModal(id) {
    const el = document.getElementById(id);
    if (el) el.classList.add("hidden");
  }

  function openConfirm(title, message, onConfirm) {
    const titleEl = document.getElementById("confirm-modal-title");
    const msgEl = document.getElementById("confirm-modal-msg");
    if (titleEl) titleEl.textContent = title;
    if (msgEl) msgEl.textContent = message;
    state.confirmCallback = onConfirm;
    openModal("confirm-modal");
  }

  // ── Header WebSocket Indicator ────────────────────────────────────────────

  function updateWsHeaderIndicator() {
    const pill = document.getElementById("ws-status-pill");
    const txt = document.getElementById("ws-status-text");
    if (!pill || !txt) return;

    const total = Object.keys(state.wsConnected).length;
    const up = Object.values(state.wsConnected).filter(Boolean).length;

    pill.classList.remove("ws-live", "ws-degraded", "ws-offline");
    if (up === total) {
      pill.classList.add("ws-live");
      txt.textContent = `WS: LIVE (${up}/${total})`;
    } else if (up > 0) {
      pill.classList.add("ws-degraded");
      txt.textContent = `WS: PARTIAL (${up}/${total})`;
    } else {
      pill.classList.add("ws-offline");
      txt.textContent = "WS: REST POLLING";
    }

    if (global.HunterTerminal) {
      global.HunterTerminal.setSocketStatus(
        state.wsConnected.terminal ? "WS live" : "REST fallback"
      );
    }
  }

  // ── Panel 1: Active Agents ────────────────────────────────────────────────

  function renderAgents(payload) {
    if (!payload || !Array.isArray(payload.agents)) return;
    state.agents = payload;

    const grid = document.getElementById("agents-grid");
    const meta = document.getElementById("agents-summary-meta");
    const syncEl = document.getElementById("agents-last-sync");
    const emergencyBanner = document.getElementById("emergency-banner");

    if (emergencyBanner) {
      emergencyBanner.classList.toggle("hidden", !payload.emergency_stopped);
    }

    const summary = payload.summary || {};
    if (meta) {
      meta.textContent = `${summary.running ?? 0} Running • ${summary.idle ?? 0} Idle • ${
        summary.error ?? 0
      } Error • ${summary.stopped ?? 0} Stopped`;
    }
    if (syncEl) {
      syncEl.textContent = `Sync: ${formatTime(payload.timestamp || Date.now() / 1000)}`;
    }

    if (!grid) return;
    grid.innerHTML = payload.agents
      .map((agent) => {
        const status = String(agent.status || "idle").toLowerCase();
        const badge =
          agent.status_badge ||
          (status === "running"
            ? "🟢 Running"
            : status === "error"
            ? "🔴 Error"
            : status === "stopped"
            ? "⚫ Stopped"
            : "🟡 Idle");
        const cpu = Number(agent.cpu_percent || 0).toFixed(1);
        const mem = Number(agent.memory_mb || 0).toFixed(0);
        const lastAct = formatTime(agent.last_action_iso || agent.last_action_ts);
        const task = agent.error
          ? `${agent.current_task || "Error"} — ${agent.error}`
          : agent.current_task || "Standby";

        return `
          <div class="agent-card" data-agent-id="${escapeHtml(agent.id)}" data-status="${escapeHtml(status)}">
            <div class="agent-card-top">
              <div>
                <div class="agent-name">${escapeHtml(agent.name || agent.id)}</div>
                <div class="agent-role">${escapeHtml(agent.role || "Security Agent")}</div>
              </div>
              <span class="status-pill status-${escapeHtml(status)}">${escapeHtml(badge)}</span>
            </div>
            <div class="agent-task">${escapeHtml(task)}</div>
            <div class="agent-telemetry">
              <div class="telemetry-kv"><span class="telemetry-k">CPU</span><span class="telemetry-v">${cpu}%</span></div>
              <div class="telemetry-kv"><span class="telemetry-k">RAM</span><span class="telemetry-v">${mem} MB</span></div>
              <div class="telemetry-kv"><span class="telemetry-k">Last Act</span><span class="telemetry-v">${escapeHtml(lastAct)}</span></div>
            </div>
            <div class="agent-controls">
              <button type="button" class="btn btn-xs btn-emerald" data-agent-action="start" data-agent-id="${escapeHtml(agent.id)}">▶️ Start</button>
              <button type="button" class="btn btn-xs btn-amber" data-agent-action="pause" data-agent-id="${escapeHtml(agent.id)}">⏸️ Pause</button>
              <button type="button" class="btn btn-xs btn-danger-outline" data-agent-action="stop" data-agent-id="${escapeHtml(agent.id)}">⏹️ Stop</button>
              <button type="button" class="btn btn-xs btn-cyan" data-agent-action="restart" data-agent-id="${escapeHtml(agent.id)}">🔄 Restart</button>
            </div>
          </div>
        `;
      })
      .join("");
  }

  async function handleAgentAction(agentId, action) {
    try {
      const body =
        action === "start" && state.scope.active_target
          ? { target: state.scope.active_target }
          : undefined;
      const res = await apiJson(
        `/api/agents/${encodeURIComponent(agentId)}/${encodeURIComponent(action)}`,
        { method: "POST", body }
      );
      showToast(
        `Agent ${agentId}`,
        `Action '${action}' executed (${res.agent?.status_badge || "OK"})`,
        action === "stop" ? "warning" : "success",
        3200
      );
      await refreshAgents();
    } catch (err) {
      showToast(`Agent ${agentId} Error`, err.message, "error");
    }
  }

  // ── Panel 2: Live Findings Stream ─────────────────────────────────────────

  function verdictBadgeClass(verdict) {
    const v = String(verdict || "").toUpperCase();
    if (v === "CONFIRMED") return "badge-verdict-confirmed";
    if (v === "FALSE_POSITIVE" || v === "DISPROVED") return "badge-verdict-fp";
    return "badge-verdict-verifying";
  }

  function severityClass(sev) {
    const s = String(sev || "medium").toLowerCase();
    if (s === "critical") return "critical";
    if (s === "high") return "high";
    if (s === "low") return "low";
    if (s === "info" || s === "informational") return "info";
    return "medium";
  }

  function renderFindings(payload) {
    if (!payload || !Array.isArray(payload.findings)) return;

    const incoming = payload.findings;
    state.findings = incoming;
    state.findingsMap.clear();

    for (const f of incoming) {
      if (!f || !f.id) continue;
      state.findingsMap.set(f.id, f);
      if (state.findingsInitialized && !state.seenFindingIds.has(f.id)) {
        const sev = severityClass(f.severity);
        const variant = sev === "critical" || sev === "high" ? "critical" : "warning";
        showToast(
          `New ${f.severity || "Security"} Finding`,
          `${f.title || "Finding"} (${f.source_agent || "Agent"}) — ${f.endpoint || f.target || ""}`,
          variant,
          6500
        );
      }
      state.seenFindingIds.add(f.id);
    }
    state.findingsInitialized = true;

    const meta = document.getElementById("findings-total-meta");
    if (meta) {
      meta.textContent = `${payload.total ?? incoming.length} Findings`;
    }

    const listEl = document.getElementById("findings-list");
    if (!listEl) return;

    const filtered =
      state.severityFilter === "ALL"
        ? incoming
        : incoming.filter(
            (f) => String(f.severity || "").toUpperCase() === state.severityFilter
          );

    if (filtered.length === 0) {
      listEl.innerHTML =
        '<div class="empty-state">No findings match the current filter.</div>';
      return;
    }

    listEl.innerHTML = filtered
      .map((f) => {
        const sev = severityClass(f.severity);
        const fp = Boolean(f.false_positive || f.verdict === "FALSE_POSITIVE");
        const exported = Boolean(f.exported_to_burp);
        return `
          <div class="finding-item sev-${sev} ${fp ? "is-fp" : ""}" data-finding-id="${escapeHtml(f.id)}">
            <div class="finding-top">
              <div class="finding-badges">
                <span class="badge badge-${sev}">${escapeHtml(f.severity || "Medium")}</span>
                <span class="badge badge-source">${escapeHtml(f.source_agent || "Brain")}</span>
                <span class="badge ${verdictBadgeClass(f.verdict)}">${escapeHtml(f.verdict || "UNVERIFIED")}</span>
                ${exported ? '<span class="badge badge-verdict-confirmed">Burp Exported</span>' : ""}
              </div>
              <span class="finding-time">${escapeHtml(formatTime(f.timestamp_iso || f.timestamp))}</span>
            </div>
            <div class="finding-title">${escapeHtml(f.title || "Security Finding")}</div>
            <div class="finding-endpoint">${escapeHtml(f.endpoint || f.target || "N/A")}</div>
            <div class="finding-footer">
              <span class="finding-time">ID: ${escapeHtml(f.id)}</span>
              <div class="finding-actions">
                <button type="button" class="btn btn-xs" data-finding-action="details" data-finding-id="${escapeHtml(f.id)}">View Details</button>
                <button type="button" class="btn btn-xs btn-cyan" data-finding-action="export-burp" data-finding-id="${escapeHtml(f.id)}" ${exported ? "disabled" : ""}>${exported ? "Exported" : "Export to Burp"}</button>
                <button type="button" class="btn btn-xs btn-danger-outline" data-finding-action="false-positive" data-finding-id="${escapeHtml(f.id)}" ${fp ? "disabled" : ""}>${fp ? "Marked FP" : "Mark False Positive"}</button>
              </div>
            </div>
          </div>
        `;
      })
      .join("");
  }

  async function openFindingDetails(findingId) {
    state.activeModalFindingId = findingId;
    const titleEl = document.getElementById("finding-modal-title");
    const bodyEl = document.getElementById("finding-modal-body");
    const exportBtn = document.getElementById("modal-finding-export-burp");
    const fpBtn = document.getElementById("modal-finding-false-positive");

    if (bodyEl) bodyEl.innerHTML = '<div class="empty-state">Loading finding details...</div>';
    openModal("finding-modal");

    let detail = state.findingsMap.get(findingId) || null;
    try {
      detail = await apiJson(`/api/findings/${encodeURIComponent(findingId)}`);
    } catch {
      // Fall back to cached finding if REST lookup fails
    }

    if (!detail) {
      if (bodyEl) bodyEl.innerHTML = '<div class="empty-state">Finding details unavailable.</div>';
      return;
    }

    if (titleEl) {
      titleEl.textContent = `[${detail.severity || "Medium"}] ${detail.title || detail.id}`;
    }
    if (exportBtn) exportBtn.disabled = Boolean(detail.exported_to_burp);
    if (fpBtn) fpBtn.disabled = Boolean(detail.false_positive || detail.verdict === "FALSE_POSITIVE");

    const extraBlocks = [];
    if (detail.payload_used) {
      extraBlocks.push(
        `<div><div class="field-label">Payload Used</div><pre class="modal-pre">${escapeHtml(detail.payload_used)}</pre></div>`
      );
    }
    if (detail.raw_request) {
      extraBlocks.push(
        `<div><div class="field-label">Raw Request</div><pre class="modal-pre">${escapeHtml(detail.raw_request)}</pre></div>`
      );
    }
    if (detail.raw_response) {
      extraBlocks.push(
        `<div><div class="field-label">Raw Response</div><pre class="modal-pre">${escapeHtml(detail.raw_response)}</pre></div>`
      );
    }
    if (detail.remediation) {
      extraBlocks.push(
        `<div><div class="field-label">Remediation</div><pre class="modal-pre">${escapeHtml(detail.remediation)}</pre></div>`
      );
    }

    if (bodyEl) {
      bodyEl.innerHTML = `
        <div class="finding-badges">
          <span class="badge badge-${severityClass(detail.severity)}">${escapeHtml(detail.severity || "Medium")}</span>
          <span class="badge badge-source">${escapeHtml(detail.source_agent || "Brain")}</span>
          <span class="badge ${verdictBadgeClass(detail.verdict)}">${escapeHtml(detail.verdict || "UNVERIFIED")}</span>
          ${detail.cwe ? `<span class="badge badge-info">${escapeHtml(detail.cwe)}</span>` : ""}
        </div>
        <div>
          <div class="field-label">Target / Endpoint</div>
          <pre class="modal-pre">${escapeHtml(detail.endpoint || detail.target || "N/A")}</pre>
        </div>
        <div>
          <div class="field-label">Evidence</div>
          <pre class="modal-pre">${escapeHtml(detail.evidence || "No evidence recorded.")}</pre>
        </div>
        ${extraBlocks.join("")}
      `;
    }
  }

  async function exportFindingToBurp(findingId) {
    try {
      await apiJson(`/api/findings/${encodeURIComponent(findingId)}/export-burp`, {
        method: "POST",
      });
      showToast("Burp Exported", `Finding ${findingId} exported to Burp Suite.`, "success", 3800);
      await refreshFindings();
      if (state.activeModalFindingId === findingId) {
        const exportBtn = document.getElementById("modal-finding-export-burp");
        if (exportBtn) exportBtn.disabled = true;
      }
    } catch (err) {
      showToast("Burp Export Failed", err.message, "error");
    }
  }

  async function markFindingFalsePositive(findingId) {
    try {
      await apiJson(`/api/findings/${encodeURIComponent(findingId)}/false-positive`, {
        method: "POST",
        body: { reason: "Marked by operator via Control Center" },
      });
      showToast("False Positive Marked", `Finding ${findingId} rejected by operator.`, "warning", 3500);
      await Promise.all([refreshFindings(), refreshCourt()]);
      if (state.activeModalFindingId === findingId) {
        const fpBtn = document.getElementById("modal-finding-false-positive");
        if (fpBtn) fpBtn.disabled = true;
      }
    } catch (err) {
      showToast("Update Failed", err.message, "error");
    }
  }

  // ── Panel 3: Evidence Court Visualizer ────────────────────────────────────

  function renderCourt(payload) {
    if (!payload || typeof payload !== "object") return;
    state.court = payload;

    const setVal = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = String(val ?? 0);
    };

    setVal("court-pending", payload.pending_claims ?? 0);
    setVal("court-verifying", payload.under_verification ?? 0);
    setVal("court-confirmed", payload.confirmed_last_hour ?? 0);
    setVal("court-rejected", payload.false_positives_rejected ?? 0);

    const feedEl = document.getElementById("court-feed");
    if (!feedEl) return;

    const feed = Array.isArray(payload.feed) ? payload.feed : [];
    if (feed.length === 0) {
      feedEl.innerHTML =
        '<div class="empty-state">Waiting for Evidence Court adjudication events...</div>';
      return;
    }

    const nearBottom =
      feedEl.scrollHeight - feedEl.scrollTop - feedEl.clientHeight < 40;

    feedEl.innerHTML = feed
      .map((ev) => {
        const verdict = String(ev.verdict || "VERIFYING").toUpperCase();
        const line = `[${ev.time || "--:--:--"}] Claim #${ev.id || "?"}: ${ev.summary || ""} -> ${verdict}`;
        return `<div class="court-feed-line verdict-${escapeHtml(verdict)}">${escapeHtml(line)}</div>`;
      })
      .join("");

    if (nearBottom) {
      feedEl.scrollTop = feedEl.scrollHeight;
    }
  }

  // ── Panel 4: Scope & Target Management ────────────────────────────────────

  function renderScope(payload, forceOverwrite = false) {
    if (!payload || typeof payload !== "object") return;
    state.scope = {
      targets: Array.isArray(payload.targets) ? payload.targets : [],
      active_target: payload.active_target || "",
      excluded_domains: Array.isArray(payload.excluded_domains)
        ? payload.excluded_domains
        : [],
      firewall_rules: Array.isArray(payload.firewall_rules)
        ? payload.firewall_rules
        : [],
      locked: Boolean(payload.locked),
    };

    const locked = state.scope.locked;
    const activeDisplay = state.scope.active_target || "No Active Target";

    const hdrTarget = document.getElementById("header-active-target");
    if (hdrTarget) hdrTarget.textContent = activeDisplay;

    const panelInd = document.getElementById("scope-active-indicator");
    if (panelInd) panelInd.textContent = `Active: ${activeDisplay}`;

    const hdrLock = document.getElementById("header-scope-lock");
    if (hdrLock) {
      hdrLock.classList.remove("scope-locked", "scope-unlocked");
      hdrLock.classList.add(locked ? "scope-locked" : "scope-unlocked");
      hdrLock.innerHTML = `<span>${locked ? "🔒 SCOPE LOCKED" : "🔓 SCOPE UNLOCKED"}</span>`;
    }

    const lockBtn = document.getElementById("btn-scope-lock");
    if (lockBtn) {
      lockBtn.textContent = locked ? "🔓 Unlock Scope" : "🔒 Lock Scope";
      lockBtn.classList.toggle("btn-amber", locked);
      lockBtn.classList.toggle("btn-emerald", !locked);
    }

    const saveBtn = document.getElementById("btn-scope-save");
    if (saveBtn) saveBtn.disabled = locked;

    const activeInput = document.getElementById("scope-active-input");
    const targetsEl = document.getElementById("scope-targets-textarea");
    const excludedEl = document.getElementById("scope-excluded-textarea");

    if (activeInput) activeInput.disabled = locked;
    if (targetsEl) targetsEl.disabled = locked;
    if (excludedEl) excludedEl.disabled = locked;

    const activeDom = document.activeElement;
    const editingScope =
      activeDom === activeInput || activeDom === targetsEl || activeDom === excludedEl;

    if (forceOverwrite || (!state.scopeDirty && !editingScope)) {
      if (activeInput) activeInput.value = state.scope.active_target;
      if (targetsEl) targetsEl.value = state.scope.targets.join("\n");
      if (excludedEl) excludedEl.value = state.scope.excluded_domains.join("\n");
      state.scopeDirty = false;
    }

    const targetsCount = document.getElementById("scope-targets-count");
    if (targetsCount) targetsCount.textContent = String(state.scope.targets.length);

    const exclCount = document.getElementById("scope-excluded-count");
    if (exclCount) exclCount.textContent = String(state.scope.excluded_domains.length);

    const rulesCount = document.getElementById("scope-rules-count");
    if (rulesCount) rulesCount.textContent = `${state.scope.firewall_rules.length} rules`;

    const rulesBox = document.getElementById("scope-firewall-rules");
    if (rulesBox) {
      rulesBox.innerHTML =
        state.scope.firewall_rules.length > 0
          ? state.scope.firewall_rules
              .map((r) => `<div class="scope-rule-item">${escapeHtml(r)}</div>`)
              .join("")
          : '<div class="scope-rule-item">No custom firewall rules configured.</div>';
    }
  }

  async function saveScope() {
    if (state.scope.locked) {
      showToast("Scope Locked", "Unlock scope before saving changes.", "warning");
      return;
    }
    const activeInput = document.getElementById("scope-active-input");
    const targetsEl = document.getElementById("scope-targets-textarea");
    const excludedEl = document.getElementById("scope-excluded-textarea");

    const splitLines = (txt) =>
      String(txt || "")
        .split(/[\r\n,]+/)
        .map((s) => s.trim())
        .filter(Boolean);

    try {
      const res = await apiJson("/api/scope", {
        method: "POST",
        body: {
          active_target: activeInput ? activeInput.value.trim() : "",
          targets: targetsEl ? splitLines(targetsEl.value) : [],
          excluded_domains: excludedEl ? splitLines(excludedEl.value) : [],
        },
      });
      state.scopeDirty = false;
      renderScope(res, true);
      showToast("Scope Saved", "Target scope & exclusions updated.", "success", 3200);
    } catch (err) {
      showToast(
        err.status === 423 ? "Scope Locked (HTTP 423)" : "Scope Update Failed",
        err.message,
        err.status === 423 ? "warning" : "error"
      );
      await refreshScope();
    }
  }

  async function toggleScopeLock() {
    try {
      const nextLocked = !state.scope.locked;
      const res = await apiJson("/api/scope/lock", {
        method: "POST",
        body: { locked: nextLocked },
      });
      renderScope(res, false);
      showToast(
        res.locked ? "Scope Locked" : "Scope Unlocked",
        res.locked
          ? "Scope mutations are now blocked (HTTP 423)."
          : "Scope mutations are now enabled.",
        res.locked ? "warning" : "success",
        3000
      );
    } catch (err) {
      showToast("Scope Lock Error", err.message, "error");
    }
  }

  async function checkScopeUrl() {
    const input = document.getElementById("scope-check-input");
    const out = document.getElementById("scope-check-result");
    if (!input || !out) return;
    const target = input.value.trim();
    if (!target) {
      out.textContent = "Enter a URL or domain to test.";
      out.style.color = "#fde68a";
      return;
    }
    try {
      const res = await apiJson("/api/scope/check", {
        method: "POST",
        body: { target },
      });
      out.textContent = `${res.allowed ? "✅ IN SCOPE" : "⛔ BLOCKED"}: ${res.reason || ""}`;
      out.style.color = res.allowed ? "#6ee7b7" : "#fca5a5";
    } catch (err) {
      out.textContent = `Check failed: ${err.message}`;
      out.style.color = "#fca5a5";
    }
  }

  // ── Panel 5: MCP Server Monitor ───────────────────────────────────────────

  function mcpStatusPill(status) {
    const st = String(status || "disabled").toLowerCase();
    if (st === "connected") return '<span class="status-pill status-running">🟢 Connected</span>';
    if (st === "failed") return '<span class="status-pill status-error">🔴 Failed</span>';
    return '<span class="status-pill status-stopped">⚫ Disabled</span>';
  }

  function renderMcp(payload) {
    if (!payload || typeof payload !== "object") return;
    state.mcp = payload;

    const setNum = (id, v) => {
      const el = document.getElementById(id);
      if (el) el.textContent = String(v ?? 0);
    };
    setNum("mcp-configured", payload.configured ?? 0);
    setNum("mcp-connected", payload.connected ?? 0);
    setNum("mcp-failed", payload.failed ?? 0);
    setNum("mcp-disabled", payload.disabled ?? 0);

    const listEl = document.getElementById("mcp-servers-list");
    if (!listEl) return;

    const servers = Array.isArray(payload.servers) ? payload.servers : [];
    if (servers.length === 0) {
      listEl.innerHTML = '<div class="empty-state">No MCP servers configured in opencode.json.</div>';
      return;
    }

    listEl.innerHTML = servers
      .map((srv) => {
        const sid = srv.id || srv.name;
        const expanded = state.expandedMcpIds.has(sid);
        const lastChecked = formatTime(srv.last_checked_iso || srv.last_checked);
        return `
          <div class="mcp-row ${expanded ? "expanded" : ""}" data-mcp-id="${escapeHtml(sid)}">
            <div class="mcp-row-head" data-mcp-toggle="${escapeHtml(sid)}">
              <div class="mcp-row-left">
                <span class="mcp-name">${escapeHtml(srv.name || sid)}</span>
                <span class="mcp-type">${escapeHtml(srv.type || "local")}</span>
              </div>
              <div class="mcp-row-right">
                ${mcpStatusPill(srv.status)}
                <button type="button" class="btn btn-xs" data-mcp-edit="${escapeHtml(sid)}" title="Configure ${escapeHtml(sid)}">⚙️</button>
              </div>
            </div>
            <div class="mcp-details">
              <div><strong>Target:</strong> ${escapeHtml(srv.command_or_url || "N/A")}</div>
              <div><strong>Timeout:</strong> ${escapeHtml(srv.timeout ?? "default")} ms &bull; <strong>Last Checked:</strong> ${escapeHtml(lastChecked)}</div>
              ${
                srv.error
                  ? `<div class="mcp-error-box"><strong>Failure Error:</strong> ${escapeHtml(srv.error)}</div>`
                  : `<div style="margin-top:4px;color:#6ee7b7;">Status healthy — click header to collapse.</div>`
              }
            </div>
          </div>
        `;
      })
      .join("");
  }

  function openMcpConfigModal(preselectId) {
    const select = document.getElementById("mcp-cfg-server");
    const servers = Array.isArray(state.mcp.servers) ? state.mcp.servers : [];
    if (!select) return;

    select.innerHTML = servers
      .map(
        (s) =>
          `<option value="${escapeHtml(s.id)}">${escapeHtml(s.name || s.id)} (${escapeHtml(s.status)})</option>`
      )
      .join("");

    if (preselectId && servers.some((s) => s.id === preselectId)) {
      select.value = preselectId;
    }

    populateMcpModalFields();
    openModal("mcp-modal");
  }

  function populateMcpModalFields() {
    const select = document.getElementById("mcp-cfg-server");
    const enabledEl = document.getElementById("mcp-cfg-enabled");
    const timeoutEl = document.getElementById("mcp-cfg-timeout");
    const cmdEl = document.getElementById("mcp-cfg-cmd");
    if (!select) return;

    const srv = (state.mcp.servers || []).find((s) => s.id === select.value);
    if (!srv) return;
    if (enabledEl) enabledEl.checked = Boolean(srv.enabled);
    if (timeoutEl) timeoutEl.value = srv.timeout || 60000;
    if (cmdEl) cmdEl.value = srv.command_or_url || "";
  }

  async function saveMcpConfig() {
    const select = document.getElementById("mcp-cfg-server");
    const enabledEl = document.getElementById("mcp-cfg-enabled");
    const timeoutEl = document.getElementById("mcp-cfg-timeout");
    const cmdEl = document.getElementById("mcp-cfg-cmd");
    if (!select || !select.value) return;

    const timeoutVal = parseInt(timeoutEl ? timeoutEl.value : "60000", 10);
    try {
      const res = await apiJson("/api/mcp/configure", {
        method: "POST",
        body: {
          server_id: select.value,
          enabled: enabledEl ? enabledEl.checked : true,
          timeout: Number.isFinite(timeoutVal) ? timeoutVal : 60000,
          command_or_url: cmdEl ? cmdEl.value.trim() : "",
        },
      });
      renderMcp(res);
      closeModal("mcp-modal");
      showToast("MCP Updated", `Server '${select.value}' configuration saved.`, "success", 3200);
    } catch (err) {
      showToast("MCP Config Error", err.message, "error");
    }
  }

  async function retryFailedMcp() {
    try {
      const res = await apiJson("/api/mcp/retry", { method: "POST", body: {} });
      renderMcp(res);
      const count = Array.isArray(res.retried) ? res.retried.length : 0;
      showToast(
        "MCP Retry Complete",
        `Retried ${count} failed server(s). Connected: ${res.connected ?? 0}, Failed: ${res.failed ?? 0}.`,
        (res.failed ?? 0) > 0 ? "warning" : "success",
        4000
      );
    } catch (err) {
      showToast("MCP Retry Error", err.message, "error");
    }
  }

  // ── Header Emergency Actions ──────────────────────────────────────────────

  async function emergencyStopAll() {
    try {
      await apiJson("/api/emergency/stop-all", { method: "POST" });
      showToast(
        "🛑 EMERGENCY STOP ALL",
        "All agents halted immediately.",
        "critical",
        6000
      );
      await Promise.all([refreshAgents(), refreshTerminal()]);
    } catch (err) {
      showToast("Emergency Stop Error", err.message, "error");
    }
  }

  async function pauseAllScans() {
    try {
      await apiJson("/api/emergency/pause-all", { method: "POST" });
      showToast("Scans Paused", "All active agents transitioned to Idle.", "warning", 3500);
      await Promise.all([refreshAgents(), refreshTerminal()]);
    } catch (err) {
      showToast("Pause All Error", err.message, "error");
    }
  }

  function clearAllData() {
    openConfirm(
      "🧹 Clear All Session Data",
      "Clear all live findings, Evidence Court history, metrics samples, and console logs?",
      async () => {
        try {
          await apiJson("/api/emergency/clear-data", { method: "POST" });
          state.seenFindingIds.clear();
          state.findings = [];
          state.findingsMap.clear();
          renderFindings({ findings: [], total: 0, alerts: [] });
          renderCourt({
            pending_claims: 0,
            under_verification: 0,
            confirmed_last_hour: 0,
            false_positives_rejected: 0,
            feed: [],
          });
          if (global.HunterCharts) global.HunterCharts.reset();
          if (global.HunterTerminal) {
            global.HunterTerminal.handlePayload({ cleared: true });
            global.HunterTerminal.appendLine(
              "[System] All session telemetry cleared by operator.",
              "term-warn"
            );
          }
          showToast("Data Cleared", "Findings, court feed, and metrics reset.", "success", 3500);
        } catch (err) {
          showToast("Clear Data Failed", err.message, "error");
        }
      }
    );
  }

  async function exportAllEvidence() {
    try {
      const res = await apiJson("/api/emergency/export-evidence", { method: "GET" });
      const payload = res.bundle || res;
      const blob = new Blob([JSON.stringify(payload, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = res.filename || `hunterai-evidence-${Date.now()}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);

      showToast(
        "Evidence Exported",
        `Exported ${res.findings_count ?? 0} finding(s)${
          res.export_path ? ` -> ${res.export_path}` : ""
        }.`,
        "success",
        4500
      );
    } catch (err) {
      showToast("Export Failed", err.message, "error");
    }
  }

  // ── REST Fetch Helpers ────────────────────────────────────────────────────

  async function refreshAgents() {
    try {
      renderAgents(await apiJson("/api/agents"));
    } catch {
      // Ignore transient poll errors
    }
  }

  async function refreshFindings() {
    try {
      renderFindings(await apiJson("/api/findings"));
    } catch {
      // Ignore transient poll errors
    }
  }

  async function refreshCourt() {
    try {
      renderCourt(await apiJson("/api/court/status"));
    } catch {
      // Ignore transient poll errors
    }
  }

  async function refreshMetrics() {
    try {
      const data = await apiJson("/api/metrics/system");
      if (global.HunterCharts) global.HunterCharts.update(data);
    } catch {
      // Ignore transient poll errors
    }
  }

  async function refreshScope() {
    try {
      renderScope(await apiJson("/api/scope"), false);
    } catch {
      // Ignore transient poll errors
    }
  }

  async function refreshMcp() {
    try {
      renderMcp(await apiJson("/api/mcp/status"));
    } catch {
      // Ignore transient poll errors
    }
  }

  async function refreshTerminal() {
    try {
      const data = await apiJson("/api/terminal/state");
      if (global.HunterTerminal) global.HunterTerminal.handlePayload({ type: "state", ...data });
    } catch {
      // Ignore transient poll errors
    }
  }

  // ── WebSocket Connections with Exponential Backoff ────────────────────────

  function buildWsUrl(path) {
    const proto = global.location.protocol === "https:" ? "wss:" : "ws:";
    return `${proto}//${global.location.host}${path}`;
  }

  function connectChannel(name, path, onMessage) {
    let delayMs = 1000;
    const maxDelayMs = 15000;

    function connect() {
      let ws;
      try {
        ws = new WebSocket(buildWsUrl(path));
      } catch {
        scheduleReconnect();
        return;
      }

      state.sockets[name] = ws;
      if (name === "terminal" && global.HunterTerminal) {
        global.HunterTerminal.setSocket(ws);
      }

      ws.onopen = () => {
        delayMs = 1000;
        state.wsConnected[name] = true;
        updateWsHeaderIndicator();
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          onMessage(data);
        } catch {
          // Ignore malformed frame
        }
      };

      ws.onerror = () => {
        // Closed handler triggers reconnect
      };

      ws.onclose = () => {
        state.wsConnected[name] = false;
        if (name === "terminal" && global.HunterTerminal) {
          global.HunterTerminal.setSocket(null);
        }
        updateWsHeaderIndicator();
        scheduleReconnect();
      };
    }

    function scheduleReconnect() {
      const wait = delayMs;
      delayMs = Math.min(maxDelayMs, Math.round(delayMs * 1.7));
      setTimeout(connect, wait);
    }

    connect();
  }

  function startWebSocketsAndPolling() {
    connectChannel("agents", "/ws/agents", renderAgents);
    connectChannel("findings", "/ws/findings", renderFindings);
    connectChannel("metrics", "/ws/metrics", (data) => {
      if (global.HunterCharts) global.HunterCharts.update(data);
    });
    connectChannel("court", "/ws/court", renderCourt);
    connectChannel("terminal", "/ws/terminal", (data) => {
      if (global.HunterTerminal) global.HunterTerminal.handlePayload(data);
    });

    // REST fallback polling for disconnected WS channels (every 3s)
    setInterval(() => {
      if (!state.wsConnected.agents) refreshAgents();
      if (!state.wsConnected.findings) refreshFindings();
      if (!state.wsConnected.metrics) refreshMetrics();
      if (!state.wsConnected.court) refreshCourt();
    }, 3000);

    // Periodic refresh for Scope & MCP status (every 5s)
    setInterval(() => {
      refreshScope();
      refreshMcp();
    }, 5000);
  }

  // ── Bootstrap & Event Wiring ──────────────────────────────────────────────

  function hydrateInitialState() {
    const el = document.getElementById("initial-state");
    if (!el) return;
    try {
      const raw = (el.textContent || "").trim();
      if (!raw || raw.startsWith("{{")) return;
      const init = JSON.parse(raw);
      if (init.agents && Array.isArray(init.agents.agents)) renderAgents(init.agents);
      if (init.findings && Array.isArray(init.findings.findings)) renderFindings(init.findings);
      if (init.scope && typeof init.scope === "object") renderScope(init.scope, true);
      if (init.mcp && Array.isArray(init.mcp.servers)) renderMcp(init.mcp);
      if (init.metrics && typeof init.metrics === "object" && global.HunterCharts) {
        global.HunterCharts.update(init.metrics);
      }
      if (init.court && typeof init.court === "object") renderCourt(init.court);
      if (init.terminal && typeof init.terminal === "object" && global.HunterTerminal) {
        global.HunterTerminal.handlePayload({ type: "state", ...init.terminal });
      }
    } catch {
      // Static HTML or empty context falls back to REST bootstrap
    }
  }

  function wireDomHandlers() {
    // Emergency & Header controls
    const bindClick = (id, fn) => {
      const el = document.getElementById(id);
      if (el) el.addEventListener("click", fn);
    };

    bindClick("btn-emergency-stop", emergencyStopAll);
    bindClick("btn-pause-all", pauseAllScans);
    bindClick("btn-clear-data", clearAllData);
    bindClick("btn-export-evidence", exportAllEvidence);

    // Panel 1: Agents delegation
    const agentsGrid = document.getElementById("agents-grid");
    if (agentsGrid) {
      agentsGrid.addEventListener("click", (ev) => {
        const btn = ev.target.closest("[data-agent-action][data-agent-id]");
        if (!btn) return;
        handleAgentAction(btn.dataset.agentId, btn.dataset.agentAction);
      });
    }

    // Panel 2: Severity filter chips + finding buttons
    const sevFilters = document.getElementById("findings-severity-filters");
    if (sevFilters) {
      sevFilters.addEventListener("click", (ev) => {
        const chip = ev.target.closest("[data-sev-filter]");
        if (!chip) return;
        state.severityFilter = chip.dataset.sevFilter;
        sevFilters.querySelectorAll(".filter-chip").forEach((c) => {
          c.classList.toggle("active", c === chip);
        });
        renderFindings({ findings: state.findings, total: state.findings.length });
      });
    }

    const findingsList = document.getElementById("findings-list");
    if (findingsList) {
      findingsList.addEventListener("click", (ev) => {
        const btn = ev.target.closest("[data-finding-action][data-finding-id]");
        if (!btn) return;
        const fid = btn.dataset.findingId;
        const action = btn.dataset.findingAction;
        if (action === "details") openFindingDetails(fid);
        else if (action === "export-burp") exportFindingToBurp(fid);
        else if (action === "false-positive") markFindingFalsePositive(fid);
      });
    }

    bindClick("modal-finding-export-burp", () => {
      if (state.activeModalFindingId) exportFindingToBurp(state.activeModalFindingId);
    });
    bindClick("modal-finding-false-positive", () => {
      if (state.activeModalFindingId) markFindingFalsePositive(state.activeModalFindingId);
    });

    // Panel 4: Scope
    bindClick("btn-scope-lock", toggleScopeLock);
    bindClick("btn-scope-save", saveScope);
    bindClick("btn-scope-check", checkScopeUrl);

    ["scope-active-input", "scope-targets-textarea", "scope-excluded-textarea"].forEach((id) => {
      const el = document.getElementById(id);
      if (el) {
        el.addEventListener("input", () => {
          state.scopeDirty = true;
        });
      }
    });

    const scopeCheckInput = document.getElementById("scope-check-input");
    if (scopeCheckInput) {
      scopeCheckInput.addEventListener("keydown", (ev) => {
        if (ev.key === "Enter") {
          ev.preventDefault();
          checkScopeUrl();
        }
      });
    }

    // Panel 5: MCP Monitor
    bindClick("btn-mcp-retry", retryFailedMcp);
    bindClick("btn-mcp-configure", () => openMcpConfigModal(null));
    bindClick("btn-mcp-cfg-save", saveMcpConfig);

    const mcpSelect = document.getElementById("mcp-cfg-server");
    if (mcpSelect) mcpSelect.addEventListener("change", populateMcpModalFields);

    const mcpList = document.getElementById("mcp-servers-list");
    if (mcpList) {
      mcpList.addEventListener("click", (ev) => {
        const editBtn = ev.target.closest("[data-mcp-edit]");
        if (editBtn) {
          ev.stopPropagation();
          openMcpConfigModal(editBtn.dataset.mcpEdit);
          return;
        }
        const rowHead = ev.target.closest("[data-mcp-toggle]");
        if (!rowHead) return;
        const sid = rowHead.dataset.mcpToggle;
        if (state.expandedMcpIds.has(sid)) state.expandedMcpIds.delete(sid);
        else state.expandedMcpIds.add(sid);
        const row = rowHead.closest(".mcp-row");
        if (row) row.classList.toggle("expanded", state.expandedMcpIds.has(sid));
      });
    }

    // Modals close & confirm
    document.querySelectorAll("[data-close-modal]").forEach((btn) => {
      btn.addEventListener("click", () => closeModal(btn.dataset.closeModal));
    });
    document.querySelectorAll(".modal-backdrop").forEach((backdrop) => {
      backdrop.addEventListener("click", (ev) => {
        if (ev.target === backdrop) backdrop.classList.add("hidden");
      });
    });
    document.addEventListener("keydown", (ev) => {
      if (ev.key === "Escape") {
        document.querySelectorAll(".modal-backdrop").forEach((m) => m.classList.add("hidden"));
      }
    });

    bindClick("btn-confirm-proceed", () => {
      const cb = state.confirmCallback;
      state.confirmCallback = null;
      closeModal("confirm-modal");
      if (typeof cb === "function") cb();
    });
  }

  function bootstrap() {
    if (global.HunterCharts) global.HunterCharts.init();
    if (global.HunterTerminal) {
      global.HunterTerminal.init();
      global.HunterTerminal.setOnCommandResult((res) => {
        const cmd = String(res.command || "").toLowerCase();
        if (cmd.startsWith("agent") || cmd.startsWith("scan") || cmd.startsWith("emergency")) {
          refreshAgents();
        }
        if (cmd.startsWith("scope") || cmd.startsWith("scan")) {
          refreshScope();
        }
        if (cmd.startsWith("mcp")) {
          refreshMcp();
        }
        if (cmd.startsWith("court")) {
          refreshCourt();
        }
      });
    }

    wireDomHandlers();
    hydrateInitialState();

    // Always perform an immediate REST sync for static mirror & freshness
    Promise.all([
      refreshAgents(),
      refreshFindings(),
      refreshScope(),
      refreshMcp(),
      refreshMetrics(),
      refreshCourt(),
    ]);

    startWebSocketsAndPolling();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bootstrap);
  } else {
    bootstrap();
  }

  global.HunterControlCenter = {
    refreshAgents,
    refreshFindings,
    refreshScope,
    refreshMcp,
    refreshMetrics,
    refreshCourt,
    showToast,
  };
})(window);
