/* HunterAI Security Co-Pilot — clean streaming WebSocket client.
   Talks to the existing /ws/chat WebSocket and /api/models/catalog.
*/

(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);

  const STORE_KEY = "pentestai.chats.v1";

  let state = load();
  let ws = null;
  let retryDelay = 1000;
  let sending = false;
  let pendingNode = null;
  let pendingText = "";
  let pendingTraces = [];
  let catalog = null;

  function esc(s) {
    if (window.HunterCore && typeof window.HunterCore.escapeHtml === "function") {
      return window.HunterCore.escapeHtml(s);
    }
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function sanitizeHtml(html) {
    if (window.HunterCore && typeof window.HunterCore.sanitizeHtml === "function") {
      return window.HunterCore.sanitizeHtml(html);
    }
    if (window.DOMPurify && typeof window.DOMPurify.sanitize === "function") {
      return window.DOMPurify.sanitize(String(html || ""));
    }
    return esc(String(html || ""));
  }

  function inline(t) {
    let out = esc(t);
    out = out.replace(/`([^`\n]+)`/g, (_, c) => `<code class="ltr-isolate">${c}</code>`);
    out = out.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    out = out.replace(/(^|[^\*])\*([^*\n]+)\*/g, "$1<em>$2</em>");
    return out;
  }

  function md(src) {
    if (!src) return "";
    const parts = String(src).split(/```/);
    const html = [];
    for (let i = 0; i < parts.length; i++) {
      if (i % 2 === 1) {
        const block = parts[i].replace(/^[a-zA-Z0-9_-]*\n/, "");
        html.push(`<pre class="ltr-isolate" dir="ltr"><code>${esc(block)}</code></pre>`);
      } else {
        const seg = parts[i].trim();
        if (!seg) continue;
        const paras = seg.split(/\n{2,}/);
        for (const p of paras) {
          const lines = p.split("\n");
          if (lines.every((l) => /^\s*[-*]\s+/.test(l))) {
            html.push("<ul>" + lines.map((l) => `<li>${inline(l.replace(/^\s*[-*]\s+/, ""))}</li>`).join("") + "</ul>");
          } else if (lines.length === 1 && /^#{1,3}\s+/.test(lines[0])) {
            const m = lines[0].match(/^(#{1,3})\s+(.*)$/);
            const tag = m[1].length === 1 ? "h3" : "h4";
            html.push(`<${tag}>${inline(m[2])}</${tag}>`);
          } else {
            html.push(`<p>${lines.map(inline).join("<br>")}</p>`);
          }
        }
      }
    }
    return sanitizeHtml(html.join(""));
  }

  function decorateRenderedMarkdown(node) {
    if (!node) return;
    node.querySelectorAll("pre, code").forEach((el) => {
      el.classList.add("ltr-isolate");
      el.setAttribute("dir", "ltr");
    });
  }

  function load() {
    try {
      const raw = localStorage.getItem(STORE_KEY);
      if (raw) {
        const parsed = JSON.parse(raw);
        if (parsed && Array.isArray(parsed.convs)) return parsed;
      }
    } catch (_) {}
    return { activeId: null, convs: [] };
  }

  function save() {
    try { localStorage.setItem(STORE_KEY, JSON.stringify(state)); } catch (_) {}
  }

  function find(id) { return state.convs.find((c) => c.id === id) || null; }
  function activeConv() { return find(state.activeId); }

  function newConversation() {
    const id = "c_" + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
    const c = { id, serverConversationId: null, title: "New chat", model: $("modelSelect").value || "auto", messages: [] };
    state.convs.unshift(c);
    state.activeId = id;
    save();
    return c;
  }

  function ensureConversation() {
    let c = activeConv();
    if (!c) c = state.convs[0] || newConversation();
    state.activeId = c.id;
    return c;
  }

  function renderConvs() {
    const box = $("convs");
    box.textContent = "";
    for (const c of state.convs) {
      const item = document.createElement("div");
      item.className = "conv" + (c.id === state.activeId ? " active" : "");
      item.setAttribute("role", "button");
      item.setAttribute("tabindex", "0");

      const titleSpan = document.createElement("span");
      titleSpan.className = "t";
      titleSpan.textContent = c.title || "New chat";

      const delBtn = document.createElement("button");
      delBtn.type = "button";
      delBtn.className = "x";
      delBtn.title = "Delete";
      delBtn.setAttribute("aria-label", "Delete conversation");
      delBtn.textContent = "✕";
      delBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        state.convs = state.convs.filter((x) => x.id !== c.id);
        if (state.activeId === c.id) state.activeId = state.convs[0]?.id || null;
        save();
        renderConvs();
        renderThread();
      });

      const activate = () => {
        state.activeId = c.id;
        save();
        renderConvs();
        renderThread();
        $("sidebar").classList.remove("open");
      };
      item.addEventListener("click", activate);
      item.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          activate();
        }
      });

      item.appendChild(titleSpan);
      item.appendChild(delBtn);
      box.appendChild(item);
    }
  }

  const SUGGESTIONS = [
    "اقترح خطة فحص مبدئية لـ target.example.com",
    "Explain why an SSRF finding needs proof before submission",
    "ما الأدوات الأفضل لاكتشاف endpoints مخفية في تطبيق Node/Express؟",
    "Summarize the 7-Question Gate for report triage",
  ];

  function renderThread() {
    const box = $("messages");
    const conv = activeConv();
    box.textContent = "";
    if (!conv || conv.messages.length === 0) {
      const empty = document.createElement("div");
      empty.className = "empty";

      const heading = document.createElement("h2");
      heading.textContent = "اسأل HunterAI أي سؤال";

      const para = document.createElement("p");
      para.textContent = "النموذج يتكيّف تلقائياً حسب نوع السؤال — أسئلة سريعة أو تخطيط وتحليل أعمق.";

      const chips = document.createElement("div");
      chips.className = "chips";
      for (const s of SUGGESTIONS) {
        const chip = document.createElement("button");
        chip.type = "button";
        chip.className = "chip";
        chip.textContent = s;
        chip.addEventListener("click", () => {
          $("input").value = s;
          $("input").focus();
          submit();
        });
        chips.appendChild(chip);
      }

      empty.appendChild(heading);
      empty.appendChild(para);
      empty.appendChild(chips);
      box.appendChild(empty);
      return;
    }
    for (const m of conv.messages) {
      box.appendChild(messageNode(m));
    }
    scrollDown();
  }

  function renderMultilinePlain(target, text) {
    target.textContent = "";
    const lines = String(text ?? "").split("\n");
    lines.forEach((line, idx) => {
      target.appendChild(document.createTextNode(line));
      if (idx < lines.length - 1) {
        target.appendChild(document.createElement("br"));
      }
    });
  }

  function messageNode(m) {
    const wrap = document.createElement("div");
    wrap.className = "msg " + m.role;
    const bubble = document.createElement("div");
    bubble.className = "bubble";

    const tracesEl = document.createElement("div");
    tracesEl.className = "traces";

    const textEl = document.createElement("div");
    textEl.className = "text";

    if (m.pending) {
      const typing = document.createElement("span");
      typing.className = "typing";
      typing.appendChild(document.createElement("span"));
      typing.appendChild(document.createElement("span"));
      typing.appendChild(document.createElement("span"));
      textEl.appendChild(typing);
    } else if (m.role === "user") {
      renderMultilinePlain(textEl, m.content);
    } else {
      textEl.innerHTML = md(m.content);
      decorateRenderedMarkdown(textEl);
    }

    bubble.appendChild(tracesEl);
    bubble.appendChild(textEl);

    if (m.role === "assistant" && Array.isArray(m.traces) && m.traces.length) {
      for (const t of m.traces) tracesEl.appendChild(traceNode(t, true));
    }
    if (m.role === "assistant" && m.meta) {
      const meta = document.createElement("div");
      meta.className = "meta ltr-isolate";
      const bits = [];
      if (m.meta.model) bits.push(m.meta.model);
      if (m.meta.provider) bits.push(m.meta.provider);
      if (m.meta.latency_ms != null) bits.push(m.meta.latency_ms + "ms");
      if (m.meta.tier) bits.push(m.meta.tier);
      if (m.meta.fallback) bits.push("fallback");
      if (bits.length) {
        meta.textContent = bits.join(" · ");
        bubble.appendChild(meta);
      }
    }
    if (m.error) {
      const err = document.createElement("div");
      err.className = "err";
      err.textContent = m.error;
      bubble.appendChild(err);
    }
    wrap.appendChild(bubble);
    return wrap;
  }

  function traceNode(trace, done) {
    const el = document.createElement("div");
    el.className = "trace" + (done ? " done" : "");

    const head = document.createElement("button");
    head.type = "button";
    head.className = "trace-head";

    const label = document.createElement("span");
    label.textContent = String(trace.label || "step");

    const status = document.createElement("span");
    status.className = "st";
    status.textContent = done ? "done" : "running";

    head.appendChild(label);
    head.appendChild(status);
    el.appendChild(head);

    if (trace.detail) {
      const body = document.createElement("pre");
      body.className = "trace-body ltr-isolate";
      body.setAttribute("dir", "ltr");
      body.textContent = String(trace.detail);
      el.appendChild(body);
    }

    head.addEventListener("click", () => el.classList.toggle("open"));
    return el;
  }

  function scrollDown() {
    const box = $("messages");
    box.scrollTop = box.scrollHeight;
  }

  function setConn(stateName, text) {
    const dot = $("connDot");
    dot.className = "dot " + stateName;
    $("connText").textContent = text;
  }

  function connect() {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    let socket;
    try {
      socket = new WebSocket(`${proto}://${location.host}/ws/chat`);
      ws = socket;
    } catch (_) {
      setConn("err", "ws error");
      return;
    }
    setConn("", "connecting…");

    socket.onopen = () => {
      if (ws !== socket) return;
      retryDelay = 1000;
      setConn("ok", "connected");
    };
    socket.onclose = () => {
      if (ws !== socket) return;
      setConn("err", "reconnecting…");
      setTimeout(connect, retryDelay);
      retryDelay = Math.min(retryDelay * 1.6, 15000);
    };
    socket.onerror = () => {
      if (ws !== socket) return;
      setConn("err", "error");
    };
    socket.onmessage = (ev) => {
      if (ws !== socket) return;
      let d;
      try { d = JSON.parse(ev.data); } catch { return; }
      handleEvent(d);
    };
  }

  function appendPendingTrace(label, detail, done) {
    if (!pendingNode) return;
    const t = { label: String(label || "step"), detail: String(detail || "") };
    pendingTraces.push(t);
    const tracesEl = pendingNode.querySelector(".traces");
    if (tracesEl) tracesEl.appendChild(traceNode(t, Boolean(done)));
    scrollDown();
  }

  function handleEvent(d) {
    if (!d || typeof d !== "object") return;
    const ev = d.event || d.type;

    if (ev === "chat_start" || ev === "chat_ack") {
      const conv = activeConv();
      if (conv && d.conversation_id) {
        conv.serverConversationId = d.conversation_id;
        save();
      }
      if (d.policy) {
        const pText = typeof d.policy === "string" ? d.policy : (d.policy.status || "checked");
        $("policyTag").textContent = "policy: " + pText;
      } else if (d.mode) {
        $("policyTag").textContent = "mode: " + d.mode;
      }
      return;
    }
    if (ev === "context" || ev === "refs") {
      const refs = Array.isArray(d.refs) ? d.refs : [];
      const cites = Array.isArray(d.citations) ? d.citations : [];
      if (refs.length > 0 || cites.length > 0) {
        const lines = refs.map((r) => `[${r.kind || "ref"}] ${r.label || r.id || ""}`);
        if (cites.length > 0) lines.push(`citations: ${cites.length}`);
        appendPendingTrace(ev, lines.join("\n"), true);
      }
      return;
    }
    if (ev === "approval_request") {
      const ap = d.approval || d;
      $("policyTag").textContent = "policy: approval_required";
      const detail = `${ap.action_type || "ACTION"} · ${ap.tool_name || "tool"} -> ${ap.target || ""}` +
        (ap.risk_tier ? ` (${ap.risk_tier})` : "") +
        (ap.approval_id ? ` [${ap.approval_id}]` : "");
      appendPendingTrace("approval_request", detail, false);
      if (window.HunterPlatform && typeof window.HunterPlatform.refreshOverview === "function") {
        window.HunterPlatform.refreshOverview();
      }
      return;
    }
    if (ev === "policy_blocked") {
      const pol = d.policy || d;
      $("policyTag").textContent = "policy: " + (pol.status || "blocked");
      appendPendingTrace("policy_blocked", `${pol.status || "BLOCKED"}: ${pol.reason || ""}`, true);
      return;
    }
    if (ev === "chat_trace") {
      appendPendingTrace(d.label || "step", d.detail || "", false);
      return;
    }
    if (ev === "token" || ev === "chat_token") {
      if (!pendingNode) return;
      const tok = d.delta ?? d.token ?? "";
      pendingText += tok;
      const textEl = pendingNode.querySelector(".text");
      textEl.innerHTML = md(pendingText);
      decorateRenderedMarkdown(textEl);
      scrollDown();
      return;
    }
    if (ev === "chat_response" || ev === "chat_done") {
      const conv = activeConv();
      if (conv && d.conversation_id) {
        conv.serverConversationId = d.conversation_id;
      }
      if (d.policy) {
        const pStatus = typeof d.policy === "string" ? d.policy : (d.policy.status || (d.policy.allowed === false ? "blocked" : "allowed"));
        $("policyTag").textContent = "policy: " + pStatus;
      }
      const content = (d.answer !== undefined && d.answer !== null && d.answer !== "")
        ? d.answer
        : ((d.response !== undefined && d.response !== null && d.response !== "")
          ? d.response
          : (pendingText || ""));
      const meta = {
        model: d.model_used || d.model,
        provider: d.provider,
        latency_ms: d.latency_ms != null ? d.latency_ms : (d.duration != null ? Math.round(Number(d.duration) * 1000) : null),
        tier: d.tier || d.mode || d.route,
        fallback: Boolean(d.fallback),
      };
      finishAssistant(content, meta, null);
      return;
    }
    if (ev === "error" || ev === "chat_error") {
      finishAssistant(pendingText || "", null, d.message || d.error || "Error");
      return;
    }
  }

  function finishAssistant(text, meta, isError) {
    const conv = activeConv();
    if (conv) {
      const last = conv.messages[conv.messages.length - 1];
      if (last && last.pending) {
        last.pending = false;
        last.content = text;
        last.traces = pendingTraces.slice();
        last.meta = meta;
        last.error = isError;
      }
      save();
      renderThread();
    }
    sending = false;
    pendingNode = null;
    pendingText = "";
    pendingTraces = [];
    $("send").disabled = false;
  }

  function submit() {
    if (sending) return;
    const input = $("input");
    const msg = input.value.trim();
    if (!msg) return;
    if (!ws || ws.readyState !== 1) {
      setConn("err", "not connected");
      return;
    }

    const conv = ensureConversation();
    if (conv.messages.length === 0) {
      conv.title = msg.slice(0, 40) + (msg.length > 40 ? "…" : "");
    }
    conv.messages.push({ role: "user", content: msg });
    const placeholder = { role: "assistant", content: "", pending: true, traces: [] };
    conv.messages.push(placeholder);
    save();

    renderConvs();
    renderThread();

    const box = $("messages");
    pendingNode = box.lastElementChild;
    pendingText = "";
    pendingTraces = [];

    input.value = "";
    input.style.height = "auto";
    sending = true;
    $("send").disabled = true;

    const platformState = window.HunterPlatform && typeof window.HunterPlatform.getState === "function"
      ? window.HunterPlatform.getState()
      : null;
    const ctx = (platformState && platformState.context) || {};

    ws.send(JSON.stringify({
      type: "chat",
      message: msg,
      model: $("modelSelect").value || "auto",
      conversation_id: conv.serverConversationId || conv.id,
      engagement_id: ctx.active_engagement_id || ctx.engagement_id || "",
      run_id: ctx.active_run_id || ctx.run_id || "",
    }));
  }

  async function loadCatalog() {
    try {
      const r = await fetch("/api/models/catalog");
      if (!r.ok) return;
      catalog = await r.json();
      fillModels(catalog);
    } catch (_) {}
  }

  function normalizeCatalogChoices(cat) {
    if (Array.isArray(cat?.choices) && cat.choices.length > 0) {
      return cat.choices;
    }
    const choices = [];
    if (Array.isArray(cat?.cloud)) {
      for (const c of cat.cloud) {
        const prov = c.provider || "cloud";
        const models = Array.isArray(c.models) ? c.models : [];
        for (const m of models) {
          choices.push({
            id: `api:${prov}:${m}`,
            kind: "cloud",
            provider: prov,
            model: m,
            label: `${c.label || prov} · ${m}`,
            available: true,
          });
        }
      }
    }
    const localModels = Array.isArray(cat?.local?.models) ? cat.local.models : [];
    for (const m of localModels) {
      choices.push({
        id: `local:${m}`,
        kind: "local",
        provider: "ollama",
        model: m,
        label: `Ollama · ${m}`,
        available: cat?.local?.available !== false,
      });
    }
    if (choices.length === 0 && Array.isArray(cat?.models)) {
      for (const m of cat.models) {
        const p = m.provider || "other";
        const rawId = String(m.id || "");
        choices.push({
          id: rawId.startsWith("api:") || rawId.startsWith("local:") ? rawId : `${p}:${rawId}`,
          kind: m.kind || (p === "ollama" ? "local" : "cloud"),
          provider: p,
          model: m.model || rawId,
          label: m.label || rawId,
          tier: m.tier,
          available: m.available !== false,
        });
      }
    }
    return choices;
  }

  function fillModels(cat) {
    const sel = $("modelSelect");
    const saved = sel.value || "auto";
    sel.textContent = "";

    const autoOpt = document.createElement("option");
    autoOpt.value = "auto";
    autoOpt.textContent = "Auto (smart router)";
    sel.appendChild(autoOpt);

    const choices = normalizeCatalogChoices(cat);
    const byProvider = new Map();
    for (const m of choices) {
      const p = m.provider || (m.kind === "local" ? "ollama" : "other");
      if (!byProvider.has(p)) byProvider.set(p, []);
      byProvider.get(p).push(m);
    }

    for (const [provider, list] of byProvider.entries()) {
      const grp = document.createElement("optgroup");
      grp.label = provider.toUpperCase();
      for (const m of list) {
        const opt = document.createElement("option");
        opt.value = m.id;
        const tag = m.tier ? ` [${m.tier}]` : "";
        const avail = m.available === false ? " (offline)" : "";
        opt.textContent = `${m.label || m.model || m.id}${tag}${avail}`;
        grp.appendChild(opt);
      }
      sel.appendChild(grp);
    }

    if ([...sel.options].some((o) => o.value === saved)) sel.value = saved;
    updateModelHint();
  }

  function updateModelHint() {
    const v = $("modelSelect").value;
    const hint = $("modelHint");
    if (v === "auto") {
      if (catalog?.auto) {
        hint.textContent = `Fast: ${catalog.auto.fast || "local"} · Deep: ${catalog.auto.reasoning || "local"}`;
      } else if (catalog) {
        const policy = catalog.policy || "auto";
        const localCount = Array.isArray(catalog.local?.models) ? catalog.local.models.length : 0;
        const cloudCount = Array.isArray(catalog.cloud) ? catalog.cloud.length : 0;
        hint.textContent = `Policy: ${policy} · Local: ${localCount} · Cloud: ${cloudCount}`;
      } else {
        hint.textContent = "Chooses fast vs reasoning automatically";
      }
    } else {
      hint.textContent = `Pinned: ${v}`;
    }
  }

  function init() {
    if (state.convs.length === 0) newConversation();
    else if (!activeConv()) state.activeId = state.convs[0].id;

    renderConvs();
    renderThread();
    loadCatalog();
    connect();

    $("composer").addEventListener("submit", (e) => { e.preventDefault(); submit(); });
    $("input").addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); submit(); }
    });
    $("input").addEventListener("input", () => {
      const el = $("input");
      el.style.height = "auto";
      el.style.height = Math.min(el.scrollHeight, 180) + "px";
    });
    $("newChat").addEventListener("click", () => {
      newConversation();
      renderConvs();
      renderThread();
      $("input").focus();
    });
    $("clearBtn").addEventListener("click", () => {
      const c = activeConv();
      if (!c) return;
      c.messages = [];
      c.serverConversationId = null;
      c.title = "New chat";
      save();
      renderConvs();
      renderThread();
      if (ws && ws.readyState === 1) {
        try { ws.send(JSON.stringify({ action: "clear_memory" })); } catch (_) {}
      }
    });
    $("modelSelect").addEventListener("change", updateModelHint);
    $("menuBtn").addEventListener("click", () => $("sidebar").classList.toggle("open"));
  }

  document.addEventListener("DOMContentLoaded", init);
})();
