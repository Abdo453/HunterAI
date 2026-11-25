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
    const c = { id, title: "New chat", model: $("modelSelect").value || "auto", messages: [] };
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
      if (m.meta.latency_ms != null) bits.push(m.meta.latency_ms + "ms");
      if (m.meta.tier) bits.push(m.meta.tier);
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
    try {
      ws = new WebSocket(`${proto}://${location.host}/ws/chat`);
    } catch (_) {
      setConn("err", "ws error");
      return;
    }
    setConn("", "connecting…");

    ws.onopen = () => {
      retryDelay = 1000;
      setConn("ok", "connected");
    };
    ws.onclose = () => {
      setConn("err", "reconnecting…");
      setTimeout(connect, retryDelay);
      retryDelay = Math.min(retryDelay * 1.6, 15000);
    };
    ws.onerror = () => { setConn("err", "error"); };
    ws.onmessage = (ev) => {
      let d;
      try { d = JSON.parse(ev.data); } catch { return; }
      handleEvent(d);
    };
  }

  function handleEvent(d) {
    if (d.type === "chat_ack") {
      if (d.policy) $("policyTag").textContent = "policy: " + d.policy;
      return;
    }
    if (d.type === "chat_trace") {
      if (!pendingNode) return;
      const t = { label: d.label || "step", detail: d.detail || "" };
      pendingTraces.push(t);
      pendingNode.querySelector(".traces").appendChild(traceNode(t, false));
      scrollDown();
      return;
    }
    if (d.type === "chat_token") {
      if (!pendingNode) return;
      const tok = d.delta ?? d.token ?? "";
      pendingText += tok;
      const textEl = pendingNode.querySelector(".text");
      textEl.innerHTML = md(pendingText);
      decorateRenderedMarkdown(textEl);
      scrollDown();
      return;
    }
    if (d.type === "chat_done") {
      const content = d.response ?? pendingText ?? "";
      const meta = { model: d.model, latency_ms: d.latency_ms, tier: d.tier };
      finishAssistant(content, meta, null);
      return;
    }
    if (d.type === "chat_error") {
      finishAssistant(pendingText || "", null, d.message || "Error");
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
      conversation_id: conv.id,
      engagement_id: ctx.engagement_id || "",
      run_id: ctx.run_id || "",
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

  function fillModels(cat) {
    const sel = $("modelSelect");
    const saved = sel.value || "auto";
    sel.textContent = "";

    const autoOpt = document.createElement("option");
    autoOpt.value = "auto";
    autoOpt.textContent = "Auto (smart router)";
    sel.appendChild(autoOpt);

    const models = Array.isArray(cat?.models) ? cat.models : [];
    const byProvider = new Map();
    for (const m of models) {
      const p = m.provider || "other";
      if (!byProvider.has(p)) byProvider.set(p, []);
      byProvider.get(p).push(m);
    }

    for (const [provider, list] of byProvider.entries()) {
      const grp = document.createElement("optgroup");
      grp.label = provider.toUpperCase();
      for (const m of list) {
        const opt = document.createElement("option");
        opt.value = `${provider}:${m.id}`;
        const tag = m.tier ? ` [${m.tier}]` : "";
        const avail = m.available === false ? " (offline)" : "";
        opt.textContent = `${m.label || m.id}${tag}${avail}`;
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
      hint.textContent = catalog?.auto
        ? `Fast: ${catalog.auto.fast || "local"} · Deep: ${catalog.auto.reasoning || "local"}`
        : "Chooses fast vs reasoning automatically";
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
      c.title = "New chat";
      save();
      renderConvs();
      renderThread();
    });
    $("modelSelect").addEventListener("change", updateModelHint);
    $("menuBtn").addEventListener("click", () => $("sidebar").classList.toggle("open"));
  }

  document.addEventListener("DOMContentLoaded", init);
})();
